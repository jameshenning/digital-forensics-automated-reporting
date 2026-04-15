/// Entity database queries — Phase 4.
///
/// Manages the `entities` table: add, get, list for case, update, soft-delete.
/// All deletes are soft (is_deleted = 1 — never hard DELETE).
/// Soft-deleting an entity cascades to all entity_links where the entity is
/// source or target (within the same transaction).
///
/// Public surface:
///   - `add_entity`    — INSERT with full validation
///   - `get_entity`    — fetch single row by entity_id (returns is_deleted rows too)
///   - `list_for_case` — active rows only, ordered by entity_type, display_name
///   - `update_entity` — UPDATE with cycle-check on parent_entity_id
///   - `soft_delete`   — sets is_deleted = 1 + cascades to entity_links
///
/// Validation:
///   - entity_type allowlist: person | business | phone | email | alias |
///                            address | account | vehicle
///   - subtype allowlist (person only): suspect | victim | witness |
///                                      investigator | poi | other
///   - display_name: 1–200 chars, required
///   - parent_entity_id: must exist in same case, no self-loop, no cycle
///   - metadata_json: must be valid JSON if provided
// NaiveDateTime no longer needed — `created_at` / `updated_at` are Strings.
use serde::{Deserialize, Serialize};
use sqlx::{sqlite::Sqlite, SqlitePool, Transaction};

use crate::error::AppError;

// ─── Validation constants ─────────────────────────────────────────────────────

const VALID_ENTITY_TYPES: &[&str] = &[
    "person", "business", "phone", "email", "alias", "address", "account", "vehicle",
];

const VALID_SUBTYPES: &[&str] = &[
    "suspect", "victim", "witness", "investigator", "poi", "other",
];

const DISPLAY_NAME_MAX_LEN: usize = 200;

/// Maximum depth when walking the parent chain for cycle detection.
/// Forensic org trees realistically never exceed a handful of levels;
/// 50 is a hard safety bound against pathological inputs.
const MAX_PARENT_DEPTH: usize = 50;

// ─── Public data types ────────────────────────────────────────────────────────

/// Full entity row, maps 1:1 to the `entities` table.
/// `created_at`/`updated_at` are `String` for v1 compat — see `db::cases::Case`.
///
/// The `photo_path`/`email`/`phone`/`username`/`employer`/`dob` columns
/// were added in migration 0002 and are only meaningful when
/// `entity_type = 'person'`. All are nullable — non-person rows leave them
/// NULL. `photo_path` holds an absolute filesystem path to a file stored
/// under `%APPDATA%\DFARS\person_photos\<case_id>\`.
#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct Entity {
    pub entity_id: i64,
    pub case_id: String,
    pub entity_type: String,
    pub display_name: String,
    pub subtype: Option<String>,
    pub organizational_rank: Option<String>,
    pub parent_entity_id: Option<i64>,
    pub notes: Option<String>,
    pub metadata_json: Option<String>,
    pub is_deleted: i64,
    pub created_at: String,
    pub updated_at: String,
    // Person-specific columns (migration 0002) — NULL for non-person rows.
    pub photo_path: Option<String>,
    pub email: Option<String>,
    pub phone: Option<String>,
    pub username: Option<String>,
    pub employer: Option<String>,
    pub dob: Option<String>,
}

/// Writable fields for creating or updating an entity.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EntityInput {
    pub entity_type: String,
    pub display_name: String,
    pub subtype: Option<String>,
    pub organizational_rank: Option<String>,
    pub parent_entity_id: Option<i64>,
    pub notes: Option<String>,
    pub metadata_json: Option<String>,
    // Person-specific inputs — ignored for non-person entity_types.
    // `photo_path` is NOT set via this input; it's updated separately by
    // the `person_photo_upload` command so the upload path owns the file
    // lifecycle. Included here as `None` for struct symmetry only.
    #[serde(default)]
    pub email: Option<String>,
    #[serde(default)]
    pub phone: Option<String>,
    #[serde(default)]
    pub username: Option<String>,
    #[serde(default)]
    pub employer: Option<String>,
    #[serde(default)]
    pub dob: Option<String>,
}

// ─── Validation helpers ───────────────────────────────────────────────────────

fn validate_entity_input(input: &EntityInput) -> Result<(), AppError> {
    // entity_type allowlist
    if !VALID_ENTITY_TYPES.contains(&input.entity_type.as_str()) {
        return Err(AppError::ValidationError {
            field: "entity_type".into(),
            message: format!(
                "entity_type must be one of: {}",
                VALID_ENTITY_TYPES.join(", ")
            ),
        });
    }

    // display_name: required, 1–200 chars
    let name = input.display_name.trim();
    if name.is_empty() {
        return Err(AppError::ValidationError {
            field: "display_name".into(),
            message: "display_name must not be empty".into(),
        });
    }
    if name.len() > DISPLAY_NAME_MAX_LEN {
        return Err(AppError::ValidationError {
            field: "display_name".into(),
            message: format!("display_name must not exceed {DISPLAY_NAME_MAX_LEN} characters"),
        });
    }

    // subtype: only allowed for person, and must be in allowlist if provided
    if let Some(ref subtype) = input.subtype {
        if input.entity_type != "person" {
            return Err(AppError::ValidationError {
                field: "subtype".into(),
                message: "subtype is only allowed when entity_type is 'person'".into(),
            });
        }
        if !VALID_SUBTYPES.contains(&subtype.as_str()) {
            return Err(AppError::ValidationError {
                field: "subtype".into(),
                message: format!(
                    "subtype must be one of: {}",
                    VALID_SUBTYPES.join(", ")
                ),
            });
        }
    }

    // metadata_json: must be valid JSON if provided
    if let Some(ref json_str) = input.metadata_json {
        serde_json::from_str::<serde_json::Value>(json_str).map_err(|e| {
            AppError::ValidationError {
                field: "metadata_json".into(),
                message: format!("metadata_json must be valid JSON: {e}"),
            }
        })?;
    }

    Ok(())
}

/// Verify that `parent_entity_id`, if set, exists in the same case and is not soft-deleted.
/// Returns `AppError::ValidationError` on failure.
async fn validate_parent_exists(
    pool: &SqlitePool,
    case_id: &str,
    parent_entity_id: i64,
) -> Result<(), AppError> {
    let exists: (i64,) = sqlx::query_as(
        "SELECT COUNT(*) FROM entities WHERE entity_id = ? AND case_id = ? AND is_deleted = 0",
    )
    .bind(parent_entity_id)
    .bind(case_id)
    .fetch_one(pool)
    .await?;

    if exists.0 == 0 {
        return Err(AppError::ValidationError {
            field: "parent_entity_id".into(),
            message: format!(
                "parent_entity_id {parent_entity_id} does not exist in case '{case_id}'"
            ),
        });
    }
    Ok(())
}

/// Walk the parent chain starting from `start_id` and check whether following
/// parents would eventually reach `would_be_child_id`, which would create a cycle.
///
/// Uses a while-loop with a max-depth bound of 50 — forensic org trees are never
/// that deep in practice.
async fn check_no_cycle(
    pool: &SqlitePool,
    start_id: i64,
    would_be_child_id: i64,
) -> Result<(), AppError> {
    let mut current = start_id;
    let mut depth = 0usize;

    loop {
        if current == would_be_child_id {
            return Err(AppError::EntityCycle {
                entity_id: would_be_child_id,
            });
        }
        depth += 1;
        if depth > MAX_PARENT_DEPTH {
            // Treat as a cycle (pathological input) to prevent infinite loops.
            return Err(AppError::EntityCycle {
                entity_id: would_be_child_id,
            });
        }

        // Fetch the next parent in the chain.
        let row: Option<(Option<i64>,)> = sqlx::query_as(
            "SELECT parent_entity_id FROM entities WHERE entity_id = ? AND is_deleted = 0",
        )
        .bind(current)
        .fetch_optional(pool)
        .await?;

        match row {
            None => break, // entity doesn't exist or soft-deleted; chain ends
            Some((None,)) => break, // no parent; chain ends cleanly
            Some((Some(next_parent),)) => {
                current = next_parent;
            }
        }
    }

    Ok(())
}

// ─── Public query functions ───────────────────────────────────────────────────

/// Add a new entity to a case.
///
/// Validates entity_type, subtype, display_name, parent_entity_id, metadata_json.
/// Returns the newly-created entity row.
pub async fn add_entity(
    pool: &SqlitePool,
    case_id: &str,
    input: &EntityInput,
) -> Result<Entity, AppError> {
    validate_entity_input(input)?;

    // Validate parent before insert
    if let Some(parent_id) = input.parent_entity_id {
        validate_parent_exists(pool, case_id, parent_id).await?;
    }

    let row = sqlx::query_as::<_, Entity>(
        r#"
        INSERT INTO entities (
            case_id, entity_type, display_name, subtype, organizational_rank,
            parent_entity_id, notes, metadata_json,
            email, phone, username, employer, dob
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        RETURNING
            entity_id, case_id, entity_type, display_name, subtype,
            organizational_rank, parent_entity_id, notes, metadata_json,
            is_deleted, created_at, updated_at,
            photo_path, email, phone, username, employer, dob
        "#,
    )
    .bind(case_id)
    .bind(&input.entity_type)
    .bind(input.display_name.trim())
    .bind(&input.subtype)
    .bind(&input.organizational_rank)
    .bind(input.parent_entity_id)
    .bind(&input.notes)
    .bind(&input.metadata_json)
    .bind(&input.email)
    .bind(&input.phone)
    .bind(&input.username)
    .bind(&input.employer)
    .bind(&input.dob)
    .fetch_one(pool)
    .await?;

    Ok(row)
}

/// Fetch a single entity by entity_id (includes soft-deleted rows for audit purposes).
pub async fn get_entity(pool: &SqlitePool, entity_id: i64) -> Result<Entity, AppError> {
    sqlx::query_as::<_, Entity>(
        r#"
        SELECT entity_id, case_id, entity_type, display_name, subtype,
               organizational_rank, parent_entity_id, notes, metadata_json,
               is_deleted, created_at, updated_at,
               photo_path, email, phone, username, employer, dob
        FROM entities
        WHERE entity_id = ?
        "#,
    )
    .bind(entity_id)
    .fetch_optional(pool)
    .await?
    .ok_or(AppError::EntityNotFound { entity_id })
}

/// List all active (non-deleted) entities for a case.
///
/// Ordered by `entity_type ASC, display_name ASC`.
pub async fn list_for_case(pool: &SqlitePool, case_id: &str) -> Result<Vec<Entity>, AppError> {
    let rows = sqlx::query_as::<_, Entity>(
        r#"
        SELECT entity_id, case_id, entity_type, display_name, subtype,
               organizational_rank, parent_entity_id, notes, metadata_json,
               is_deleted, created_at, updated_at,
               photo_path, email, phone, username, employer, dob
        FROM entities
        WHERE case_id = ? AND is_deleted = 0
        ORDER BY entity_type ASC, display_name ASC
        "#,
    )
    .bind(case_id)
    .fetch_all(pool)
    .await?;

    Ok(rows)
}

/// Update mutable fields of an existing entity.
///
/// Validates the same rules as `add_entity`, plus a cycle check on `parent_entity_id`
/// (since updating a parent could create a ring in the org tree).
/// Sets `updated_at = CURRENT_TIMESTAMP`.
pub async fn update_entity(
    pool: &SqlitePool,
    entity_id: i64,
    input: &EntityInput,
) -> Result<Entity, AppError> {
    validate_entity_input(input)?;

    // Fetch existing to get the case_id (needed for parent validation)
    let existing = get_entity(pool, entity_id).await?;
    if existing.is_deleted != 0 {
        return Err(AppError::EntityNotFound { entity_id });
    }

    if let Some(parent_id) = input.parent_entity_id {
        // No self-parent
        if parent_id == entity_id {
            return Err(AppError::ValidationError {
                field: "parent_entity_id".into(),
                message: "an entity cannot be its own parent".into(),
            });
        }
        // Parent must exist in same case
        validate_parent_exists(pool, &existing.case_id, parent_id).await?;
        // Cycle check: walk up from parent_id looking for entity_id
        check_no_cycle(pool, parent_id, entity_id).await?;
    }

    let row = sqlx::query_as::<_, Entity>(
        r#"
        UPDATE entities SET
            entity_type = ?,
            display_name = ?,
            subtype = ?,
            organizational_rank = ?,
            parent_entity_id = ?,
            notes = ?,
            metadata_json = ?,
            email = ?,
            phone = ?,
            username = ?,
            employer = ?,
            dob = ?,
            updated_at = CURRENT_TIMESTAMP
        WHERE entity_id = ? AND is_deleted = 0
        RETURNING
            entity_id, case_id, entity_type, display_name, subtype,
            organizational_rank, parent_entity_id, notes, metadata_json,
            is_deleted, created_at, updated_at,
            photo_path, email, phone, username, employer, dob
        "#,
    )
    .bind(&input.entity_type)
    .bind(input.display_name.trim())
    .bind(&input.subtype)
    .bind(&input.organizational_rank)
    .bind(input.parent_entity_id)
    .bind(&input.notes)
    .bind(&input.metadata_json)
    .bind(&input.email)
    .bind(&input.phone)
    .bind(&input.username)
    .bind(&input.employer)
    .bind(&input.dob)
    .bind(entity_id)
    .fetch_optional(pool)
    .await?
    .ok_or(AppError::EntityNotFound { entity_id })?;

    Ok(row)
}

/// Soft-delete an entity and cascade to entity_links (atomic transaction).
///
/// Sets `is_deleted = 1` on the entity and also sets `is_deleted = 1` on any
/// `entity_links` row where this entity is the source or target. This mirrors v1
/// behavior: links to a deleted entity become invisible even though the rows stay.
pub async fn soft_delete(pool: &SqlitePool, entity_id: i64) -> Result<(), AppError> {
    // Verify entity exists first
    let entity = get_entity(pool, entity_id).await?;
    if entity.is_deleted != 0 {
        return Err(AppError::EntityNotFound { entity_id });
    }

    let mut tx = pool.begin().await?;

    // Cascade soft-delete to entity_links
    cascade_soft_delete_links(&mut tx, entity_id).await?;

    // Cascade soft-delete to person_identifiers (no-op for non-person entities)
    crate::db::person_identifiers::cascade_soft_delete_for_entity(&mut tx, entity_id).await?;

    // Soft-delete the entity itself
    let rows_affected = sqlx::query(
        "UPDATE entities SET is_deleted = 1, updated_at = CURRENT_TIMESTAMP WHERE entity_id = ?",
    )
    .bind(entity_id)
    .execute(&mut *tx)
    .await?
    .rows_affected();

    if rows_affected == 0 {
        let _ = tx.rollback().await;
        return Err(AppError::EntityNotFound { entity_id });
    }

    tx.commit().await?;
    Ok(())
}

/// Soft-delete all entity_links referencing `entity_id` as source or target.
/// Runs inside an existing transaction.
pub(crate) async fn cascade_soft_delete_links(
    tx: &mut Transaction<'_, Sqlite>,
    entity_id: i64,
) -> Result<(), AppError> {
    let entity_id_str = entity_id.to_string();

    sqlx::query(
        r#"
        UPDATE entity_links
        SET is_deleted = 1
        WHERE is_deleted = 0
          AND (
            (source_type = 'entity' AND source_id = ?)
            OR (target_type = 'entity' AND target_id = ?)
          )
        "#,
    )
    .bind(&entity_id_str)
    .bind(&entity_id_str)
    .execute(&mut **tx)
    .await?;

    Ok(())
}
