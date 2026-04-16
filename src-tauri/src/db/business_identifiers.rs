//! Business identifier queries — migration 0005.
//!
//! Manages the `business_identifiers` table: add, get, list by entity, update,
//! soft-delete. Every identifier is attached to a parent `entities` row whose
//! `entity_type` MUST be `'business'` (enforced at add time). Deletes are soft
//! only (`is_deleted = 1`) so the OSINT submission history stays intact even
//! after the investigator removes an identifier from the active view.
//!
//! A single business typically has many OSINT-relevant identifiers — domain
//! names, registration numbers, EINs, email addresses, phone numbers, addresses,
//! social media profiles, and URLs. The OSINT submission flow (Pass 2) batches
//! the active rows here for a given entity into a single Agent Zero job.
//!
//! Public surface:
//!   - `add_identifier`        — INSERT with validation + parent-entity check
//!   - `get_identifier`        — fetch a single row (includes soft-deleted)
//!   - `list_for_entity`       — active rows for a given entity_id
//!   - `update_identifier`     — UPDATE mutable fields
//!   - `soft_delete`           — sets is_deleted = 1
//!   - `cascade_soft_delete_for_entity` — tx-scoped helper called from
//!     `entities::soft_delete` so deleting a business also removes their
//!     identifiers from the active view.

use serde::{Deserialize, Serialize};
use sqlx::{sqlite::Sqlite, SqlitePool, Transaction};

use crate::error::AppError;

// ─── Validation constants ─────────────────────────────────────────────────────

const VALID_KINDS: &[&str] = &[
    "domain", "registration", "ein", "email", "phone", "address", "social", "url",
];

const VALUE_MAX_LEN: usize = 500;
const PLATFORM_MAX_LEN: usize = 100;
const NOTES_MAX_LEN: usize = 2000;

// ─── Public data types ────────────────────────────────────────────────────────

/// Full business_identifier row. `created_at`/`updated_at` are `String` for
/// v1-compat with the rest of the schema — see `db::cases::Case`.
#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct BusinessIdentifier {
    pub identifier_id: i64,
    pub entity_id: i64,
    pub kind: String,
    pub value: String,
    pub platform: Option<String>,
    pub notes: Option<String>,
    pub is_deleted: i64,
    pub created_at: String,
    pub updated_at: String,
}

/// Writable fields for creating or updating a business_identifier.
///
/// `entity_id` is supplied as a path/command parameter on the add path and
/// is implicit (from the existing row) on the update path, so it is NOT
/// part of this input struct.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BusinessIdentifierInput {
    pub kind: String,
    pub value: String,
    #[serde(default)]
    pub platform: Option<String>,
    #[serde(default)]
    pub notes: Option<String>,
}

// ─── Validation ───────────────────────────────────────────────────────────────

fn validate_input(input: &BusinessIdentifierInput) -> Result<(), AppError> {
    // kind: lowercase allowlist
    let kind = input.kind.trim();
    if !VALID_KINDS.contains(&kind) {
        return Err(AppError::ValidationError {
            field: "kind".into(),
            message: format!("kind must be one of: {}", VALID_KINDS.join(", ")),
        });
    }

    // value: required, 1..=VALUE_MAX_LEN (character count, not byte length,
    // so it matches zod's .max(500) on the frontend for Unicode text).
    let value = input.value.trim();
    if value.is_empty() {
        return Err(AppError::ValidationError {
            field: "value".into(),
            message: "value must not be empty".into(),
        });
    }
    if value.chars().count() > VALUE_MAX_LEN {
        return Err(AppError::ValidationError {
            field: "value".into(),
            message: format!("value must not exceed {VALUE_MAX_LEN} characters"),
        });
    }
    // Reject values that start with '-' — prevents argv-injection (CWE-88)
    // when Agent Zero tools receive the value as a positional argument (e.g.,
    // `whois <domain>`, `spiderfoot -s <target>`, `onionsearch <keyword>`).
    // A leading-dash value would be parsed as a flag rather than a positional.
    // No legitimate domain / email / registration / phone starts with a dash.
    if value.starts_with('-') {
        return Err(AppError::ValidationError {
            field: "value".into(),
            message: "value must not start with '-' (argv-injection safety)".into(),
        });
    }

    // platform: optional, <= PLATFORM_MAX_LEN (chars)
    if let Some(ref p) = input.platform {
        if p.chars().count() > PLATFORM_MAX_LEN {
            return Err(AppError::ValidationError {
                field: "platform".into(),
                message: format!("platform must not exceed {PLATFORM_MAX_LEN} characters"),
            });
        }
    }

    // notes: optional, <= NOTES_MAX_LEN (chars)
    if let Some(ref n) = input.notes {
        if n.chars().count() > NOTES_MAX_LEN {
            return Err(AppError::ValidationError {
                field: "notes".into(),
                message: format!("notes must not exceed {NOTES_MAX_LEN} characters"),
            });
        }
    }

    Ok(())
}

/// Verify the parent entity exists, is not soft-deleted, and is a business.
/// Returns the entity's `case_id` (needed for audit logging by callers).
async fn validate_parent_is_business(
    pool: &SqlitePool,
    entity_id: i64,
) -> Result<String, AppError> {
    let row: Option<(String, String, i64)> = sqlx::query_as(
        "SELECT case_id, entity_type, is_deleted FROM entities WHERE entity_id = ?",
    )
    .bind(entity_id)
    .fetch_optional(pool)
    .await?;

    match row {
        None => Err(AppError::EntityNotFound { entity_id }),
        Some((_, _, is_deleted)) if is_deleted != 0 => {
            Err(AppError::EntityNotFound { entity_id })
        }
        Some((_, entity_type, _)) if entity_type != "business" => {
            Err(AppError::EntityNotABusiness {
                entity_id,
                entity_type,
            })
        }
        Some((case_id, _, _)) => Ok(case_id),
    }
}

// Empty-to-none normalization: trim whitespace, collapse "" and all-whitespace
// to None. Used on platform/notes to avoid storing meaningless empty strings.
fn normalize_optional(s: &Option<String>) -> Option<String> {
    s.as_ref().and_then(|v| {
        let t = v.trim();
        if t.is_empty() {
            None
        } else {
            Some(t.to_string())
        }
    })
}

// ─── Public query functions ───────────────────────────────────────────────────

/// Add a new identifier to a business entity. Returns the inserted row.
///
/// Validates the input, then verifies the parent entity exists, is active,
/// and has `entity_type = 'business'`. Callers are responsible for audit logging.
pub async fn add_identifier(
    pool: &SqlitePool,
    entity_id: i64,
    input: &BusinessIdentifierInput,
) -> Result<BusinessIdentifier, AppError> {
    validate_input(input)?;
    validate_parent_is_business(pool, entity_id).await?;

    let kind = input.kind.trim();
    let value = input.value.trim();
    let platform = normalize_optional(&input.platform);
    let notes = normalize_optional(&input.notes);

    let row = sqlx::query_as::<_, BusinessIdentifier>(
        r#"
        INSERT INTO business_identifiers (entity_id, kind, value, platform, notes)
        VALUES (?, ?, ?, ?, ?)
        RETURNING identifier_id, entity_id, kind, value, platform, notes,
                  is_deleted, created_at, updated_at
        "#,
    )
    .bind(entity_id)
    .bind(kind)
    .bind(value)
    .bind(&platform)
    .bind(&notes)
    .fetch_one(pool)
    .await?;

    Ok(row)
}

/// Fetch a single identifier (including soft-deleted rows for audit).
pub async fn get_identifier(
    pool: &SqlitePool,
    identifier_id: i64,
) -> Result<BusinessIdentifier, AppError> {
    sqlx::query_as::<_, BusinessIdentifier>(
        r#"
        SELECT identifier_id, entity_id, kind, value, platform, notes,
               is_deleted, created_at, updated_at
        FROM business_identifiers
        WHERE identifier_id = ?
        "#,
    )
    .bind(identifier_id)
    .fetch_optional(pool)
    .await?
    .ok_or(AppError::BusinessIdentifierNotFound { identifier_id })
}

/// List all active (non-deleted) identifiers for a given entity, ordered by
/// `kind ASC, created_at ASC` so the UI shows addresses before domains before
/// EINs, each group in creation order.
pub async fn list_for_entity(
    pool: &SqlitePool,
    entity_id: i64,
) -> Result<Vec<BusinessIdentifier>, AppError> {
    let rows = sqlx::query_as::<_, BusinessIdentifier>(
        r#"
        SELECT identifier_id, entity_id, kind, value, platform, notes,
               is_deleted, created_at, updated_at
        FROM business_identifiers
        WHERE entity_id = ? AND is_deleted = 0
        ORDER BY kind ASC, created_at ASC
        "#,
    )
    .bind(entity_id)
    .fetch_all(pool)
    .await?;

    Ok(rows)
}

/// Update mutable fields of an existing identifier. Entity ownership is not
/// changeable — that would require deleting and recreating the row so the
/// audit trail reflects a real move. `updated_at` is set to `CURRENT_TIMESTAMP`.
///
/// Re-validates that the parent entity is still a business on every update —
/// `add_identifier` guaranteed this at insert time, but nothing prevents a
/// future call to `entity_update` from retyping the parent. Without this
/// check an orphan identifier could be edited indefinitely on a non-business
/// row, violating the "identifiers only exist on businesses" invariant.
pub async fn update_identifier(
    pool: &SqlitePool,
    identifier_id: i64,
    input: &BusinessIdentifierInput,
) -> Result<BusinessIdentifier, AppError> {
    validate_input(input)?;

    // Verify the row exists and is active first — update-if-soft-deleted is
    // not a valid operation; investigators must first soft-undelete (not
    // currently exposed) or add a fresh row.
    let existing = get_identifier(pool, identifier_id).await?;
    if existing.is_deleted != 0 {
        return Err(AppError::BusinessIdentifierNotFound { identifier_id });
    }

    // Re-enforce the "identifiers only exist on businesses" invariant in case
    // the parent entity was retyped after the identifier was created.
    validate_parent_is_business(pool, existing.entity_id).await?;

    let kind = input.kind.trim();
    let value = input.value.trim();
    let platform = normalize_optional(&input.platform);
    let notes = normalize_optional(&input.notes);

    let row = sqlx::query_as::<_, BusinessIdentifier>(
        r#"
        UPDATE business_identifiers SET
            kind = ?,
            value = ?,
            platform = ?,
            notes = ?,
            updated_at = CURRENT_TIMESTAMP
        WHERE identifier_id = ? AND is_deleted = 0
        RETURNING identifier_id, entity_id, kind, value, platform, notes,
                  is_deleted, created_at, updated_at
        "#,
    )
    .bind(kind)
    .bind(value)
    .bind(&platform)
    .bind(&notes)
    .bind(identifier_id)
    .fetch_optional(pool)
    .await?
    .ok_or(AppError::BusinessIdentifierNotFound { identifier_id })?;

    Ok(row)
}

/// Soft-delete an identifier (sets is_deleted = 1, stamps updated_at).
pub async fn soft_delete(pool: &SqlitePool, identifier_id: i64) -> Result<(), AppError> {
    // Require the row to exist and be active — re-deleting a soft-deleted
    // row is a no-op but should still fail loudly so callers can log it.
    let existing = get_identifier(pool, identifier_id).await?;
    if existing.is_deleted != 0 {
        return Err(AppError::BusinessIdentifierNotFound { identifier_id });
    }

    let rows_affected = sqlx::query(
        r#"
        UPDATE business_identifiers
        SET is_deleted = 1, updated_at = CURRENT_TIMESTAMP
        WHERE identifier_id = ? AND is_deleted = 0
        "#,
    )
    .bind(identifier_id)
    .execute(pool)
    .await?
    .rows_affected();

    if rows_affected == 0 {
        return Err(AppError::BusinessIdentifierNotFound { identifier_id });
    }
    Ok(())
}

/// Auto-insert a batch of OSINT-discovered identifiers.  Dedupes against the
/// entity's existing active rows AND against itself (so the same email showing
/// up in two different tool outputs produces one row, not two). Validates
/// each candidate through `validate_input`; candidates that fail validation
/// are skipped silently (best-effort enrichment — one malformed entry must
/// not abort the batch). Caps at `max_new` to prevent an OSINT run from
/// bloating the identifier list. Each inserted row gets a
/// `notes = "Auto-discovered via OSINT <tool> on <iso_date>"` stamp so the
/// investigator can trace provenance and decide whether to keep or remove it.
///
/// Returns `(attempted, inserted)`: how many candidates were considered after
/// dedup (up to the cap) and how many actually landed.  The caller uses the
/// pair to surface a meaningful frontend toast.
pub async fn insert_discovered_batch(
    pool: &SqlitePool,
    entity_id: i64,
    discovered: &[(String, String, Option<String>, String)],
    iso_date: &str,
    max_new: usize,
) -> Result<(usize, usize), AppError> {
    // Verify the parent up front so we fail fast without hitting validation
    // for each item. Same check add_identifier does — redundant here, but
    // catches the case where the entity was retyped between the OSINT call
    // and now.
    validate_parent_is_business(pool, entity_id).await?;

    // Existing active identifiers — used to suppress duplicates.
    let existing = list_for_entity(pool, entity_id).await?;
    let mut seen: std::collections::BTreeSet<(String, String, String)> =
        std::collections::BTreeSet::new();
    for row in &existing {
        seen.insert((
            row.kind.clone(),
            row.value.trim().to_lowercase(),
            row.platform
                .as_deref()
                .unwrap_or("")
                .trim()
                .to_lowercase(),
        ));
    }

    let mut attempted = 0usize;
    let mut inserted = 0usize;

    for (kind, value, platform, source_tool) in discovered {
        if inserted >= max_new {
            break;
        }

        // Candidate dedup key (must match the set above exactly).
        let key = (
            kind.clone(),
            value.trim().to_lowercase(),
            platform
                .as_deref()
                .unwrap_or("")
                .trim()
                .to_lowercase(),
        );
        if seen.contains(&key) {
            continue;
        }

        let input = BusinessIdentifierInput {
            kind: kind.clone(),
            value: value.clone(),
            platform: platform.clone(),
            notes: Some(format!(
                "Auto-discovered via OSINT {source_tool} on {iso_date}"
            )),
        };

        // Validate — silently skip candidates that fail (e.g., wrong kind for
        // this entity type, too long, leading-dash).
        if validate_input(&input).is_err() {
            continue;
        }

        attempted += 1;
        match add_identifier(pool, entity_id, &input).await {
            Ok(_) => {
                inserted += 1;
                seen.insert(key);
            }
            Err(_) => {
                // Individual insert failures are non-fatal — log would be
                // ideal but we're in the db layer with no tracing context.
                // The caller tracks the delta between attempted and inserted.
                continue;
            }
        }
    }

    Ok((attempted, inserted))
}

/// Cascade soft-delete all active identifiers for a given entity. Called from
/// `entities::soft_delete` inside its transaction so deleting a business and
/// hiding their identifiers is atomic.
pub(crate) async fn cascade_soft_delete_for_entity(
    tx: &mut Transaction<'_, Sqlite>,
    entity_id: i64,
) -> Result<(), AppError> {
    sqlx::query(
        r#"
        UPDATE business_identifiers
        SET is_deleted = 1, updated_at = CURRENT_TIMESTAMP
        WHERE entity_id = ? AND is_deleted = 0
        "#,
    )
    .bind(entity_id)
    .execute(&mut **tx)
    .await?;

    Ok(())
}

// ─── Unit tests ───────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::entities::{add_entity, EntityInput};
    use crate::test_helpers::test_forensics_db_with_schema as make_forensics_pool;

    async fn seed_business(pool: &SqlitePool) -> i64 {
        // A case must exist because entities.case_id has a FK to cases.
        sqlx::query(
            r#"
            INSERT INTO cases (case_id, case_name, investigator, start_date)
            VALUES ('CASE-001', 'Test Case', 'Investigator', '2026-01-01')
            "#,
        )
        .execute(pool)
        .await
        .expect("insert test case");

        let biz = add_entity(
            pool,
            "CASE-001",
            &EntityInput {
                entity_type: "business".into(),
                display_name: "Acme Corp".into(),
                subtype: None,
                organizational_rank: None,
                parent_entity_id: None,
                notes: None,
                metadata_json: None,
                email: None,
                phone: None,
                username: None,
                employer: None,
                dob: None,
            },
        )
        .await
        .expect("add business");

        biz.entity_id
    }

    async fn seed_person(pool: &SqlitePool) -> i64 {
        sqlx::query(
            r#"
            INSERT INTO cases (case_id, case_name, investigator, start_date)
            VALUES ('CASE-002', 'Test Case 2', 'Investigator', '2026-01-01')
            "#,
        )
        .execute(pool)
        .await
        .expect("insert test case");

        let person = add_entity(
            pool,
            "CASE-002",
            &EntityInput {
                entity_type: "person".into(),
                display_name: "Alice Example".into(),
                subtype: Some("suspect".into()),
                organizational_rank: None,
                parent_entity_id: None,
                notes: None,
                metadata_json: None,
                email: None,
                phone: None,
                username: None,
                employer: None,
                dob: None,
            },
        )
        .await
        .expect("add person");

        person.entity_id
    }

    fn make_input(kind: &str, value: &str) -> BusinessIdentifierInput {
        BusinessIdentifierInput {
            kind: kind.into(),
            value: value.into(),
            platform: None,
            notes: None,
        }
    }

    #[tokio::test]
    async fn add_and_get_roundtrip() {
        let pool = make_forensics_pool().await;
        let entity_id = seed_business(&pool).await;

        let input = BusinessIdentifierInput {
            kind: "email".into(),
            value: "info@acme.com".into(),
            platform: Some("google-workspace".into()),
            notes: Some("primary contact".into()),
        };
        let added = add_identifier(&pool, entity_id, &input).await.unwrap();
        assert!(added.identifier_id > 0);
        assert_eq!(added.entity_id, entity_id);
        assert_eq!(added.kind, "email");
        assert_eq!(added.value, "info@acme.com");
        assert_eq!(added.platform.as_deref(), Some("google-workspace"));
        assert_eq!(added.notes.as_deref(), Some("primary contact"));
        assert_eq!(added.is_deleted, 0);

        let fetched = get_identifier(&pool, added.identifier_id).await.unwrap();
        assert_eq!(fetched.identifier_id, added.identifier_id);
        assert_eq!(fetched.value, "info@acme.com");
    }

    #[tokio::test]
    async fn list_for_entity_orders_by_kind_then_created_at() {
        let pool = make_forensics_pool().await;
        let entity_id = seed_business(&pool).await;

        // Insert in scrambled order: url, domain, domain, email
        add_identifier(&pool, entity_id, &make_input("url", "https://acme.com/about"))
            .await
            .unwrap();
        add_identifier(&pool, entity_id, &make_input("domain", "acme.com"))
            .await
            .unwrap();
        add_identifier(&pool, entity_id, &make_input("domain", "acme.org"))
            .await
            .unwrap();
        add_identifier(&pool, entity_id, &make_input("email", "info@acme.com"))
            .await
            .unwrap();

        let list = list_for_entity(&pool, entity_id).await.unwrap();
        // Order: domain, domain, email, url (alphabetical by kind)
        let kinds: Vec<&str> = list.iter().map(|i| i.kind.as_str()).collect();
        assert_eq!(kinds, vec!["domain", "domain", "email", "url"]);
        // Within domain group, insertion order is preserved.
        assert_eq!(list[0].value, "acme.com");
        assert_eq!(list[1].value, "acme.org");
    }

    #[tokio::test]
    async fn validation_rejects_bad_kind() {
        let pool = make_forensics_pool().await;
        let entity_id = seed_business(&pool).await;

        let err = add_identifier(
            &pool,
            entity_id,
            &make_input("facebook", "acme.facebook"),
        )
        .await
        .unwrap_err();
        assert!(matches!(err, AppError::ValidationError { ref field, .. } if field == "kind"));
    }

    #[tokio::test]
    async fn validation_rejects_empty_value() {
        let pool = make_forensics_pool().await;
        let entity_id = seed_business(&pool).await;

        let err = add_identifier(&pool, entity_id, &make_input("email", "   "))
            .await
            .unwrap_err();
        assert!(matches!(err, AppError::ValidationError { ref field, .. } if field == "value"));
    }

    #[tokio::test]
    async fn validation_rejects_oversize_value() {
        let pool = make_forensics_pool().await;
        let entity_id = seed_business(&pool).await;

        let huge = "a".repeat(VALUE_MAX_LEN + 1);
        let err = add_identifier(&pool, entity_id, &make_input("email", &huge))
            .await
            .unwrap_err();
        assert!(matches!(err, AppError::ValidationError { ref field, .. } if field == "value"));
    }

    #[tokio::test]
    async fn rejects_non_business_parent() {
        let pool = make_forensics_pool().await;
        let person_id = seed_person(&pool).await;

        let err = add_identifier(&pool, person_id, &make_input("email", "info@acme.com"))
            .await
            .unwrap_err();
        assert!(matches!(
            err,
            AppError::EntityNotABusiness { entity_type, .. } if entity_type == "person"
        ));
    }

    #[tokio::test]
    async fn rejects_missing_parent() {
        let pool = make_forensics_pool().await;
        let err = add_identifier(&pool, 999_999, &make_input("email", "info@acme.com"))
            .await
            .unwrap_err();
        assert!(matches!(err, AppError::EntityNotFound { entity_id: 999_999 }));
    }

    #[tokio::test]
    async fn update_changes_fields_and_stamps_updated_at() {
        let pool = make_forensics_pool().await;
        let entity_id = seed_business(&pool).await;

        let added = add_identifier(&pool, entity_id, &make_input("email", "info@acme.com"))
            .await
            .unwrap();

        let updated = update_identifier(
            &pool,
            added.identifier_id,
            &BusinessIdentifierInput {
                kind: "email".into(),
                value: "contact@acme.com".into(),
                platform: Some("google-workspace".into()),
                notes: Some("updated 2026-04".into()),
            },
        )
        .await
        .unwrap();

        assert_eq!(updated.value, "contact@acme.com");
        assert_eq!(updated.platform.as_deref(), Some("google-workspace"));
        assert_eq!(updated.notes.as_deref(), Some("updated 2026-04"));
    }

    #[tokio::test]
    async fn soft_delete_hides_from_list_but_get_still_returns() {
        let pool = make_forensics_pool().await;
        let entity_id = seed_business(&pool).await;

        let added = add_identifier(&pool, entity_id, &make_input("email", "info@acme.com"))
            .await
            .unwrap();

        soft_delete(&pool, added.identifier_id).await.unwrap();

        // list_for_entity must skip it.
        let list = list_for_entity(&pool, entity_id).await.unwrap();
        assert!(list.is_empty(), "soft-deleted row must not appear in list");

        // get_identifier still returns the row (audit-trail semantics).
        let fetched = get_identifier(&pool, added.identifier_id).await.unwrap();
        assert_eq!(fetched.is_deleted, 1);
    }

    #[tokio::test]
    async fn soft_delete_twice_fails() {
        let pool = make_forensics_pool().await;
        let entity_id = seed_business(&pool).await;

        let added = add_identifier(&pool, entity_id, &make_input("email", "info@acme.com"))
            .await
            .unwrap();

        soft_delete(&pool, added.identifier_id).await.unwrap();
        let err = soft_delete(&pool, added.identifier_id).await.unwrap_err();
        assert!(matches!(
            err,
            AppError::BusinessIdentifierNotFound { identifier_id } if identifier_id == added.identifier_id
        ));
    }

    #[tokio::test]
    async fn update_rejects_soft_deleted() {
        let pool = make_forensics_pool().await;
        let entity_id = seed_business(&pool).await;

        let added = add_identifier(&pool, entity_id, &make_input("email", "info@acme.com"))
            .await
            .unwrap();
        soft_delete(&pool, added.identifier_id).await.unwrap();

        let err = update_identifier(
            &pool,
            added.identifier_id,
            &make_input("email", "contact@acme.com"),
        )
        .await
        .unwrap_err();
        assert!(matches!(err, AppError::BusinessIdentifierNotFound { .. }));
    }

    #[tokio::test]
    async fn empty_platform_and_notes_normalized_to_none() {
        let pool = make_forensics_pool().await;
        let entity_id = seed_business(&pool).await;

        let input = BusinessIdentifierInput {
            kind: "domain".into(),
            value: "acme.com".into(),
            platform: Some("   ".into()),
            notes: Some("".into()),
        };
        let added = add_identifier(&pool, entity_id, &input).await.unwrap();
        assert_eq!(added.platform, None);
        assert_eq!(added.notes, None);
    }

    #[tokio::test]
    async fn update_rejects_parent_retyped_to_non_business() {
        // Invariant: identifiers only exist on business entities. If the parent
        // entity is retyped (via entity_update) after an identifier is added,
        // any subsequent update to the identifier must fail with
        // EntityNotABusiness — the update path re-validates.
        let pool = make_forensics_pool().await;
        let entity_id = seed_business(&pool).await;

        let added = add_identifier(&pool, entity_id, &make_input("email", "info@acme.com"))
            .await
            .unwrap();

        // Retype the business to a person via direct SQL. This simulates a
        // future entity_update that permits type changes.
        sqlx::query("UPDATE entities SET entity_type = 'person' WHERE entity_id = ?")
            .bind(entity_id)
            .execute(&pool)
            .await
            .unwrap();

        let err = update_identifier(
            &pool,
            added.identifier_id,
            &make_input("email", "contact@acme.com"),
        )
        .await
        .unwrap_err();
        assert!(matches!(
            err,
            AppError::EntityNotABusiness { entity_type, .. } if entity_type == "person"
        ));
    }

    #[tokio::test]
    async fn value_length_counts_chars_not_bytes() {
        // A 500-char string of 4-byte emoji (2000 bytes) must PASS the length
        // check now that we count characters instead of bytes. This matches
        // zod .max(500) on the frontend.
        let pool = make_forensics_pool().await;
        let entity_id = seed_business(&pool).await;

        let emoji = "🦀".repeat(500); // exactly 500 chars, 2000 bytes
        assert_eq!(emoji.chars().count(), 500);
        assert_eq!(emoji.len(), 2000);

        let added = add_identifier(
            &pool,
            entity_id,
            &BusinessIdentifierInput {
                kind: "domain".into(),
                value: emoji,
                platform: None,
                notes: None,
            },
        )
        .await
        .expect("500-char Unicode value must be accepted");
        assert_eq!(added.value.chars().count(), 500);

        // A 501-char emoji string must still fail.
        let too_long = "🦀".repeat(501);
        let err = add_identifier(
            &pool,
            entity_id,
            &BusinessIdentifierInput {
                kind: "domain".into(),
                value: too_long,
                platform: None,
                notes: None,
            },
        )
        .await
        .unwrap_err();
        assert!(matches!(err, AppError::ValidationError { ref field, .. } if field == "value"));
    }

    #[tokio::test]
    async fn cascade_soft_delete_for_entity_hides_all_identifiers() {
        let pool = make_forensics_pool().await;
        let entity_id = seed_business(&pool).await;

        add_identifier(&pool, entity_id, &make_input("email", "a@acme.com")).await.unwrap();
        add_identifier(&pool, entity_id, &make_input("domain", "acme.com")).await.unwrap();
        add_identifier(&pool, entity_id, &make_input("phone", "+15555551234")).await.unwrap();
        assert_eq!(list_for_entity(&pool, entity_id).await.unwrap().len(), 3);

        // Call cascade directly in a transaction.
        let mut tx = pool.begin().await.unwrap();
        cascade_soft_delete_for_entity(&mut tx, entity_id).await.unwrap();
        tx.commit().await.unwrap();

        assert!(list_for_entity(&pool, entity_id).await.unwrap().is_empty());
    }

    // ─── insert_discovered_batch tests ─────────────────────────────────────

    fn disco(
        kind: &str,
        value: &str,
        platform: Option<&str>,
        tool: &str,
    ) -> (String, String, Option<String>, String) {
        (
            kind.into(),
            value.into(),
            platform.map(|s| s.into()),
            tool.into(),
        )
    }

    #[tokio::test]
    async fn discovered_batch_inserts_new_and_skips_existing() {
        let pool = make_forensics_pool().await;
        let entity_id = seed_business(&pool).await;

        add_identifier(
            &pool,
            entity_id,
            &BusinessIdentifierInput {
                kind: "domain".into(),
                value: "acme.com".into(),
                platform: None,
                notes: None,
            },
        )
        .await
        .unwrap();

        let batch = vec![
            disco("domain", "acme.com", None, "subfinder"),
            disco("domain", "dev.acme.com", None, "subfinder"),
            disco("email", "info@acme.com", None, "theHarvester"),
        ];

        let (_attempted, inserted) =
            insert_discovered_batch(&pool, entity_id, &batch, "2026-04-16", 50)
                .await
                .unwrap();
        assert_eq!(inserted, 2, "acme.com already existed — only 2 new");

        let rows = list_for_entity(&pool, entity_id).await.unwrap();
        let values: Vec<&str> = rows.iter().map(|r| r.value.as_str()).collect();
        assert!(values.contains(&"dev.acme.com"));
        assert!(values.contains(&"info@acme.com"));
    }

    #[tokio::test]
    async fn discovered_batch_stamps_provenance_in_notes() {
        let pool = make_forensics_pool().await;
        let entity_id = seed_business(&pool).await;

        let batch = vec![disco("domain", "new.acme.com", None, "subfinder")];
        let (_attempted, inserted) =
            insert_discovered_batch(&pool, entity_id, &batch, "2026-04-16", 50)
                .await
                .unwrap();
        assert_eq!(inserted, 1);

        let rows = list_for_entity(&pool, entity_id).await.unwrap();
        let row = rows.iter().find(|r| r.value == "new.acme.com").unwrap();
        let notes = row.notes.as_deref().unwrap_or("");
        assert!(
            notes.contains("Auto-discovered via OSINT")
                && notes.contains("subfinder")
                && notes.contains("2026-04-16"),
            "notes should carry tool + date provenance, got: {notes}"
        );
    }

    #[tokio::test]
    async fn discovered_batch_enforces_max_new_cap() {
        let pool = make_forensics_pool().await;
        let entity_id = seed_business(&pool).await;

        let batch: Vec<_> = (0..10)
            .map(|i| disco("domain", &format!("sub{i}.acme.com"), None, "subfinder"))
            .collect();

        let (_attempted, inserted) =
            insert_discovered_batch(&pool, entity_id, &batch, "2026-04-16", 4)
                .await
                .unwrap();
        assert_eq!(inserted, 4, "cap should limit insertion to 4");
    }

    #[tokio::test]
    async fn discovered_batch_skips_invalid_kinds_for_business() {
        let pool = make_forensics_pool().await;
        let entity_id = seed_business(&pool).await;

        // "username" and "handle" are person-only kinds — must be skipped.
        let batch = vec![
            disco("username", "acmecorp", None, "sherlock"),
            disco("handle", "@acme", None, "sherlock"),
            disco("email", "info@acme.com", None, "theHarvester"),
        ];

        let (_attempted, inserted) =
            insert_discovered_batch(&pool, entity_id, &batch, "2026-04-16", 50)
                .await
                .unwrap();
        assert_eq!(inserted, 1);
        let rows = list_for_entity(&pool, entity_id).await.unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].kind, "email");
    }

    #[tokio::test]
    async fn discovered_batch_dedupes_within_batch() {
        let pool = make_forensics_pool().await;
        let entity_id = seed_business(&pool).await;

        let batch = vec![
            disco("email", "info@acme.com", None, "theHarvester"),
            disco("email", "info@acme.com", None, "spiderfoot"),
            disco("email", "INFO@ACME.COM", None, "holehe"),
        ];

        let (_attempted, inserted) =
            insert_discovered_batch(&pool, entity_id, &batch, "2026-04-16", 50)
                .await
                .unwrap();
        assert_eq!(inserted, 1);
    }

    #[tokio::test]
    async fn discovered_batch_rejects_non_business_entity() {
        let pool = make_forensics_pool().await;
        let person_id = seed_person(&pool).await;

        let batch = vec![disco("domain", "acme.com", None, "subfinder")];
        let result =
            insert_discovered_batch(&pool, person_id, &batch, "2026-04-16", 50).await;
        assert!(matches!(result, Err(AppError::EntityNotABusiness { .. })));
    }
}
