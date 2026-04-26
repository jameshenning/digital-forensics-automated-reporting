/// Entity links database queries — Phase 4.
///
/// Manages the `entity_links` table: add, list for case, soft-delete.
/// No update method — mirrors v1 which uses delete-and-readd.
/// All deletes are soft (is_deleted = 1).
///
/// Public surface:
///   - `add_link`      — INSERT with full endpoint validation
///   - `list_for_case` — active rows only
///   - `soft_delete`   — sets is_deleted = 1
///
/// Validation:
///   - source_type / target_type: 'entity' | 'evidence'
///   - If entity: source_id/target_id must exist in same case (not soft-deleted)
///   - If evidence: source_id/target_id must exist in same case
///   - No self-loops
///   - directional: 0 or 1  (default 1)
///   - weight: 0.0 < weight ≤ 1000.0  (default 1.0)
///   - link_label: max 100 chars
// NaiveDateTime no longer needed — `created_at` is a String for v1 compat.
use serde::{Deserialize, Serialize};
use sqlx::SqlitePool;

use crate::error::AppError;

// ─── Validation constants ─────────────────────────────────────────────────────

const VALID_NODE_TYPES: &[&str] = &["entity", "evidence"];
const LINK_LABEL_MAX_LEN: usize = 100;
const WEIGHT_MAX: f64 = 1000.0;

/// Phase B (migration 0008) attribution allowlist. Matches Phase A's
/// `analysis_notes.confidence_level` enum so the UI can reuse the same chip
/// component across analytical findings and link assertions.
const VALID_CONFIDENCE_LEVELS: &[&str] = &["Low", "Medium", "High"];

// Character-counted caps (Unicode-safe). 200 for short identity-like fields,
// 500 for short narrative, 5000 for long narrative — same scale as the
// Phase A validation fields on analysis_notes.
const ATTRIBUTED_BY_MAX_LEN: usize = 200;
const BASIS_MAX_LEN: usize = 5000;
const METHOD_REFERENCE_MAX_LEN: usize = 500;
const ALTERNATIVES_MAX_LEN: usize = 5000;
const EVIDENCE_REFS_MAX_LEN: usize = 1000;

// ─── Public data types ────────────────────────────────────────────────────────

/// Full entity_links row, maps 1:1 to the `entity_links` table.
/// `created_at` is a `String` for v1 compat — see `db::cases::Case`.
///
/// Attribution fields (migration 0008, Phase B): every field is `Option<String>`
/// because v1 rows have no attribution recorded. The UI / report layer renders
/// "not recorded" placeholders rather than silently backfilling so v1 data is
/// presented honestly.
#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct Link {
    pub link_id: i64,
    pub case_id: String,
    pub source_type: String,
    pub source_id: String,
    pub target_type: String,
    pub target_id: String,
    pub link_label: Option<String>,
    pub directional: i64,
    pub weight: f64,
    pub notes: Option<String>,
    pub is_deleted: i64,
    pub created_at: String,
    // ── Migration 0008 attribution fields (all nullable for v1 compat) ──
    #[serde(default)]
    pub attributed_by: Option<String>,
    #[serde(default)]
    pub basis: Option<String>,
    #[serde(default)]
    pub confidence_level: Option<String>,
    #[serde(default)]
    pub method_reference: Option<String>,
    #[serde(default)]
    pub alternatives_considered: Option<String>,
    #[serde(default)]
    pub evidence_refs: Option<String>,
}

/// Writable fields for creating a new link.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LinkInput {
    pub source_type: String,
    pub source_id: String,
    pub target_type: String,
    pub target_id: String,
    pub link_label: Option<String>,
    /// `None` → 1 (directed)
    pub directional: Option<i64>,
    /// `None` → 1.0
    pub weight: Option<f64>,
    pub notes: Option<String>,
    // ── Migration 0008 attribution fields (all optional) ──
    #[serde(default)]
    pub attributed_by: Option<String>,
    #[serde(default)]
    pub basis: Option<String>,
    /// One of `VALID_CONFIDENCE_LEVELS` ("Low" | "Medium" | "High"), or `None`
    /// to leave attribution-confidence unrecorded. Unlike Phase A, we do NOT
    /// default to "Medium" here — confidence on a connection assertion is more
    /// load-bearing than on an analytical finding, and silently defaulting
    /// would misrepresent v1 rows that genuinely have no recorded confidence.
    #[serde(default)]
    pub confidence_level: Option<String>,
    #[serde(default)]
    pub method_reference: Option<String>,
    #[serde(default)]
    pub alternatives_considered: Option<String>,
    #[serde(default)]
    pub evidence_refs: Option<String>,
}

// ─── Validation helpers ───────────────────────────────────────────────────────

fn validate_node_type(field: &str, node_type: &str) -> Result<(), AppError> {
    if !VALID_NODE_TYPES.contains(&node_type) {
        return Err(AppError::ValidationError {
            field: field.into(),
            message: format!("{field} must be one of: {}", VALID_NODE_TYPES.join(", ")),
        });
    }
    Ok(())
}

async fn validate_entity_endpoint(
    pool: &SqlitePool,
    case_id: &str,
    entity_id_str: &str,
    field: &str,
) -> Result<(), AppError> {
    let entity_id: i64 = entity_id_str.parse().map_err(|_| AppError::ValidationError {
        field: field.into(),
        message: format!("{field} must be a valid integer entity_id when source_type is 'entity'"),
    })?;

    let exists: (i64,) = sqlx::query_as(
        "SELECT COUNT(*) FROM entities WHERE entity_id = ? AND case_id = ? AND is_deleted = 0",
    )
    .bind(entity_id)
    .bind(case_id)
    .fetch_one(pool)
    .await?;

    if exists.0 == 0 {
        return Err(AppError::LinkEndpointMissing {
            kind: "entity".into(),
            id: entity_id_str.to_string(),
        });
    }
    Ok(())
}

/// Reject an optional string that, when Some, exceeds `max_len` chars.
/// Mirrors the helper in `db::analysis` — empty Some("") is allowed through
/// here; the frontend coerces empty inputs to None before IPC.
fn check_optional_len(
    value: &Option<String>,
    field: &'static str,
    max_len: usize,
) -> Result<(), AppError> {
    if let Some(v) = value {
        if v.chars().count() > max_len {
            return Err(AppError::ValidationError {
                field: field.into(),
                message: format!("{field} must not exceed {max_len} characters"),
            });
        }
    }
    Ok(())
}

/// Validate the optional `confidence_level` against the allowlist.
/// Unlike Phase A we never *default* the value — `None` stays `None`.
fn validate_confidence_level(value: &Option<String>) -> Result<(), AppError> {
    if let Some(v) = value {
        if !VALID_CONFIDENCE_LEVELS.contains(&v.as_str()) {
            return Err(AppError::ValidationError {
                field: "confidence_level".into(),
                message: format!(
                    "confidence_level must be one of: {}",
                    VALID_CONFIDENCE_LEVELS.join(", ")
                ),
            });
        }
    }
    Ok(())
}

/// Validate all migration-0008 attribution fields on a `LinkInput`.
fn validate_attribution(input: &LinkInput) -> Result<(), AppError> {
    check_optional_len(&input.attributed_by, "attributed_by", ATTRIBUTED_BY_MAX_LEN)?;
    check_optional_len(&input.basis, "basis", BASIS_MAX_LEN)?;
    check_optional_len(
        &input.method_reference,
        "method_reference",
        METHOD_REFERENCE_MAX_LEN,
    )?;
    check_optional_len(
        &input.alternatives_considered,
        "alternatives_considered",
        ALTERNATIVES_MAX_LEN,
    )?;
    check_optional_len(&input.evidence_refs, "evidence_refs", EVIDENCE_REFS_MAX_LEN)?;
    validate_confidence_level(&input.confidence_level)?;
    Ok(())
}

async fn validate_evidence_endpoint(
    pool: &SqlitePool,
    case_id: &str,
    evidence_id: &str,
    _field: &str,
) -> Result<(), AppError> {
    let exists: (i64,) = sqlx::query_as(
        "SELECT COUNT(*) FROM evidence WHERE evidence_id = ? AND case_id = ?",
    )
    .bind(evidence_id)
    .bind(case_id)
    .fetch_one(pool)
    .await?;

    if exists.0 == 0 {
        return Err(AppError::LinkEndpointMissing {
            kind: "evidence".into(),
            id: evidence_id.to_string(),
        });
    }
    Ok(())
}

// ─── Public query functions ───────────────────────────────────────────────────

/// Add a new link between two nodes (entity or evidence) in a case.
///
/// Validates both endpoints, no self-loops, directional/weight bounds.
pub async fn add_link(
    pool: &SqlitePool,
    case_id: &str,
    input: &LinkInput,
) -> Result<Link, AppError> {
    // Validate node types
    validate_node_type("source_type", &input.source_type)?;
    validate_node_type("target_type", &input.target_type)?;

    // No self-loops
    if input.source_type == input.target_type && input.source_id == input.target_id {
        return Err(AppError::ValidationError {
            field: "source_id".into(),
            message: "a link cannot connect a node to itself".into(),
        });
    }

    // Validate source endpoint
    match input.source_type.as_str() {
        "entity" => {
            validate_entity_endpoint(pool, case_id, &input.source_id, "source_id").await?
        }
        "evidence" => {
            validate_evidence_endpoint(pool, case_id, &input.source_id, "source_id").await?
        }
        _ => unreachable!("node type validated above"),
    }

    // Validate target endpoint
    match input.target_type.as_str() {
        "entity" => {
            validate_entity_endpoint(pool, case_id, &input.target_id, "target_id").await?
        }
        "evidence" => {
            validate_evidence_endpoint(pool, case_id, &input.target_id, "target_id").await?
        }
        _ => unreachable!("node type validated above"),
    }

    // Validate directional
    let directional = input.directional.unwrap_or(1);
    if directional != 0 && directional != 1 {
        return Err(AppError::ValidationError {
            field: "directional".into(),
            message: "directional must be 0 or 1".into(),
        });
    }

    // Validate weight
    let weight = input.weight.unwrap_or(1.0);
    if weight <= 0.0 || weight > WEIGHT_MAX {
        return Err(AppError::ValidationError {
            field: "weight".into(),
            message: format!("weight must be > 0.0 and ≤ {WEIGHT_MAX}"),
        });
    }

    // Validate link_label length
    if let Some(ref label) = input.link_label {
        if label.len() > LINK_LABEL_MAX_LEN {
            return Err(AppError::ValidationError {
                field: "link_label".into(),
                message: format!("link_label must not exceed {LINK_LABEL_MAX_LEN} characters"),
            });
        }
    }

    // Migration 0008: attribution-field caps + confidence allowlist.
    validate_attribution(input)?;

    let row = sqlx::query_as::<_, Link>(
        r#"
        INSERT INTO entity_links (
            case_id, source_type, source_id, target_type, target_id,
            link_label, directional, weight, notes,
            attributed_by, basis, confidence_level,
            method_reference, alternatives_considered, evidence_refs
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        RETURNING
            link_id, case_id, source_type, source_id, target_type, target_id,
            link_label, directional, weight, notes, is_deleted, created_at,
            attributed_by, basis, confidence_level,
            method_reference, alternatives_considered, evidence_refs
        "#,
    )
    .bind(case_id)
    .bind(&input.source_type)
    .bind(&input.source_id)
    .bind(&input.target_type)
    .bind(&input.target_id)
    .bind(&input.link_label)
    .bind(directional)
    .bind(weight)
    .bind(&input.notes)
    .bind(&input.attributed_by)
    .bind(&input.basis)
    .bind(&input.confidence_level)
    .bind(&input.method_reference)
    .bind(&input.alternatives_considered)
    .bind(&input.evidence_refs)
    .fetch_one(pool)
    .await?;

    Ok(row)
}

/// List all active (non-deleted) links for a case.
pub async fn list_for_case(pool: &SqlitePool, case_id: &str) -> Result<Vec<Link>, AppError> {
    let rows = sqlx::query_as::<_, Link>(
        r#"
        SELECT link_id, case_id, source_type, source_id, target_type, target_id,
               link_label, directional, weight, notes, is_deleted, created_at,
               attributed_by, basis, confidence_level,
               method_reference, alternatives_considered, evidence_refs
        FROM entity_links
        WHERE case_id = ? AND is_deleted = 0
        ORDER BY created_at ASC
        "#,
    )
    .bind(case_id)
    .fetch_all(pool)
    .await?;

    Ok(rows)
}

/// Soft-delete a link by link_id.
pub async fn soft_delete(pool: &SqlitePool, link_id: i64) -> Result<(), AppError> {
    let rows_affected = sqlx::query(
        "UPDATE entity_links SET is_deleted = 1 WHERE link_id = ? AND is_deleted = 0",
    )
    .bind(link_id)
    .execute(pool)
    .await?
    .rows_affected();

    if rows_affected == 0 {
        return Err(AppError::LinkNotFound { link_id });
    }

    Ok(())
}

/// Fetch a single link by link_id (includes soft-deleted rows for audit purposes).
pub async fn get_link(pool: &SqlitePool, link_id: i64) -> Result<Link, AppError> {
    sqlx::query_as::<_, Link>(
        r#"
        SELECT link_id, case_id, source_type, source_id, target_type, target_id,
               link_label, directional, weight, notes, is_deleted, created_at,
               attributed_by, basis, confidence_level,
               method_reference, alternatives_considered, evidence_refs
        FROM entity_links
        WHERE link_id = ?
        "#,
    )
    .bind(link_id)
    .fetch_optional(pool)
    .await?
    .ok_or(AppError::LinkNotFound { link_id })
}
