/// Analysis notes database queries — Phase 3a.
///
/// Manages the `analysis_notes` table: add and list.
/// No delete (append-only investigator notes — matches v1 behavior where there
/// is no delete route for analysis_notes in routes.py).
///
/// Public surface:
///   - `add_analysis`      — INSERT with validation; category/confidence allowlists
///   - `list_for_case`     — all notes for a case, ordered by created_at DESC
///   - `list_for_evidence` — notes linked to a specific evidence item
///
/// Validation:
///   - category: Observation | Timeline | Correlation | Anomaly |
///               Recommendation | Conclusion | Other
///   - confidence_level: Low | Medium | High  (default: Medium)
///   - finding: required, non-empty, max 500 chars
///   - description: optional, max 5000 chars
// NaiveDateTime no longer needed — `created_at` is a String for v1 compat.
use serde::{Deserialize, Serialize};
use sqlx::SqlitePool;

use crate::error::AppError;

// ─── Validation constants ────────────────────────────────────────────────────

const VALID_CATEGORIES: &[&str] = &[
    "Observation",
    "Timeline",
    "Correlation",
    "Anomaly",
    "Recommendation",
    "Conclusion",
    "Other",
];

const VALID_CONFIDENCE_LEVELS: &[&str] = &["Low", "Medium", "High"];

/// Validation levels per DFIR Forensic Validation methodology.
///   0 = Unvalidated        — not independently validated
///   1 = Tool-Validated     — validated against known-good dataset or hash
///   2 = Cross-Validated    — corroborated by secondary method or tool
///   3 = Examiner-Validated — manual verification by primary examiner
///   4 = Peer-Reviewed      — independently validated by second examiner
const VALIDATION_LEVEL_MIN: i64 = 0;
const VALIDATION_LEVEL_MAX: i64 = 4;

const FINDING_MAX_LEN: usize = 500;
const DESCRIPTION_MAX_LEN: usize = 5000;
// Validation-field length caps — generous but bounded so a stray paste
// doesn't bloat the audit trail. `alternatives_considered` is highest
// because reasoning chains run long in practice.
const CREATED_BY_MAX_LEN: usize = 200;
const METHOD_REFERENCE_MAX_LEN: usize = 500;
const ALTERNATIVES_MAX_LEN: usize = 5000;
const TOOL_VERSION_MAX_LEN: usize = 200;

// ─── Public data types ────────────────────────────────────────────────────────

/// Full analysis note row, maps 1:1 to the `analysis_notes` table.
/// `created_at` is a `String` for v1 compat — see `db::cases::Case`.
/// The four validation fields (created_by, method_reference,
/// alternatives_considered, tool_version) are nullable — v1 rows carry
/// NULLs and the UI renders "not recorded" placeholders rather than
/// silently backfilling. See migration 0007.
#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct AnalysisNote {
    pub note_id: i64,
    pub case_id: String,
    pub evidence_id: Option<String>,
    pub category: String,
    pub finding: String,
    pub description: Option<String>,
    pub confidence_level: String,
    pub created_at: String,
    #[serde(default)]
    pub created_by: Option<String>,
    #[serde(default)]
    pub method_reference: Option<String>,
    #[serde(default)]
    pub alternatives_considered: Option<String>,
    #[serde(default)]
    pub tool_version: Option<String>,
    /// Validation level (0-4) per DFIR Forensic Validation methodology.
    /// Backfilled to 0 (Unvalidated) for pre-migration rows.
    pub validation_level: i64,
}

/// Writable fields for adding a new analysis note.
///
/// `Default` yields empty strings for `category` + `finding`; callers
/// MUST set them explicitly or `validate_analysis_input` will reject
/// the input. Default exists so test construction can `..Default::default()`
/// and avoid churn when new optional fields are added (e.g., migration
/// 0007's `created_by`/`method_reference`/etc.).
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct AnalysisInput {
    /// Optional — note may apply to the whole case or a specific evidence item.
    pub evidence_id: Option<String>,
    pub category: String,
    pub finding: String,
    pub description: Option<String>,
    /// `None` → default `"Medium"`.
    pub confidence_level: Option<String>,
    /// Author of the finding. Optional at the DB layer for v1 compat,
    /// but the frontend form encourages it to enable meaningful peer
    /// review.
    #[serde(default)]
    pub created_by: Option<String>,
    /// SOP or standard cited (e.g., "NIST SP 800-86 §5.2").
    #[serde(default)]
    pub method_reference: Option<String>,
    /// Alternative explanations examined and ruled out.
    #[serde(default)]
    pub alternatives_considered: Option<String>,
    /// Tool + version that produced the finding.
    #[serde(default)]
    pub tool_version: Option<String>,
    /// Validation level (0-4). Defaults to 0 (Unvalidated) when omitted.
    #[serde(default)]
    pub validation_level: Option<i64>,
}

// ─── Validation helpers ───────────────────────────────────────────────────────

/// Validate category against the allowlist.
pub(crate) fn validate_category(category: &str) -> Result<(), AppError> {
    if !VALID_CATEGORIES.contains(&category) {
        return Err(AppError::ValidationError {
            field: "category".into(),
            message: format!(
                "category must be one of: {}",
                VALID_CATEGORIES.join(", ")
            ),
        });
    }
    Ok(())
}

/// Validate and resolve confidence_level (default: "Medium").
pub(crate) fn resolve_confidence(confidence: Option<&str>) -> Result<String, AppError> {
    let c = confidence.unwrap_or("Medium");
    if !VALID_CONFIDENCE_LEVELS.contains(&c) {
        return Err(AppError::ValidationError {
            field: "confidence_level".into(),
            message: format!(
                "confidence_level must be one of: {}",
                VALID_CONFIDENCE_LEVELS.join(", ")
            ),
        });
    }
    Ok(c.to_string())
}

/// Validate and resolve validation_level (default: 0).
pub(crate) fn resolve_validation_level(level: Option<i64>) -> Result<i64, AppError> {
    let v = level.unwrap_or(0);
    if !(VALIDATION_LEVEL_MIN..=VALIDATION_LEVEL_MAX).contains(&v) {
        return Err(AppError::ValidationError {
            field: "validation_level".into(),
            message: format!(
                "validation_level must be an integer between {VALIDATION_LEVEL_MIN} and {VALIDATION_LEVEL_MAX}"
            ),
        });
    }
    Ok(v)
}

fn validate_analysis_input(input: &AnalysisInput) -> Result<(String, i64), AppError> {
    validate_category(&input.category)?;
    let confidence = resolve_confidence(input.confidence_level.as_deref())?;
    let validation_level = resolve_validation_level(input.validation_level)?;

    if input.finding.trim().is_empty() {
        return Err(AppError::ValidationError {
            field: "finding".into(),
            message: "finding must not be empty".into(),
        });
    }
    // chars().count() — Unicode-safe character count. The previous
    // .len() check was BYTES, so a 250-emoji finding (~1000 bytes)
    // wrongly tripped the 500-char cap. Matches the new validation
    // fields' character-count pattern.
    if input.finding.chars().count() > FINDING_MAX_LEN {
        return Err(AppError::ValidationError {
            field: "finding".into(),
            message: format!("finding must not exceed {FINDING_MAX_LEN} characters"),
        });
    }
    if let Some(desc) = &input.description {
        if desc.chars().count() > DESCRIPTION_MAX_LEN {
            return Err(AppError::ValidationError {
                field: "description".into(),
                message: format!("description must not exceed {DESCRIPTION_MAX_LEN} characters"),
            });
        }
    }
    check_optional_len(&input.created_by, "created_by", CREATED_BY_MAX_LEN)?;
    check_optional_len(&input.method_reference, "method_reference", METHOD_REFERENCE_MAX_LEN)?;
    check_optional_len(&input.alternatives_considered, "alternatives_considered", ALTERNATIVES_MAX_LEN)?;
    check_optional_len(&input.tool_version, "tool_version", TOOL_VERSION_MAX_LEN)?;
    Ok((confidence, validation_level))
}

/// Reject an optional string that, when Some, exceeds `max_len` chars.
/// Does NOT reject empty strings — the frontend is responsible for
/// coercing empty form inputs to None before the IPC call.
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

// ─── Public query functions ───────────────────────────────────────────────────

/// Add a new analysis note.
///
/// `confidence_level` defaults to `"Medium"` when `None`.
/// Returns the full saved row (including the DB-generated `created_at`).
pub async fn add_analysis(
    pool: &SqlitePool,
    case_id: &str,
    input: &AnalysisInput,
) -> Result<AnalysisNote, AppError> {
    let (confidence, validation_level) = validate_analysis_input(input)?;

    let row_id = sqlx::query(
        r#"
        INSERT INTO analysis_notes (
            case_id, evidence_id, category, finding, description, confidence_level,
            created_by, method_reference, alternatives_considered, tool_version, validation_level
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        "#,
    )
    .bind(case_id)
    .bind(&input.evidence_id)
    .bind(&input.category)
    .bind(&input.finding)
    .bind(&input.description)
    .bind(&confidence)
    .bind(&input.created_by)
    .bind(&input.method_reference)
    .bind(&input.alternatives_considered)
    .bind(&input.tool_version)
    .bind(validation_level)
    .execute(pool)
    .await?
    .last_insert_rowid();

    let note = sqlx::query_as::<_, AnalysisNote>(
        r#"
        SELECT
            note_id, case_id, evidence_id, category, finding,
            description, confidence_level, created_at,
            created_by, method_reference, alternatives_considered, tool_version, validation_level
        FROM analysis_notes
        WHERE note_id = ?
        "#,
    )
    .bind(row_id)
    .fetch_one(pool)
    .await?;

    Ok(note)
}

/// List all analysis notes for a case, ordered by created_at DESC.
pub async fn list_for_case(
    pool: &SqlitePool,
    case_id: &str,
) -> Result<Vec<AnalysisNote>, AppError> {
    let rows = sqlx::query_as::<_, AnalysisNote>(
        r#"
        SELECT
            note_id, case_id, evidence_id, category, finding,
            description, confidence_level, created_at,
            created_by, method_reference, alternatives_considered, tool_version, validation_level
        FROM analysis_notes
        WHERE case_id = ?
        ORDER BY created_at DESC
        "#,
    )
    .bind(case_id)
    .fetch_all(pool)
    .await?;
    Ok(rows)
}

/// List analysis notes linked to a specific evidence item,
/// ordered by created_at DESC.
///
/// Only returns notes where evidence_id IS NOT NULL and matches the given
/// evidence_id. Notes that were unlinked (SET NULL on evidence delete) are
/// not included.
pub async fn list_for_evidence(
    pool: &SqlitePool,
    evidence_id: &str,
) -> Result<Vec<AnalysisNote>, AppError> {
    let rows = sqlx::query_as::<_, AnalysisNote>(
        r#"
        SELECT
            note_id, case_id, evidence_id, category, finding,
            description, confidence_level, created_at,
            created_by, method_reference, alternatives_considered, tool_version, validation_level
        FROM analysis_notes
        WHERE evidence_id = ?
        ORDER BY created_at DESC
        "#,
    )
    .bind(evidence_id)
    .fetch_all(pool)
    .await?;
    Ok(rows)
}

// ─── Inline unit tests ────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::{resolve_confidence, resolve_validation_level, validate_category};
    use crate::error::AppError;

    #[test]
    fn test_valid_categories() {
        for cat in &[
            "Observation",
            "Timeline",
            "Correlation",
            "Anomaly",
            "Recommendation",
            "Conclusion",
            "Other",
        ] {
            assert!(validate_category(cat).is_ok(), "category '{cat}' should be valid");
        }
    }

    #[test]
    fn test_invalid_category() {
        for bad in &["Note", "finding", "observation", ""] {
            let err = validate_category(bad).unwrap_err();
            assert!(
                matches!(err, AppError::ValidationError { ref field, .. } if field == "category"),
                "expected ValidationError for category {bad:?}"
            );
        }
    }

    #[test]
    fn test_valid_confidence_levels() {
        assert_eq!(resolve_confidence(Some("Low")).unwrap(), "Low");
        assert_eq!(resolve_confidence(Some("Medium")).unwrap(), "Medium");
        assert_eq!(resolve_confidence(Some("High")).unwrap(), "High");
    }

    #[test]
    fn test_confidence_default() {
        assert_eq!(resolve_confidence(None).unwrap(), "Medium");
    }

    #[test]
    fn test_invalid_confidence() {
        let err = resolve_confidence(Some("Critical")).unwrap_err();
        assert!(
            matches!(err, AppError::ValidationError { ref field, .. } if field == "confidence_level")
        );
    }

    #[test]
    fn test_valid_validation_levels() {
        for level in 0..=4 {
            assert_eq!(resolve_validation_level(Some(level)).unwrap(), level);
        }
    }

    #[test]
    fn test_validation_level_default() {
        assert_eq!(resolve_validation_level(None).unwrap(), 0);
    }

    #[test]
    fn test_invalid_validation_level() {
        let err = resolve_validation_level(Some(5)).unwrap_err();
        assert!(
            matches!(err, AppError::ValidationError { ref field, .. } if field == "validation_level")
        );
        let err = resolve_validation_level(Some(-1)).unwrap_err();
        assert!(
            matches!(err, AppError::ValidationError { ref field, .. } if field == "validation_level")
        );
    }
}
