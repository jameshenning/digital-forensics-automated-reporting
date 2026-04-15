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

const FINDING_MAX_LEN: usize = 500;
const DESCRIPTION_MAX_LEN: usize = 5000;

// ─── Public data types ────────────────────────────────────────────────────────

/// Full analysis note row, maps 1:1 to the `analysis_notes` table.
/// `created_at` is a `String` for v1 compat — see `db::cases::Case`.
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
}

/// Writable fields for adding a new analysis note.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnalysisInput {
    /// Optional — note may apply to the whole case or a specific evidence item.
    pub evidence_id: Option<String>,
    pub category: String,
    pub finding: String,
    pub description: Option<String>,
    /// `None` → default `"Medium"`.
    pub confidence_level: Option<String>,
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

fn validate_analysis_input(input: &AnalysisInput) -> Result<String, AppError> {
    validate_category(&input.category)?;
    let confidence = resolve_confidence(input.confidence_level.as_deref())?;

    if input.finding.trim().is_empty() {
        return Err(AppError::ValidationError {
            field: "finding".into(),
            message: "finding must not be empty".into(),
        });
    }
    if input.finding.len() > FINDING_MAX_LEN {
        return Err(AppError::ValidationError {
            field: "finding".into(),
            message: format!("finding must not exceed {FINDING_MAX_LEN} characters"),
        });
    }
    if let Some(desc) = &input.description {
        if desc.len() > DESCRIPTION_MAX_LEN {
            return Err(AppError::ValidationError {
                field: "description".into(),
                message: format!("description must not exceed {DESCRIPTION_MAX_LEN} characters"),
            });
        }
    }
    Ok(confidence)
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
    let confidence = validate_analysis_input(input)?;

    let row_id = sqlx::query(
        r#"
        INSERT INTO analysis_notes (
            case_id, evidence_id, category, finding, description, confidence_level
        ) VALUES (?, ?, ?, ?, ?, ?)
        "#,
    )
    .bind(case_id)
    .bind(&input.evidence_id)
    .bind(&input.category)
    .bind(&input.finding)
    .bind(&input.description)
    .bind(&confidence)
    .execute(pool)
    .await?
    .last_insert_rowid();

    let note = sqlx::query_as::<_, AnalysisNote>(
        r#"
        SELECT
            note_id, case_id, evidence_id, category, finding,
            description, confidence_level, created_at
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
            description, confidence_level, created_at
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
            description, confidence_level, created_at
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
    use super::{resolve_confidence, validate_category};
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
}
