/// Evidence database queries — Phase 3a.
///
/// Manages the `evidence` table: add, get, list for case, delete.
///
/// Public surface:
///   - `add_evidence`    — strict INSERT; validates evidence_id format and future-date
///   - `get_evidence`    — fetch single row by evidence_id
///   - `list_for_case`   — all evidence for a case, ordered by collection_datetime
///   - `delete_evidence` — transactional delete; explicitly unlinks analysis_notes
///                         (ON DELETE SET NULL), then attempts DELETE on evidence row.
///                         Custody/hash/files FKs are RESTRICT — caught and mapped to
///                         EvidenceHasDependents.
///
/// Validation:
///   - evidence_id: `[A-Za-z0-9._-]+`, max 64 chars, non-empty (same as case_id)
///   - collection_datetime: must not be in the future
///   - case_id FK: CaseNotFound if missing
use chrono::{NaiveDateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::SqlitePool;

use crate::error::AppError;

// ─── Validation constants ────────────────────────────────────────────────────

const EVIDENCE_ID_MAX_LEN: usize = 64;

// ─── Public data types ────────────────────────────────────────────────────────

/// Full evidence row, maps 1:1 to the `evidence` table.
#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct Evidence {
    pub evidence_id: String,
    pub case_id: String,
    pub description: String,
    pub collected_by: String,
    pub collection_datetime: NaiveDateTime,
    pub location: Option<String>,
    pub status: String,
    pub evidence_type: Option<String>,
    pub make_model: Option<String>,
    pub serial_number: Option<String>,
    pub storage_location: Option<String>,
}

/// Writable fields for creating a new evidence item.
/// `evidence_id` is user-supplied (same model as `case_id` — investigator
/// controls the identifier for evidence tracking purposes).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvidenceInput {
    pub evidence_id: String,
    pub description: String,
    pub collected_by: String,
    pub collection_datetime: NaiveDateTime,
    pub location: Option<String>,
    /// `None` → default `"Collected"`.
    pub status: Option<String>,
    pub evidence_type: Option<String>,
    pub make_model: Option<String>,
    pub serial_number: Option<String>,
    pub storage_location: Option<String>,
}

// ─── Validation helpers ───────────────────────────────────────────────────────

/// Validate the evidence_id format: same rules as case_id.
pub(crate) fn validate_evidence_id(evidence_id: &str) -> Result<(), AppError> {
    if evidence_id.is_empty() {
        return Err(AppError::ValidationError {
            field: "evidence_id".into(),
            message: "evidence_id must not be empty".into(),
        });
    }
    if evidence_id.len() > EVIDENCE_ID_MAX_LEN {
        return Err(AppError::ValidationError {
            field: "evidence_id".into(),
            message: format!("evidence_id must not exceed {EVIDENCE_ID_MAX_LEN} characters"),
        });
    }
    if !evidence_id
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '_' || c == '-')
    {
        return Err(AppError::ValidationError {
            field: "evidence_id".into(),
            message: "evidence_id may only contain A-Z, a-z, 0-9, '.', '_', '-'".into(),
        });
    }
    Ok(())
}

// ─── FK-constraint error helpers ─────────────────────────────────────────────

fn is_fk_constraint_error(e: &sqlx::Error) -> bool {
    match e {
        sqlx::Error::Database(db_err) => db_err.message().contains("FOREIGN KEY constraint failed"),
        _ => false,
    }
}

fn is_unique_constraint_error(e: &sqlx::Error) -> bool {
    match e {
        sqlx::Error::Database(db_err) => db_err.message().contains("UNIQUE constraint failed"),
        _ => false,
    }
}

// ─── Public query functions ───────────────────────────────────────────────────

/// Add a new evidence item to a case.
///
/// Validates:
///   - evidence_id format
///   - collection_datetime not in the future
///   - case_id exists (FK check — surfaces as CaseNotFound)
///   - evidence_id uniqueness (surfaces as EvidenceAlreadyExists)
pub async fn add_evidence(
    pool: &SqlitePool,
    case_id: &str,
    input: &EvidenceInput,
) -> Result<Evidence, AppError> {
    validate_evidence_id(&input.evidence_id)?;

    // Reject future collection datetime
    let now = Utc::now().naive_utc();
    if input.collection_datetime > now {
        return Err(AppError::ValidationError {
            field: "collection_datetime".into(),
            message: "collection_datetime must not be in the future".into(),
        });
    }

    let status = input.status.as_deref().unwrap_or("Collected");

    let result = sqlx::query(
        r#"
        INSERT INTO evidence (
            evidence_id, case_id, description, collected_by,
            collection_datetime, location, status, evidence_type,
            make_model, serial_number, storage_location
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        "#,
    )
    .bind(&input.evidence_id)
    .bind(case_id)
    .bind(&input.description)
    .bind(&input.collected_by)
    .bind(input.collection_datetime)
    .bind(&input.location)
    .bind(status)
    .bind(&input.evidence_type)
    .bind(&input.make_model)
    .bind(&input.serial_number)
    .bind(&input.storage_location)
    .execute(pool)
    .await;

    match result {
        Err(ref e) if is_unique_constraint_error(e) => {
            return Err(AppError::EvidenceAlreadyExists {
                evidence_id: input.evidence_id.clone(),
            });
        }
        Err(ref e) if is_fk_constraint_error(e) => {
            // case_id FK failed
            return Err(AppError::CaseNotFound {
                case_id: case_id.to_string(),
            });
        }
        Err(e) => return Err(AppError::from(e)),
        Ok(_) => {}
    }

    get_evidence(pool, &input.evidence_id).await
}

/// Fetch a single evidence item by evidence_id.
///
/// Returns `AppError::EvidenceNotFound` if no row exists.
pub async fn get_evidence(pool: &SqlitePool, evidence_id: &str) -> Result<Evidence, AppError> {
    sqlx::query_as::<_, Evidence>(
        r#"
        SELECT
            evidence_id, case_id, description, collected_by,
            collection_datetime, location, status, evidence_type,
            make_model, serial_number, storage_location
        FROM evidence
        WHERE evidence_id = ?
        "#,
    )
    .bind(evidence_id)
    .fetch_optional(pool)
    .await?
    .ok_or_else(|| AppError::EvidenceNotFound {
        evidence_id: evidence_id.to_string(),
    })
}

/// List all evidence items for a case, ordered by collection_datetime ascending.
///
/// Returns an empty vec if the case has no evidence (case existence is NOT
/// checked separately — call case_get first if you need that guarantee).
pub async fn list_for_case(pool: &SqlitePool, case_id: &str) -> Result<Vec<Evidence>, AppError> {
    let rows = sqlx::query_as::<_, Evidence>(
        r#"
        SELECT
            evidence_id, case_id, description, collected_by,
            collection_datetime, location, status, evidence_type,
            make_model, serial_number, storage_location
        FROM evidence
        WHERE case_id = ?
        ORDER BY collection_datetime ASC
        "#,
    )
    .bind(case_id)
    .fetch_all(pool)
    .await?;
    Ok(rows)
}

/// Delete an evidence item.
///
/// Runs in a transaction:
///   1. UPDATE analysis_notes SET evidence_id = NULL WHERE evidence_id = ?
///      (ON DELETE SET NULL — preserves analysis notes, unlinks them from
///      the about-to-be-deleted evidence row)
///   2. DELETE FROM evidence WHERE evidence_id = ?
///
/// If any other table (chain_of_custody, hash_verification, evidence_files,
/// evidence_analyses) still references this evidence_id via ON DELETE RESTRICT,
/// the DELETE will fail with a FOREIGN KEY constraint error, which is caught and
/// mapped to `AppError::EvidenceHasDependents`.
///
/// The exact FK-constraint error string SQLite surfaces:
///   `"FOREIGN KEY constraint failed"`
pub async fn delete_evidence(pool: &SqlitePool, evidence_id: &str) -> Result<(), AppError> {
    let mut tx = pool.begin().await?;

    // Unlink analysis_notes (ON DELETE SET NULL FK — safe to unlink)
    sqlx::query("UPDATE analysis_notes SET evidence_id = NULL WHERE evidence_id = ?")
        .bind(evidence_id)
        .execute(&mut *tx)
        .await?;

    // Attempt to delete the evidence row itself.
    // Any remaining FK RESTRICT child (custody, hash, files, analyses) fires here.
    let result = sqlx::query("DELETE FROM evidence WHERE evidence_id = ?")
        .bind(evidence_id)
        .execute(&mut *tx)
        .await;

    match result {
        Err(ref e) if is_fk_constraint_error(e) => {
            let _ = tx.rollback().await;
            return Err(AppError::EvidenceHasDependents {
                evidence_id: evidence_id.to_string(),
            });
        }
        Err(e) => {
            let _ = tx.rollback().await;
            return Err(AppError::from(e));
        }
        Ok(r) if r.rows_affected() == 0 => {
            let _ = tx.rollback().await;
            return Err(AppError::EvidenceNotFound {
                evidence_id: evidence_id.to_string(),
            });
        }
        Ok(_) => {}
    }

    tx.commit().await?;
    Ok(())
}

// ─── Inline unit tests ────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::validate_evidence_id;
    use crate::error::AppError;

    #[test]
    fn test_evidence_id_valid() {
        assert!(validate_evidence_id("EV-001").is_ok());
        assert!(validate_evidence_id("evidence.2026.01").is_ok());
        assert!(validate_evidence_id("ABC123").is_ok());
        assert!(validate_evidence_id("a_b-c.D").is_ok());
    }

    #[test]
    fn test_evidence_id_empty() {
        let err = validate_evidence_id("").unwrap_err();
        assert!(matches!(err, AppError::ValidationError { ref field, .. } if field == "evidence_id"));
    }

    #[test]
    fn test_evidence_id_too_long() {
        let long = "A".repeat(65);
        let err = validate_evidence_id(&long).unwrap_err();
        assert!(matches!(err, AppError::ValidationError { ref field, .. } if field == "evidence_id"));
    }

    #[test]
    fn test_evidence_id_invalid_chars() {
        for bad in &["EV 001", "EV/001", "EV@001", "EV#001"] {
            let err = validate_evidence_id(bad).unwrap_err();
            assert!(
                matches!(err, AppError::ValidationError { ref field, .. } if field == "evidence_id"),
                "expected ValidationError for {bad:?}"
            );
        }
    }

    #[test]
    fn test_evidence_id_max_len_exactly() {
        let exactly_64 = "A".repeat(64);
        assert!(validate_evidence_id(&exactly_64).is_ok());
    }
}
