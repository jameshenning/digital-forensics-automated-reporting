/// Case shares database queries — audit trail for email/print distribution.
///
/// Tracks when forensic records leave the application (email or print),
/// satisfying chain-of-custody requirements for evidence disposition.

use serde::{Deserialize, Serialize};
use sqlx::SqlitePool;

use crate::error::AppError;

// ─── Public data types ────────────────────────────────────────────────────────

/// A single share record from the `case_shares` table.
#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct CaseShare {
    pub share_id: i64,
    pub case_id: String,
    pub record_type: String,
    pub record_id: String,
    pub record_summary: Option<String>,
    pub action: String,
    pub recipient: Option<String>,
    pub file_path: Option<String>,
    pub file_hash: String,
    pub narrative: String,
    pub shared_by: String,
    pub created_at: String,
}

/// Input for creating a share record.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShareInput {
    pub case_id: String,
    pub record_type: String,
    pub record_id: String,
    pub record_summary: Option<String>,
    pub action: String,
    pub recipient: Option<String>,
    pub file_path: Option<String>,
    pub file_hash: String,
    pub narrative: String,
    pub shared_by: String,
}

// ─── Validation constants ────────────────────────────────────────────────────

const VALID_RECORD_TYPES: &[&str] = &["evidence", "hash", "custody", "tool", "analysis", "report"];
const VALID_ACTIONS: &[&str] = &["email", "print"];
const RECORD_TYPE_MAX_LEN: usize = 32;
const RECORD_ID_MAX_LEN: usize = 128;
const RECIPIENT_MAX_LEN: usize = 256;
const NARRATIVE_MAX_LEN: usize = 2048;

// ─── Validation helpers ───────────────────────────────────────────────────────

fn validate_record_type(rt: &str) -> Result<(), AppError> {
    if rt.is_empty() {
        return Err(AppError::ValidationError {
            field: "record_type".into(),
            message: "record_type must not be empty".into(),
        });
    }
    if rt.len() > RECORD_TYPE_MAX_LEN {
        return Err(AppError::ValidationError {
            field: "record_type".into(),
            message: format!("record_type must not exceed {RECORD_TYPE_MAX_LEN} characters"),
        });
    }
    if !VALID_RECORD_TYPES.contains(&rt) {
        return Err(AppError::ValidationError {
            field: "record_type".into(),
            message: format!(
                "record_type must be one of: {}",
                VALID_RECORD_TYPES.join(", ")
            ),
        });
    }
    Ok(())
}

fn validate_record_id(rid: &str) -> Result<(), AppError> {
    if rid.is_empty() {
        return Err(AppError::ValidationError {
            field: "record_id".into(),
            message: "record_id must not be empty".into(),
        });
    }
    if rid.len() > RECORD_ID_MAX_LEN {
        return Err(AppError::ValidationError {
            field: "record_id".into(),
            message: format!("record_id must not exceed {RECORD_ID_MAX_LEN} characters"),
        });
    }
    Ok(())
}

fn validate_action(action: &str) -> Result<(), AppError> {
    if action.is_empty() {
        return Err(AppError::ValidationError {
            field: "action".into(),
            message: "action must not be empty".into(),
        });
    }
    if !VALID_ACTIONS.contains(&action) {
        return Err(AppError::ValidationError {
            field: "action".into(),
            message: format!("action must be one of: {}", VALID_ACTIONS.join(", ")),
        });
    }
    Ok(())
}

fn validate_input(input: &ShareInput) -> Result<(), AppError> {
    validate_record_type(&input.record_type)?;
    validate_record_id(&input.record_id)?;
    validate_action(&input.action)?;
    if let Some(ref recipient) = input.recipient {
        if recipient.len() > RECIPIENT_MAX_LEN {
            return Err(AppError::ValidationError {
                field: "recipient".into(),
                message: format!("recipient must not exceed {RECIPIENT_MAX_LEN} characters"),
            });
        }
    }
    if input.narrative.is_empty() {
        return Err(AppError::ValidationError {
            field: "narrative".into(),
            message: "narrative must not be empty".into(),
        });
    }
    if input.narrative.len() > NARRATIVE_MAX_LEN {
        return Err(AppError::ValidationError {
            field: "narrative".into(),
            message: format!("narrative must not exceed {NARRATIVE_MAX_LEN} characters"),
        });
    }
    if input.file_hash.is_empty() {
        return Err(AppError::ValidationError {
            field: "file_hash".into(),
            message: "file_hash must not be empty".into(),
        });
    }
    if input.shared_by.is_empty() {
        return Err(AppError::ValidationError {
            field: "shared_by".into(),
            message: "shared_by must not be empty".into(),
        });
    }
    Ok(())
}

// ─── Public query functions ───────────────────────────────────────────────────

/// Insert a new share record.
pub async fn add_share(pool: &SqlitePool, input: &ShareInput) -> Result<CaseShare, AppError> {
    validate_input(input)?;

    let row_id = sqlx::query(
        r#"
        INSERT INTO case_shares (
            case_id, record_type, record_id, record_summary,
            action, recipient, file_path, file_hash, narrative, shared_by
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        "#,
    )
    .bind(&input.case_id)
    .bind(&input.record_type)
    .bind(&input.record_id)
    .bind(&input.record_summary)
    .bind(&input.action)
    .bind(&input.recipient)
    .bind(&input.file_path)
    .bind(&input.file_hash)
    .bind(&input.narrative)
    .bind(&input.shared_by)
    .execute(pool)
    .await
    .map_err(|e| {
        if is_fk_constraint_error(&e) {
            AppError::CaseNotFound {
                case_id: input.case_id.clone(),
            }
        } else {
            AppError::from(e)
        }
    })?
    .last_insert_rowid();

    let share = sqlx::query_as::<_, CaseShare>(
        r#"
        SELECT
            share_id, case_id, record_type, record_id, record_summary,
            action, recipient, file_path, file_hash, narrative, shared_by, created_at
        FROM case_shares
        WHERE share_id = ?
        "#,
    )
    .bind(row_id)
    .fetch_one(pool)
    .await
    .map_err(AppError::from)?;

    Ok(share)
}

/// List share records for a case, ordered by created_at DESC.
pub async fn list_for_case(
    pool: &SqlitePool,
    case_id: &str,
) -> Result<Vec<CaseShare>, AppError> {
    let rows = sqlx::query_as::<_, CaseShare>(
        r#"
        SELECT
            share_id, case_id, record_type, record_id, record_summary,
            action, recipient, file_path, file_hash, narrative, shared_by, created_at
        FROM case_shares
        WHERE case_id = ?
        ORDER BY share_id DESC
        "#,
    )
    .bind(case_id)
    .fetch_all(pool)
    .await
    .map_err(AppError::from)?;

    Ok(rows)
}

// ─── FK-constraint error detection ───────────────────────────────────────────

fn is_fk_constraint_error(e: &sqlx::Error) -> bool {
    match e {
        sqlx::Error::Database(db_err) => {
            let msg = db_err.message();
            msg.contains("FOREIGN KEY constraint failed")
        }
        _ => false,
    }
}

// ─── Inline unit tests ────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validate_record_type_rejects_empty() {
        let err = validate_record_type("").unwrap_err();
        assert!(format!("{err:?}").contains("record_type"));
    }

    #[test]
    fn validate_record_type_rejects_invalid() {
        let err = validate_record_type("photo").unwrap_err();
        assert!(format!("{err:?}").contains("record_type"));
    }

    #[test]
    fn validate_record_type_accepts_evidence() {
        assert!(validate_record_type("evidence").is_ok());
    }

    #[test]
    fn validate_action_rejects_invalid() {
        let err = validate_action("fax").unwrap_err();
        assert!(format!("{err:?}").contains("action"));
    }

    #[test]
    fn validate_action_accepts_email() {
        assert!(validate_action("email").is_ok());
    }
}
