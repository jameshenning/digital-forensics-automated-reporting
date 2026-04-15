/// Tool usage database queries — Phase 3a.
///
/// Manages the `tool_usage` table: add and list.
/// No delete at the individual record level (audit trail — matching v1 behavior
/// for case-level tool records; v1's delete is only used internally by
/// Analyze Evidence, which is Phase 3b/5).
///
/// Public surface:
///   - `add_tool`          — INSERT with defaults; execution_datetime defaults to now()
///   - `list_for_case`     — ordered by execution_datetime DESC
///   - `list_for_evidence` — filtered to a specific evidence item
///
/// Note: `tool_usage.evidence_id` was added via ALTER TABLE in v1's
/// `_migrate_schema()`. The schema migration `0002_tool_evidence_id.sql`
/// adds this column to v2 DBs. The column is nullable — tools can be
/// case-scoped (evidence_id = NULL) or evidence-scoped.
use chrono::{NaiveDateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::SqlitePool;

use crate::error::AppError;

// ─── Public data types ────────────────────────────────────────────────────────

/// Full tool usage row, maps 1:1 to the `tool_usage` table.
/// `execution_datetime` is a `String` for v1 compat — see `db::cases::Case`.
///
/// The four reproduction fields (`input_sha256` / `output_sha256` /
/// `environment_notes` / `reproduction_notes`) were added in migration 0003
/// and are all nullable. Case-wide runs that have no single input file
/// can omit them. See `forensic_tools.rs` for the curated KB steps that
/// these per-row fields combine with at render time.
#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct ToolUsage {
    pub tool_id: i64,
    pub case_id: String,
    pub evidence_id: Option<String>,
    pub tool_name: String,
    pub version: Option<String>,
    pub purpose: String,
    pub command_used: Option<String>,
    pub input_file: Option<String>,
    pub output_file: Option<String>,
    pub execution_datetime: String,
    pub operator: String,
    // Reproduction fields (migration 0003)
    pub input_sha256: Option<String>,
    pub output_sha256: Option<String>,
    pub environment_notes: Option<String>,
    pub reproduction_notes: Option<String>,
}

/// Writable fields for recording a new tool usage event.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolInput {
    /// Optional — tool may apply to the whole case (NULL) or a specific evidence item.
    pub evidence_id: Option<String>,
    pub tool_name: String,
    pub version: Option<String>,
    pub purpose: String,
    pub command_used: Option<String>,
    pub input_file: Option<String>,
    pub output_file: Option<String>,
    /// `None` → current UTC time.
    pub execution_datetime: Option<NaiveDateTime>,
    pub operator: String,
    // Reproduction fields (migration 0003) — operator-supplied, all optional
    #[serde(default)]
    pub input_sha256: Option<String>,
    #[serde(default)]
    pub output_sha256: Option<String>,
    #[serde(default)]
    pub environment_notes: Option<String>,
    #[serde(default)]
    pub reproduction_notes: Option<String>,
}

// ─── Validation helpers ───────────────────────────────────────────────────────

fn validate_tool_input(input: &ToolInput) -> Result<(), AppError> {
    if input.tool_name.trim().is_empty() {
        return Err(AppError::ValidationError {
            field: "tool_name".into(),
            message: "tool_name must not be empty".into(),
        });
    }
    if input.purpose.trim().is_empty() {
        return Err(AppError::ValidationError {
            field: "purpose".into(),
            message: "purpose must not be empty".into(),
        });
    }
    if input.operator.trim().is_empty() {
        return Err(AppError::ValidationError {
            field: "operator".into(),
            message: "operator must not be empty".into(),
        });
    }
    Ok(())
}

// ─── Public query functions ───────────────────────────────────────────────────

/// Add a new tool usage record.
///
/// `execution_datetime` defaults to `Utc::now().naive_utc()` when `None`.
/// Returns the full saved row.
pub async fn add_tool(
    pool: &SqlitePool,
    case_id: &str,
    input: &ToolInput,
) -> Result<ToolUsage, AppError> {
    validate_tool_input(input)?;

    let execution_dt = input
        .execution_datetime
        .unwrap_or_else(|| Utc::now().naive_utc());

    let row_id = sqlx::query(
        r#"
        INSERT INTO tool_usage (
            case_id, evidence_id, tool_name, version, purpose,
            command_used, input_file, output_file, execution_datetime, operator,
            input_sha256, output_sha256, environment_notes, reproduction_notes
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        "#,
    )
    .bind(case_id)
    .bind(&input.evidence_id)
    .bind(&input.tool_name)
    .bind(&input.version)
    .bind(&input.purpose)
    .bind(&input.command_used)
    .bind(&input.input_file)
    .bind(&input.output_file)
    .bind(execution_dt)
    .bind(&input.operator)
    .bind(&input.input_sha256)
    .bind(&input.output_sha256)
    .bind(&input.environment_notes)
    .bind(&input.reproduction_notes)
    .execute(pool)
    .await?
    .last_insert_rowid();

    let record = sqlx::query_as::<_, ToolUsage>(
        r#"
        SELECT
            tool_id, case_id, evidence_id, tool_name, version, purpose,
            command_used, input_file, output_file, execution_datetime, operator,
            input_sha256, output_sha256, environment_notes, reproduction_notes
        FROM tool_usage
        WHERE tool_id = ?
        "#,
    )
    .bind(row_id)
    .fetch_one(pool)
    .await?;

    Ok(record)
}

/// List all tool usage records for a case, ordered by execution_datetime DESC.
pub async fn list_for_case(pool: &SqlitePool, case_id: &str) -> Result<Vec<ToolUsage>, AppError> {
    let rows = sqlx::query_as::<_, ToolUsage>(
        r#"
        SELECT
            tool_id, case_id, evidence_id, tool_name, version, purpose,
            command_used, input_file, output_file, execution_datetime, operator,
            input_sha256, output_sha256, environment_notes, reproduction_notes
        FROM tool_usage
        WHERE case_id = ?
        ORDER BY execution_datetime DESC
        "#,
    )
    .bind(case_id)
    .fetch_all(pool)
    .await?;
    Ok(rows)
}

/// List all tool usage records associated with a specific evidence item.
///
/// Uses the nullable `evidence_id` column (added via 0002_tool_evidence_id.sql).
pub async fn list_for_evidence(
    pool: &SqlitePool,
    evidence_id: &str,
) -> Result<Vec<ToolUsage>, AppError> {
    let rows = sqlx::query_as::<_, ToolUsage>(
        r#"
        SELECT
            tool_id, case_id, evidence_id, tool_name, version, purpose,
            command_used, input_file, output_file, execution_datetime, operator,
            input_sha256, output_sha256, environment_notes, reproduction_notes
        FROM tool_usage
        WHERE evidence_id = ?
        ORDER BY execution_datetime DESC
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
    use super::{ToolInput, validate_tool_input};
    use crate::error::AppError;

    fn minimal_tool_input() -> ToolInput {
        ToolInput {
            evidence_id: None,
            tool_name: "FTK Imager".to_string(),
            version: Some("4.7.1".to_string()),
            purpose: "Disk imaging".to_string(),
            command_used: None,
            input_file: None,
            output_file: None,
            execution_datetime: None,
            operator: "examiner".to_string(),
        input_sha256: None,
        output_sha256: None,
        environment_notes: None,
        reproduction_notes: None,
        }
    }

    #[test]
    fn test_valid_tool_input() {
        assert!(validate_tool_input(&minimal_tool_input()).is_ok());
    }

    #[test]
    fn test_empty_tool_name() {
        let mut input = minimal_tool_input();
        input.tool_name = "".to_string();
        let err = validate_tool_input(&input).unwrap_err();
        assert!(
            matches!(err, AppError::ValidationError { ref field, .. } if field == "tool_name")
        );
    }

    #[test]
    fn test_empty_purpose() {
        let mut input = minimal_tool_input();
        input.purpose = "".to_string();
        let err = validate_tool_input(&input).unwrap_err();
        assert!(
            matches!(err, AppError::ValidationError { ref field, .. } if field == "purpose")
        );
    }

    #[test]
    fn test_empty_operator() {
        let mut input = minimal_tool_input();
        input.operator = "".to_string();
        let err = validate_tool_input(&input).unwrap_err();
        assert!(
            matches!(err, AppError::ValidationError { ref field, .. } if field == "operator")
        );
    }
}
