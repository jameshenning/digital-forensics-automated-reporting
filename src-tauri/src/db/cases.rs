/// Case database queries — Phase 2.
///
/// All queries use dynamic `sqlx::query(...).bind(...)` + `query_as::<_, T>`
/// rather than the `query!` / `query_as!` macros because the `.sqlx/` offline
/// cache is not yet set up (Phase 6 task).
///
/// Public surface:
///   - `list_cases`  — paginated summary rows (with evidence count JOIN)
///   - `get_case`    — full case + sorted tag list
///   - `create_case` — strict INSERT (no silent overwrite); transactional
///   - `update_case` — UPDATE + tag replacement in one transaction
///   - `delete_case` — respects FK RESTRICT; maps to `CaseHasEvidence` on failure
///
/// Validation lives here (case_id format, status/priority allowlists, tag
/// normalization) so the command layer only does session checks.
use chrono::NaiveDate;
use serde::{Deserialize, Serialize};
use sqlx::{sqlite::Sqlite, SqlitePool, Transaction};

use crate::error::AppError;

// ─── Validation constants ────────────────────────────────────────────────────

const VALID_STATUSES: &[&str] = &["Active", "Closed", "Pending", "Archived"];
const VALID_PRIORITIES: &[&str] = &["Low", "Medium", "High", "Critical"];
const CASE_ID_MAX_LEN: usize = 64;

// ─── Public data types ────────────────────────────────────────────────────────

/// Full case row, maps 1:1 to the `cases` table.
///
/// NOTE: date/datetime columns are read as `String` (not chrono types) because
/// v1 stored `start_date` as datetime strings like `"2026-04-11 00:00:00"` even
/// though the column type is DATE, and `created_at` / `updated_at` as
/// space-separated (not ISO-T) datetimes. sqlx's chrono integration can't
/// parse those into `NaiveDate`/`NaiveDateTime` without brittle format guesses.
/// The frontend already treats these as strings (see `src/lib/bindings.ts`
/// `Case` type) so passing them through verbatim is simpler and compat-safe.
#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct Case {
    pub case_id: String,
    pub case_name: String,
    pub description: Option<String>,
    pub investigator: String,
    pub agency: Option<String>,
    pub start_date: String,
    pub end_date: Option<String>,
    pub status: String,
    pub priority: String,
    pub classification: Option<String>,
    pub evidence_drive_path: Option<String>,
    pub created_at: String,
    pub updated_at: String,
}

/// Lighter summary row for the case list view; includes aggregated evidence count.
/// Same date-as-string rationale as `Case` above.
#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct CaseSummary {
    pub case_id: String,
    pub case_name: String,
    pub investigator: String,
    pub start_date: String,
    pub status: String,
    pub priority: String,
    pub evidence_count: i64,
    pub created_at: String,
}

/// Full case detail returned by `get_case` and mutation commands.
///
/// Serializes to `{ "case": { ... }, "tags": [...] }` — the frontend
/// `CaseDetail` TS type (src/lib/bindings.ts) expects a nested `case`
/// field. Do NOT re-add `#[serde(flatten)]` — it was the cause of the
/// v2 "click case → blank / Failed to load case" bug.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CaseDetail {
    pub case: Case,
    pub tags: Vec<String>,
}

/// Writable fields for create/update.
///
/// Tags are normalized (trim, lowercase, dedup, drop empty) by
/// `validate_and_normalize` before the DB is touched.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CaseInput {
    /// Required for create; for update it is overridden by the URL parameter.
    pub case_id: String,
    pub case_name: String,
    pub description: Option<String>,
    pub investigator: String,
    pub agency: Option<String>,
    pub start_date: NaiveDate,
    pub end_date: Option<NaiveDate>,
    /// `None` → default `"Active"`.
    pub status: Option<String>,
    /// `None` → default `"Medium"`.
    pub priority: Option<String>,
    pub classification: Option<String>,
    pub evidence_drive_path: Option<String>,
    pub tags: Vec<String>,
}

// ─── Validation helpers ───────────────────────────────────────────────────────

/// Validate the case_id format: non-empty, max 64 chars, `[A-Za-z0-9._-]` only.
fn validate_case_id(case_id: &str) -> Result<(), AppError> {
    if case_id.is_empty() {
        return Err(AppError::ValidationError {
            field: "case_id".into(),
            message: "case_id must not be empty".into(),
        });
    }
    if case_id.len() > CASE_ID_MAX_LEN {
        return Err(AppError::ValidationError {
            field: "case_id".into(),
            message: format!("case_id must not exceed {CASE_ID_MAX_LEN} characters"),
        });
    }
    if !case_id
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '_' || c == '-')
    {
        return Err(AppError::ValidationError {
            field: "case_id".into(),
            message: "case_id may only contain A-Z, a-z, 0-9, '.', '_', '-'".into(),
        });
    }
    Ok(())
}

/// Validate and resolve the status field (default: `"Active"`).
fn resolve_status(status: Option<&str>) -> Result<String, AppError> {
    let s = status.unwrap_or("Active");
    if !VALID_STATUSES.contains(&s) {
        return Err(AppError::ValidationError {
            field: "status".into(),
            message: format!(
                "status must be one of: {}",
                VALID_STATUSES.join(", ")
            ),
        });
    }
    Ok(s.to_string())
}

/// Validate and resolve the priority field (default: `"Medium"`).
fn resolve_priority(priority: Option<&str>) -> Result<String, AppError> {
    let p = priority.unwrap_or("Medium");
    if !VALID_PRIORITIES.contains(&p) {
        return Err(AppError::ValidationError {
            field: "priority".into(),
            message: format!(
                "priority must be one of: {}",
                VALID_PRIORITIES.join(", ")
            ),
        });
    }
    Ok(p.to_string())
}

/// Normalize a raw tag list: trim, lowercase, dedup, drop empty.
fn normalize_tags(tags: &[String]) -> Vec<String> {
    let mut seen = std::collections::HashSet::new();
    let mut out = Vec::new();
    for t in tags {
        let normalized = t.trim().to_lowercase();
        if !normalized.is_empty() && seen.insert(normalized.clone()) {
            out.push(normalized);
        }
    }
    out.sort();
    out
}

/// Full validation pass on a `CaseInput`.
/// Returns the resolved (non-Option) status + priority, and the normalized tag list.
fn validate_input(input: &CaseInput) -> Result<(String, String, Vec<String>), AppError> {
    validate_case_id(&input.case_id)?;
    let status = resolve_status(input.status.as_deref())?;
    let priority = resolve_priority(input.priority.as_deref())?;
    let tags = normalize_tags(&input.tags);
    Ok((status, priority, tags))
}

// ─── FK-constraint error detection ───────────────────────────────────────────

/// Detect whether a sqlx error is a SQLite foreign-key constraint violation.
///
/// SQLite returns SQLITE_CONSTRAINT (error code 19) with a message containing
/// "FOREIGN KEY constraint failed" when ON DELETE RESTRICT fires.
/// sqlx surfaces this as `sqlx::Error::Database` wrapping the driver error.
///
/// The exact string the frontend agent needs: `"FOREIGN KEY constraint failed"`
fn is_fk_constraint_error(e: &sqlx::Error) -> bool {
    match e {
        sqlx::Error::Database(db_err) => {
            let msg = db_err.message();
            msg.contains("FOREIGN KEY constraint failed")
        }
        _ => false,
    }
}

/// Detect a UNIQUE constraint violation (used to map to `CaseAlreadyExists`).
fn is_unique_constraint_error(e: &sqlx::Error) -> bool {
    match e {
        sqlx::Error::Database(db_err) => {
            let msg = db_err.message();
            msg.contains("UNIQUE constraint failed")
        }
        _ => false,
    }
}

// ─── Tag helpers (private) ────────────────────────────────────────────────────

/// Delete all existing tag rows for a case and insert the new set.
/// Runs inside an existing transaction.
async fn replace_tags(
    tx: &mut Transaction<'_, Sqlite>,
    case_id: &str,
    tags: &[String],
) -> Result<(), AppError> {
    sqlx::query("DELETE FROM case_tags WHERE case_id = ?")
        .bind(case_id)
        .execute(&mut **tx)
        .await?;

    for tag in tags {
        sqlx::query("INSERT OR IGNORE INTO case_tags (case_id, tag) VALUES (?, ?)")
            .bind(case_id)
            .bind(tag)
            .execute(&mut **tx)
            .await?;
    }
    Ok(())
}

/// Fetch sorted tag list for a case (reads from pool, not a transaction).
async fn get_tags(pool: &SqlitePool, case_id: &str) -> Result<Vec<String>, AppError> {
    let rows: Vec<(String,)> =
        sqlx::query_as("SELECT tag FROM case_tags WHERE case_id = ? ORDER BY tag")
            .bind(case_id)
            .fetch_all(pool)
            .await?;
    Ok(rows.into_iter().map(|(t,)| t).collect())
}

// ─── Public query functions ───────────────────────────────────────────────────

/// Paginated list of case summaries with aggregated evidence count.
///
/// Default pagination: limit=100, offset=0.
/// Results ordered by `created_at DESC`.
pub async fn list_cases(
    pool: &SqlitePool,
    limit: i64,
    offset: i64,
) -> Result<Vec<CaseSummary>, AppError> {
    let rows = sqlx::query_as::<_, CaseSummary>(
        r#"
        SELECT
            c.case_id,
            c.case_name,
            c.investigator,
            c.start_date,
            c.status,
            c.priority,
            COALESCE(ec.evidence_count, 0) AS evidence_count,
            c.created_at
        FROM cases c
        LEFT JOIN (
            SELECT case_id, COUNT(*) AS evidence_count
            FROM evidence
            GROUP BY case_id
        ) ec ON c.case_id = ec.case_id
        ORDER BY c.created_at DESC
        LIMIT ? OFFSET ?
        "#,
    )
    .bind(limit)
    .bind(offset)
    .fetch_all(pool)
    .await?;

    Ok(rows)
}

/// Fetch a single case by ID plus its sorted tags.
///
/// Returns `AppError::CaseNotFound` if no row exists.
pub async fn get_case(pool: &SqlitePool, case_id: &str) -> Result<CaseDetail, AppError> {
    let case = sqlx::query_as::<_, Case>(
        r#"
        SELECT
            case_id, case_name, description, investigator, agency,
            start_date, end_date, status, priority, classification,
            evidence_drive_path, created_at, updated_at
        FROM cases
        WHERE case_id = ?
        "#,
    )
    .bind(case_id)
    .fetch_optional(pool)
    .await?
    .ok_or_else(|| AppError::CaseNotFound {
        case_id: case_id.to_string(),
    })?;

    let tags = get_tags(pool, case_id).await?;
    Ok(CaseDetail { case, tags })
}

/// Create a new case.
///
/// Uses a strict `INSERT` — duplicate `case_id` returns `AppError::CaseAlreadyExists`.
/// This is a deliberate v2 improvement over v1's `INSERT OR REPLACE` which could
/// silently overwrite existing forensic records.
///
/// Runs in a transaction: case row + tag rows are committed atomically.
pub async fn create_case(pool: &SqlitePool, input: &CaseInput) -> Result<CaseDetail, AppError> {
    let (status, priority, tags) = validate_input(input)?;

    let mut tx = pool.begin().await?;

    let result = sqlx::query(
        r#"
        INSERT INTO cases (
            case_id, case_name, description, investigator, agency,
            start_date, end_date, status, priority, classification,
            evidence_drive_path
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        "#,
    )
    .bind(&input.case_id)
    .bind(&input.case_name)
    .bind(&input.description)
    .bind(&input.investigator)
    .bind(&input.agency)
    .bind(input.start_date)
    .bind(input.end_date)
    .bind(&status)
    .bind(&priority)
    .bind(&input.classification)
    .bind(&input.evidence_drive_path)
    .execute(&mut *tx)
    .await;

    match result {
        Err(ref e) if is_unique_constraint_error(e) => {
            let _ = tx.rollback().await;
            return Err(AppError::CaseAlreadyExists {
                case_id: input.case_id.clone(),
            });
        }
        Err(e) => {
            let _ = tx.rollback().await;
            return Err(AppError::from(e));
        }
        Ok(_) => {}
    }

    replace_tags(&mut tx, &input.case_id, &tags).await?;
    tx.commit().await?;

    get_case(pool, &input.case_id).await
}

/// Update an existing case.
///
/// Returns `AppError::CaseNotFound` if the case_id doesn't exist.
/// Runs in a transaction: UPDATE + DELETE old tags + INSERT new tags, atomic.
pub async fn update_case(
    pool: &SqlitePool,
    case_id: &str,
    input: &CaseInput,
) -> Result<CaseDetail, AppError> {
    // Validate the input fields (use case_id from the path parameter, not input)
    let mut input_for_validation = input.clone();
    input_for_validation.case_id = case_id.to_string();
    let (status, priority, tags) = validate_input(&input_for_validation)?;

    let mut tx = pool.begin().await?;

    let rows_affected = sqlx::query(
        r#"
        UPDATE cases SET
            case_name = ?,
            description = ?,
            investigator = ?,
            agency = ?,
            start_date = ?,
            end_date = ?,
            status = ?,
            priority = ?,
            classification = ?,
            evidence_drive_path = ?,
            updated_at = CURRENT_TIMESTAMP
        WHERE case_id = ?
        "#,
    )
    .bind(&input.case_name)
    .bind(&input.description)
    .bind(&input.investigator)
    .bind(&input.agency)
    .bind(input.start_date)
    .bind(input.end_date)
    .bind(&status)
    .bind(&priority)
    .bind(&input.classification)
    .bind(&input.evidence_drive_path)
    .bind(case_id)
    .execute(&mut *tx)
    .await?
    .rows_affected();

    if rows_affected == 0 {
        let _ = tx.rollback().await;
        return Err(AppError::CaseNotFound {
            case_id: case_id.to_string(),
        });
    }

    replace_tags(&mut tx, case_id, &tags).await?;
    tx.commit().await?;

    get_case(pool, case_id).await
}

/// Delete a case by ID.
///
/// `case_tags` uses `ON DELETE RESTRICT` (matching the forensics schema), so we
/// explicitly delete the tags first inside a transaction before removing the case
/// row.  Tags are metadata — deleting them is safe.
///
/// The `evidence` table (and other child tables: `tool_usage`, `analysis_notes`,
/// etc.) also use `ON DELETE RESTRICT`. If any evidence rows exist, the case
/// DELETE will fail.  We catch that sqlx FK-constraint error and map it to
/// `AppError::CaseHasEvidence` so the frontend can warn the user.
/// Evidence rows are NOT deleted — that would destroy forensic records.
///
/// Returns `AppError::CaseNotFound` if the case doesn't exist (checked via
/// rowcount == 0 after the DELETE attempt).
///
/// The exact FK-constraint error string SQLite surfaces (for frontend reference):
///   `"FOREIGN KEY constraint failed"`
pub async fn delete_case(pool: &SqlitePool, case_id: &str) -> Result<(), AppError> {
    let mut tx = pool.begin().await?;

    // Delete tags first — they are metadata and safe to remove.
    // case_tags has ON DELETE RESTRICT so this must happen before the case DELETE.
    sqlx::query("DELETE FROM case_tags WHERE case_id = ?")
        .bind(case_id)
        .execute(&mut *tx)
        .await?;

    // Now delete the case row.  Any remaining FK children (evidence, tool_usage,
    // analysis_notes, entities, etc.) will cause a FOREIGN KEY constraint error.
    let result = sqlx::query("DELETE FROM cases WHERE case_id = ?")
        .bind(case_id)
        .execute(&mut *tx)
        .await;

    match result {
        Err(ref e) if is_fk_constraint_error(e) => {
            let _ = tx.rollback().await;
            return Err(AppError::CaseHasEvidence {
                case_id: case_id.to_string(),
            });
        }
        Err(e) => {
            let _ = tx.rollback().await;
            return Err(AppError::from(e));
        }
        Ok(r) if r.rows_affected() == 0 => {
            let _ = tx.rollback().await;
            return Err(AppError::CaseNotFound {
                case_id: case_id.to_string(),
            });
        }
        Ok(_) => {}
    }

    tx.commit().await?;
    Ok(())
}
