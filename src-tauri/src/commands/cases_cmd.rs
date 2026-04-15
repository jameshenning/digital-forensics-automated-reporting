/// Case CRUD Tauri commands — Phase 2.
///
/// MUST-DO 3 (SEC-1): every command starts with `require_session()` as its
/// first statement.  This is non-negotiable — see `commands/mod.rs` for the
/// full invariant list.
///
/// Commands:
///   - `cases_list`   — paginated summary list
///   - `case_get`     — full detail + tags
///   - `case_create`  — create with tag set; strict no-overwrite
///   - `case_update`  — update + replace tag set; transactional
///   - `case_delete`  — delete; respects FK RESTRICT
use std::sync::Arc;

use tauri::State;
use tracing::info;

use crate::{
    audit,
    auth::session::require_session,
    db::cases::{CaseDetail, CaseInput, CaseSummary},
    error::AppError,
    state::AppState,
};

const DEFAULT_LIMIT: i64 = 100;
const DEFAULT_OFFSET: i64 = 0;

/// Return a paginated list of case summaries.
///
/// `limit` defaults to 100, `offset` defaults to 0.
/// Ordered by `created_at DESC`.
#[tauri::command(rename_all = "snake_case")]
pub async fn cases_list(
    token: String,
    limit: Option<i64>,
    offset: Option<i64>,
    state: State<'_, Arc<AppState>>,
) -> Result<Vec<CaseSummary>, AppError> {
    info!(command = "cases_list", token_prefix = %token.chars().take(8).collect::<String>(), "cases_list entered");
    // MUST-DO 3 — session guard first
    let session = require_session(&state, &token);
    info!(command = "cases_list", session_ok = session.is_ok(), "cases_list after require_session");
    let _session = session?;

    let limit = limit.unwrap_or(DEFAULT_LIMIT);
    let offset = offset.unwrap_or(DEFAULT_OFFSET);

    let result = crate::db::cases::list_cases(&state.db.forensics, limit, offset).await;
    match &result {
        Ok(rows) => info!(command = "cases_list", count = rows.len(), "cases_list success"),
        Err(e) => info!(command = "cases_list", error = %e, "cases_list db error"),
    }
    result
}

/// Return a single case with its full metadata and sorted tag list.
#[tauri::command(rename_all = "snake_case")]
pub async fn case_get(
    token: String,
    case_id: String,
    state: State<'_, Arc<AppState>>,
) -> Result<CaseDetail, AppError> {
    info!(command = "case_get", case_id = %case_id, token_prefix = %token.chars().take(8).collect::<String>(), "case_get entered");
    // MUST-DO 3 — session guard first
    let _session = require_session(&state, &token)?;

    crate::db::cases::get_case(&state.db.forensics, &case_id).await
}

/// Create a new case.
///
/// `input.case_id` must be unique — returns `AppError::CaseAlreadyExists` on
/// collision (deliberate v2 strict-insert policy).
///
/// Logs `CASE_CREATED` to the case audit trail.
#[tauri::command(rename_all = "snake_case")]
pub async fn case_create(
    token: String,
    input: CaseInput,
    state: State<'_, Arc<AppState>>,
) -> Result<CaseDetail, AppError> {
    // MUST-DO 3 — session guard first
    let session = require_session(&state, &token)?;

    let detail = crate::db::cases::create_case(&state.db.forensics, &input).await?;

    info!(
        username = %session.username,
        case_id = %detail.case.case_id,
        "case created"
    );
    audit::log_case(
        &detail.case.case_id,
        &session.username,
        audit::CASE_CREATED,
        &format!(
            "Name={:?} Investigator={:?} Priority={}",
            detail.case.case_name, detail.case.investigator, detail.case.priority,
        ),
    );

    Ok(detail)
}

/// Update an existing case's metadata and replace its tag set atomically.
///
/// Returns `AppError::CaseNotFound` if `case_id` doesn't exist.
/// Logs `CASE_UPDATED` to the case audit trail.
#[tauri::command(rename_all = "snake_case")]
pub async fn case_update(
    token: String,
    case_id: String,
    input: CaseInput,
    state: State<'_, Arc<AppState>>,
) -> Result<CaseDetail, AppError> {
    // MUST-DO 3 — session guard first
    let session = require_session(&state, &token)?;

    let detail = crate::db::cases::update_case(&state.db.forensics, &case_id, &input).await?;

    info!(
        username = %session.username,
        case_id = %case_id,
        "case updated"
    );
    audit::log_case(
        &case_id,
        &session.username,
        audit::CASE_UPDATED,
        &format!(
            "Name={:?} Status={} Priority={}",
            detail.case.case_name, detail.case.status, detail.case.priority,
        ),
    );

    Ok(detail)
}

/// Delete a case by ID.
///
/// Respects the schema's `ON DELETE RESTRICT` FK on `evidence.case_id` —
/// returns `AppError::CaseHasEvidence` if any evidence rows exist.
/// Evidence is NOT deleted — that would destroy forensic records.
///
/// Logs `CASE_DELETED` to the auth audit trail (case audit file no longer
/// exists after deletion).
#[tauri::command(rename_all = "snake_case")]
pub async fn case_delete(
    token: String,
    case_id: String,
    state: State<'_, Arc<AppState>>,
) -> Result<(), AppError> {
    // MUST-DO 3 — session guard first
    let session = require_session(&state, &token)?;

    crate::db::cases::delete_case(&state.db.forensics, &case_id).await?;

    info!(
        username = %session.username,
        case_id = %case_id,
        "case deleted"
    );
    // Log to auth audit since the case audit file is gone.
    audit::log_auth(
        &session.username,
        audit::CASE_DELETED,
        &format!("case_id={case_id}"),
    );

    Ok(())
}
