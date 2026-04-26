/// Case share Tauri commands — records when forensic data leaves the app.
///
/// MUST-DO 3 (SEC-1): every command starts with `require_session()` as its
/// first statement.  See `commands/mod.rs`.
///
/// Covers:
///   - `share_record`    — log an email/print share event
///   - `shares_list_for_case` — list share history for a case

use std::sync::Arc;

use serde::{Deserialize, Serialize};
use tauri::State;

use crate::{
    audit,
    auth::session::require_session,
    db::{
        audit_entries::{self, AuditEntryInput},
        shares::{CaseShare, ShareInput},
    },
    error::AppError,
    state::AppState,
};

// ─── Public data types ────────────────────────────────────────────────────────

/// Input payload for `share_record`.
///
/// `file_hash` is required even for print actions (can be the hash of the
/// rendered markdown or an empty-file sentinel hash).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShareRecordInput {
    pub case_id: String,
    pub record_type: String,
    pub record_id: String,
    pub record_summary: Option<String>,
    pub action: String,
    pub recipient: Option<String>,
    pub file_path: Option<String>,
    pub file_hash: String,
    pub narrative: String,
}

// ─── Commands ─────────────────────────────────────────────────────────────────

/// Log that a record was shared (emailed or printed).
///
/// Writes:
///   1. A row to `case_shares` (the share audit trail)
///   2. A line to the case's flat-file audit log
///   3. An entry to the hash-chained audit log
#[tauri::command(rename_all = "snake_case")]
pub async fn share_record(
    token: String,
    input: ShareRecordInput,
    state: State<'_, Arc<AppState>>,
) -> Result<CaseShare, AppError> {
    let session = require_session(&state, &token)?;

    let share_input = ShareInput {
        case_id: input.case_id.clone(),
        record_type: input.record_type.clone(),
        record_id: input.record_id.clone(),
        record_summary: input.record_summary.clone(),
        action: input.action.clone(),
        recipient: input.recipient.clone(),
        file_path: input.file_path.clone(),
        file_hash: input.file_hash.clone(),
        narrative: input.narrative.clone(),
        shared_by: session.username.clone(),
    };

    let share = crate::db::shares::add_share(&state.db.forensics, &share_input).await?;

    // Flat-file audit trail (legacy, human-readable)
    let detail = format!(
        "record_type={} record_id={} action={} recipient={:?} narrative={:?}",
        input.record_type, input.record_id, input.action, input.recipient, input.narrative
    );
    audit::log_case(&input.case_id, &session.username, audit::RECORD_SHARED, &detail);

    // Hash-chained audit log (tamper-evident)
    let _ = audit_entries::add_entry(
        &state.db.forensics,
        &AuditEntryInput {
            case_id: Some(input.case_id),
            actor: format!("user:{}", session.username),
            action: audit::RECORD_SHARED.into(),
            details: Some(detail),
        },
    )
    .await;

    Ok(share)
}

/// List share records for a case.
#[tauri::command(rename_all = "snake_case")]
pub async fn shares_list_for_case(
    token: String,
    case_id: String,
    state: State<'_, Arc<AppState>>,
) -> Result<Vec<CaseShare>, AppError> {
    let _session = require_session(&state, &token)?;
    crate::db::shares::list_for_case(&state.db.forensics, &case_id).await
}
