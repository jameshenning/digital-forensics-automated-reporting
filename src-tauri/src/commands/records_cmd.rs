/// Forensic record Tauri commands — Phase 3a.
///
/// MUST-DO 3 (SEC-1): every command starts with `require_session()` as its
/// first statement.  This is non-negotiable — see `commands/mod.rs`.
///
/// Covers five record tables:
///   - `evidence`          — add, get, list for case, delete
///   - `chain_of_custody`  — add, list for evidence, list for case, update, delete
///   - `hash_verification` — add, list for evidence, list for case (no delete)
///   - `tool_usage`        — add, list for case, list for evidence
///   - `analysis_notes`    — add, list for case, list for evidence
///
/// Audit log actions emitted on mutations:
///   EVIDENCE_ADDED, EVIDENCE_DELETED,
///   CUSTODY_ADDED, CUSTODY_UPDATED, CUSTODY_DELETED,
///   HASH_ADDED, TOOL_LOGGED, ANALYSIS_ADDED
use std::sync::Arc;

use tauri::State;
use tracing::info;

use crate::{
    audit,
    auth::session::require_session,
    db::{
        analysis::{AnalysisInput, AnalysisNote},
        custody::{CustodyEvent, CustodyInput},
        evidence::{Evidence, EvidenceInput},
        hashes::{HashInput, HashRecord},
        tools::{ToolInput, ToolUsage},
    },
    error::AppError,
    state::AppState,
};

// ─── Audit action constants ───────────────────────────────────────────────────

const EVIDENCE_ADDED: &str = "EVIDENCE_ADDED";
const EVIDENCE_DELETED: &str = "EVIDENCE_DELETED";
const CUSTODY_ADDED: &str = "CUSTODY_ADDED";
const CUSTODY_UPDATED: &str = "CUSTODY_UPDATED";
const CUSTODY_DELETED: &str = "CUSTODY_DELETED";
const HASH_ADDED: &str = "HASH_ADDED";
const TOOL_LOGGED: &str = "TOOL_LOGGED";
const ANALYSIS_ADDED: &str = "ANALYSIS_ADDED";

// ─── Evidence commands ────────────────────────────────────────────────────────

/// Add a new evidence item to a case.
///
/// Validates evidence_id format, collection_datetime not in future,
/// and case_id existence.
/// Logs `EVIDENCE_ADDED` to the case audit trail.
#[tauri::command(rename_all = "snake_case")]
pub async fn evidence_add(
    token: String,
    case_id: String,
    input: EvidenceInput,
    state: State<'_, Arc<AppState>>,
) -> Result<Evidence, AppError> {
    // MUST-DO 3 — session guard first
    let session = require_session(&state, &token)?;

    let ev = crate::db::evidence::add_evidence(&state.db.forensics, &case_id, &input).await?;

    info!(
        username = %session.username,
        case_id = %case_id,
        evidence_id = %ev.evidence_id,
        "evidence added"
    );
    audit::log_case(
        &case_id,
        &session.username,
        EVIDENCE_ADDED,
        &format!(
            "evidence_id={:?} description={:?} collected_by={:?}",
            ev.evidence_id, ev.description, ev.collected_by,
        ),
    );

    Ok(ev)
}

/// Fetch a single evidence item by evidence_id.
#[tauri::command(rename_all = "snake_case")]
pub async fn evidence_get(
    token: String,
    evidence_id: String,
    state: State<'_, Arc<AppState>>,
) -> Result<Evidence, AppError> {
    // MUST-DO 3 — session guard first
    let _session = require_session(&state, &token)?;

    crate::db::evidence::get_evidence(&state.db.forensics, &evidence_id).await
}

/// List all evidence items for a case.
#[tauri::command(rename_all = "snake_case")]
pub async fn evidence_list_for_case(
    token: String,
    case_id: String,
    state: State<'_, Arc<AppState>>,
) -> Result<Vec<Evidence>, AppError> {
    // MUST-DO 3 — session guard first
    let _session = require_session(&state, &token)?;

    crate::db::evidence::list_for_case(&state.db.forensics, &case_id).await
}

/// Delete an evidence item.
///
/// Succeeds only if no custody events, hash records, files, or analyses exist
/// for this evidence (ON DELETE RESTRICT). Returns EvidenceHasDependents
/// if blocked.
/// Logs `EVIDENCE_DELETED` to the case audit trail (fetches case_id first).
#[tauri::command(rename_all = "snake_case")]
pub async fn evidence_delete(
    token: String,
    evidence_id: String,
    state: State<'_, Arc<AppState>>,
) -> Result<(), AppError> {
    // MUST-DO 3 — session guard first
    let session = require_session(&state, &token)?;

    // Fetch case_id for audit log before deleting
    let ev = crate::db::evidence::get_evidence(&state.db.forensics, &evidence_id).await?;
    let case_id = ev.case_id.clone();

    crate::db::evidence::delete_evidence(&state.db.forensics, &evidence_id).await?;

    info!(
        username = %session.username,
        case_id = %case_id,
        evidence_id = %evidence_id,
        "evidence deleted"
    );
    audit::log_case(
        &case_id,
        &session.username,
        EVIDENCE_DELETED,
        &format!("evidence_id={evidence_id:?}"),
    );

    Ok(())
}

// ─── Custody commands ─────────────────────────────────────────────────────────

/// Add a new custody event to an evidence item.
///
/// Validates `action` against the allowlist.
/// Sequence number is auto-assigned (per-evidence, starts at 1).
/// Logs `CUSTODY_ADDED` to the case audit trail.
#[tauri::command(rename_all = "snake_case")]
pub async fn custody_add(
    token: String,
    evidence_id: String,
    input: CustodyInput,
    state: State<'_, Arc<AppState>>,
) -> Result<CustodyEvent, AppError> {
    // MUST-DO 3 — session guard first
    let session = require_session(&state, &token)?;

    let ev = crate::db::custody::add_custody(&state.db.forensics, &evidence_id, &input).await?;

    // Get case_id for audit log
    let case_ev = crate::db::evidence::get_evidence(&state.db.forensics, &evidence_id).await;
    let case_id = case_ev.map(|e| e.case_id).unwrap_or_default();

    info!(
        username = %session.username,
        evidence_id = %evidence_id,
        custody_id = %ev.custody_id,
        "custody event added"
    );
    audit::log_case(
        &case_id,
        &session.username,
        CUSTODY_ADDED,
        &format!(
            "custody_id={} evidence_id={:?} action={:?} seq={}",
            ev.custody_id, evidence_id, ev.action, ev.custody_sequence,
        ),
    );

    Ok(ev)
}

/// List custody events for a specific evidence item (ordered by sequence).
#[tauri::command(rename_all = "snake_case")]
pub async fn custody_list_for_evidence(
    token: String,
    evidence_id: String,
    state: State<'_, Arc<AppState>>,
) -> Result<Vec<CustodyEvent>, AppError> {
    // MUST-DO 3 — session guard first
    let _session = require_session(&state, &token)?;

    crate::db::custody::list_for_evidence(&state.db.forensics, &evidence_id).await
}

/// List all custody events for a case (across all evidence items).
#[tauri::command(rename_all = "snake_case")]
pub async fn custody_list_for_case(
    token: String,
    case_id: String,
    state: State<'_, Arc<AppState>>,
) -> Result<Vec<CustodyEvent>, AppError> {
    // MUST-DO 3 — session guard first
    let _session = require_session(&state, &token)?;

    crate::db::custody::list_for_case(&state.db.forensics, &case_id).await
}

/// Update a custody event's mutable fields.
///
/// Does NOT change custody_sequence or evidence_id.
/// Logs `CUSTODY_UPDATED` to the audit trail.
#[tauri::command(rename_all = "snake_case")]
pub async fn custody_update(
    token: String,
    custody_id: i64,
    input: CustodyInput,
    state: State<'_, Arc<AppState>>,
) -> Result<CustodyEvent, AppError> {
    // MUST-DO 3 — session guard first
    let session = require_session(&state, &token)?;

    // Fetch evidence_id before update for audit log case resolution
    let existing = crate::db::custody::get_custody(&state.db.forensics, custody_id).await?;
    let evidence_id = existing.evidence_id.clone();

    let updated =
        crate::db::custody::update_custody(&state.db.forensics, custody_id, &input).await?;

    let case_ev = crate::db::evidence::get_evidence(&state.db.forensics, &evidence_id).await;
    let case_id = case_ev.map(|e| e.case_id).unwrap_or_default();

    info!(
        username = %session.username,
        custody_id = %custody_id,
        "custody event updated"
    );
    audit::log_case(
        &case_id,
        &session.username,
        CUSTODY_UPDATED,
        &format!(
            "custody_id={custody_id} evidence_id={evidence_id:?} action={:?}",
            updated.action,
        ),
    );

    Ok(updated)
}

/// Delete a custody event by custody_id.
///
/// Logs `CUSTODY_DELETED` to the audit trail.
#[tauri::command(rename_all = "snake_case")]
pub async fn custody_delete(
    token: String,
    custody_id: i64,
    state: State<'_, Arc<AppState>>,
) -> Result<(), AppError> {
    // MUST-DO 3 — session guard first
    let session = require_session(&state, &token)?;

    // Fetch for audit log before delete
    let existing = crate::db::custody::get_custody(&state.db.forensics, custody_id).await?;
    let evidence_id = existing.evidence_id.clone();
    let case_ev = crate::db::evidence::get_evidence(&state.db.forensics, &evidence_id).await;
    let case_id = case_ev.map(|e| e.case_id).unwrap_or_default();

    crate::db::custody::delete_custody(&state.db.forensics, custody_id).await?;

    info!(
        username = %session.username,
        custody_id = %custody_id,
        "custody event deleted"
    );
    audit::log_case(
        &case_id,
        &session.username,
        CUSTODY_DELETED,
        &format!("custody_id={custody_id} evidence_id={evidence_id:?}"),
    );

    Ok(())
}

// ─── Hash commands ────────────────────────────────────────────────────────────

/// Record a new hash verification for an evidence item.
///
/// No delete — hash records are append-only evidentiary data.
/// `hash_value` is lowercased server-side.
/// Logs `HASH_ADDED` to the case audit trail.
#[tauri::command(rename_all = "snake_case")]
pub async fn hash_add(
    token: String,
    evidence_id: String,
    input: HashInput,
    state: State<'_, Arc<AppState>>,
) -> Result<HashRecord, AppError> {
    // MUST-DO 3 — session guard first
    let session = require_session(&state, &token)?;

    let record = crate::db::hashes::add_hash(&state.db.forensics, &evidence_id, &input).await?;

    let case_ev = crate::db::evidence::get_evidence(&state.db.forensics, &evidence_id).await;
    let case_id = case_ev.map(|e| e.case_id).unwrap_or_default();

    info!(
        username = %session.username,
        evidence_id = %evidence_id,
        hash_id = %record.hash_id,
        algorithm = %record.algorithm,
        "hash verification recorded"
    );
    audit::log_case(
        &case_id,
        &session.username,
        HASH_ADDED,
        &format!(
            "hash_id={} evidence_id={:?} algorithm={:?}",
            record.hash_id, evidence_id, record.algorithm,
        ),
    );

    Ok(record)
}

/// List hash records for a specific evidence item.
#[tauri::command(rename_all = "snake_case")]
pub async fn hash_list_for_evidence(
    token: String,
    evidence_id: String,
    state: State<'_, Arc<AppState>>,
) -> Result<Vec<HashRecord>, AppError> {
    // MUST-DO 3 — session guard first
    let _session = require_session(&state, &token)?;

    crate::db::hashes::list_for_evidence(&state.db.forensics, &evidence_id).await
}

/// List all hash records for a case.
#[tauri::command(rename_all = "snake_case")]
pub async fn hash_list_for_case(
    token: String,
    case_id: String,
    state: State<'_, Arc<AppState>>,
) -> Result<Vec<HashRecord>, AppError> {
    // MUST-DO 3 — session guard first
    let _session = require_session(&state, &token)?;

    crate::db::hashes::list_for_case(&state.db.forensics, &case_id).await
}

// ─── Tool commands ────────────────────────────────────────────────────────────

/// Record a tool usage event for a case (optionally linked to an evidence item).
///
/// `execution_datetime` defaults to now() when absent.
/// Logs `TOOL_LOGGED` to the case audit trail.
#[tauri::command(rename_all = "snake_case")]
pub async fn tool_add(
    token: String,
    case_id: String,
    input: ToolInput,
    state: State<'_, Arc<AppState>>,
) -> Result<ToolUsage, AppError> {
    // MUST-DO 3 — session guard first
    let session = require_session(&state, &token)?;

    let record = crate::db::tools::add_tool(&state.db.forensics, &case_id, &input).await?;

    info!(
        username = %session.username,
        case_id = %case_id,
        tool_id = %record.tool_id,
        tool_name = %record.tool_name,
        "tool usage logged"
    );
    audit::log_case(
        &case_id,
        &session.username,
        TOOL_LOGGED,
        &format!(
            "tool_id={} tool={:?} evidence_id={:?}",
            record.tool_id, record.tool_name, record.evidence_id,
        ),
    );

    Ok(record)
}

/// List all tool usage records for a case, ordered by execution_datetime DESC.
#[tauri::command(rename_all = "snake_case")]
pub async fn tool_list_for_case(
    token: String,
    case_id: String,
    state: State<'_, Arc<AppState>>,
) -> Result<Vec<ToolUsage>, AppError> {
    // MUST-DO 3 — session guard first
    let _session = require_session(&state, &token)?;

    crate::db::tools::list_for_case(&state.db.forensics, &case_id).await
}

/// List tool usage records for a specific evidence item.
#[tauri::command(rename_all = "snake_case")]
pub async fn tool_list_for_evidence(
    token: String,
    evidence_id: String,
    state: State<'_, Arc<AppState>>,
) -> Result<Vec<ToolUsage>, AppError> {
    // MUST-DO 3 — session guard first
    let _session = require_session(&state, &token)?;

    crate::db::tools::list_for_evidence(&state.db.forensics, &evidence_id).await
}

// ─── Analysis commands ────────────────────────────────────────────────────────

/// Add a new analysis note to a case.
///
/// `confidence_level` defaults to "Medium".
/// Logs `ANALYSIS_ADDED` to the case audit trail.
#[tauri::command(rename_all = "snake_case")]
pub async fn analysis_add(
    token: String,
    case_id: String,
    input: AnalysisInput,
    state: State<'_, Arc<AppState>>,
) -> Result<AnalysisNote, AppError> {
    // MUST-DO 3 — session guard first
    let session = require_session(&state, &token)?;

    let note = crate::db::analysis::add_analysis(&state.db.forensics, &case_id, &input).await?;

    info!(
        username = %session.username,
        case_id = %case_id,
        note_id = %note.note_id,
        category = %note.category,
        "analysis note added"
    );
    audit::log_case(
        &case_id,
        &session.username,
        ANALYSIS_ADDED,
        &format!(
            "note_id={} category={:?} confidence={:?} evidence_id={:?}",
            note.note_id, note.category, note.confidence_level, note.evidence_id,
        ),
    );

    Ok(note)
}

/// List all analysis notes for a case, ordered by created_at DESC.
#[tauri::command(rename_all = "snake_case")]
pub async fn analysis_list_for_case(
    token: String,
    case_id: String,
    state: State<'_, Arc<AppState>>,
) -> Result<Vec<AnalysisNote>, AppError> {
    // MUST-DO 3 — session guard first
    let _session = require_session(&state, &token)?;

    crate::db::analysis::list_for_case(&state.db.forensics, &case_id).await
}

/// List analysis notes linked to a specific evidence item.
#[tauri::command(rename_all = "snake_case")]
pub async fn analysis_list_for_evidence(
    token: String,
    evidence_id: String,
    state: State<'_, Arc<AppState>>,
) -> Result<Vec<AnalysisNote>, AppError> {
    // MUST-DO 3 — session guard first
    let _session = require_session(&state, &token)?;

    crate::db::analysis::list_for_evidence(&state.db.forensics, &evidence_id).await
}
