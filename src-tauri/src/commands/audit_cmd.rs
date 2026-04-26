/// Audit log Tauri commands — migration 0010 hash-chained audit.
///
/// Commands:
///   - `audit_list_for_case`  — read the hash chain for a case
///   - `audit_export_case`    — export signed audit bundle as JSON
///   - `audit_verify_chain`   — verify integrity of a case's chain

use std::sync::Arc;

use serde::{Deserialize, Serialize};
use tauri::State;

use crate::{
    auth::session::require_session,
    db::audit_entries::{self, AuditEntry},
    error::AppError,
    state::AppState,
};

// ─── Public data types ────────────────────────────────────────────────────────

/// Export bundle for a case's audit trail.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditExport {
    pub case_id: String,
    pub exported_at: String,
    pub entry_count: usize,
    pub entries: Vec<AuditEntry>,
    /// SHA-256 of the canonical JSON of entries (sorted by entry_id).
    pub bundle_hash: String,
}

// ─── Commands ─────────────────────────────────────────────────────────────────

/// List audit entries for a case, ordered chronologically.
#[tauri::command(rename_all = "snake_case")]
pub async fn audit_list_for_case(
    token: String,
    case_id: String,
    state: State<'_, Arc<AppState>>,
) -> Result<Vec<AuditEntry>, AppError> {
    let _session = require_session(&state, &token)?;
    audit_entries::list_for_case(&state.db.forensics, &case_id).await
}

/// Verify the hash chain for a case.
/// Returns `true` if the chain is intact, `false` if tampered or empty.
#[tauri::command(rename_all = "snake_case")]
pub async fn audit_verify_chain(
    token: String,
    case_id: String,
    state: State<'_, Arc<AppState>>,
) -> Result<bool, AppError> {
    let _session = require_session(&state, &token)?;
    let entries = audit_entries::list_for_case(&state.db.forensics, &case_id).await?;
    if entries.is_empty() {
        return Ok(true); // empty chain is vacuously valid
    }
    match audit_entries::verify_chain(&entries) {
        Ok(()) => Ok(true),
        Err(_) => Ok(false),
    }
}

/// Export a case's audit chain as a structured bundle.
#[tauri::command(rename_all = "snake_case")]
pub async fn audit_export_case(
    token: String,
    case_id: String,
    state: State<'_, Arc<AppState>>,
) -> Result<AuditExport, AppError> {
    let _session = require_session(&state, &token)?;
    let entries = audit_entries::list_for_case(&state.db.forensics, &case_id).await?;
    let exported_at = chrono::Utc::now().to_rfc3339();

    // Compute bundle hash: SHA-256 of the canonical JSON array of entries.
    let bundle_hash = {
        use sha2::{Sha256, Digest};
        let canonical = serde_json::to_string(&entries).unwrap_or_else(|_| "[]".into());
        let hash = Sha256::digest(canonical.as_bytes());
        data_encoding::HEXLOWER.encode(&hash)
    };

    Ok(AuditExport {
        case_id,
        exported_at,
        entry_count: entries.len(),
        entries,
        bundle_hash,
    })
}
