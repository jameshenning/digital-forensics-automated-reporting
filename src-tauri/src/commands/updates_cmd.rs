/// Update-check Tauri command — Phase 6.
///
/// `settings_check_for_updates` is a user-initiated check (never automatic on
/// launch — a forensic tool must not generate unexpected outbound traffic, per
/// spec §11 OQ-SEC8-2).
///
/// For v2.0.0, the updater plugin was removed entirely per SEC-9 — shipping a
/// placeholder pubkey and unreachable endpoint was worse than not having the
/// plugin at all. This command always returns `NotConfigured` and directs the
/// user to the GitHub Releases page for manual downloads.
///
/// When auto-update hosting is configured (post-v2.0.0), the plugin will be
/// reintroduced and this command will perform a real check. Frontend consumers
/// (settings/security.tsx) do not need to change — the UI already handles all
/// 4 UpdateStatus variants gracefully.
///
/// Security:
///   - Session-gated: `require_session()` is the first call.
///   - No token, secret, or credential is logged.
///   - Returns a fixed user-facing string. No error leak.

use std::sync::Arc;

use serde::Serialize;
use tauri::State;
use tracing::info;

use crate::auth::session::require_session;
use crate::error::AppError;
use crate::state::AppState;

// ─── Result types ─────────────────────────────────────────────────────────────

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct UpdateCheckResult {
    pub status: UpdateStatus,
    pub message: String,
    pub available_version: Option<String>,
}

#[derive(Debug, Serialize)]
pub enum UpdateStatus {
    #[allow(dead_code)]
    UpToDate,
    #[allow(dead_code)]
    UpdateAvailable,
    /// Endpoint not configured — the only state v2.0.0 returns.
    NotConfigured,
    /// Reserved for post-v2.0.0 when a real endpoint is configured.
    #[allow(dead_code)]
    NetworkError,
}

// ─── Command ──────────────────────────────────────────────────────────────────

/// Check for available updates. For v2.0.0, always returns `NotConfigured`.
///
/// Requires a valid session token. The frontend surfaces a friendly message
/// pointing at GitHub Releases for manual downloads.
#[tauri::command]
pub async fn settings_check_for_updates(
    token: String,
    state: State<'_, Arc<AppState>>,
) -> Result<UpdateCheckResult, AppError> {
    let session = require_session(&state, &token)?;

    // AUDIT-LOG-SAFE: only the username is logged, never the token value.
    info!(
        username = %session.username,
        command = "settings_check_for_updates",
        "update check invoked (v2.0.0 always returns NotConfigured)"
    );

    Ok(UpdateCheckResult {
        status: UpdateStatus::NotConfigured,
        message: "Automatic updates are not configured for v2.0.0. Download newer versions manually from the GitHub Releases page.".into(),
        available_version: None,
    })
}
