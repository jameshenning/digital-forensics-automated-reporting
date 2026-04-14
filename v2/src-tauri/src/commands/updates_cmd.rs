/// Update-check Tauri command — Phase 6.
///
/// `settings_check_for_updates` is a user-initiated check (never automatic on
/// launch — a forensic tool must not generate unexpected outbound traffic, per
/// spec §11 OQ-SEC8-2).
///
/// For v2.0.0, the updater endpoint is a placeholder host that returns a DNS
/// failure.  The command catches any error and returns `NotConfigured` with a
/// human-readable message directing the user to GitHub Releases.  This keeps
/// the frontend happy without crashing.
///
/// When a real endpoint is set up (post-v2.0.0), no code changes are needed
/// here — only the `plugins.updater.endpoints` value in `tauri.conf.json` must
/// be updated.
///
/// Security:
///   - Session-gated: `require_session()` is the first call.
///   - No token, secret, or credential is logged.
///   - Network error messages from the plugin are NOT forwarded to the frontend
///     verbatim (they may contain the placeholder hostname); we return a fixed
///     user-facing string instead.

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
    UpToDate,
    UpdateAvailable,
    /// Endpoint not configured or unreachable — not an error, just informational.
    NotConfigured,
    /// Unexpected network error (transient failure when a real endpoint exists).
    /// Reserved for post-v2.0.0 use when a real endpoint is configured and we
    /// want to distinguish transient network failures from "not yet set up".
    #[allow(dead_code)]
    NetworkError,
}

// ─── Command ──────────────────────────────────────────────────────────────────

/// Check for available updates via the Tauri updater plugin.
///
/// Requires a valid session token.  Returns `UpdateStatus::NotConfigured` for
/// v2.0.0 because the endpoint is a placeholder.  When a real endpoint is
/// configured, this command will surface real update availability.
#[tauri::command]
pub async fn settings_check_for_updates(
    token: String,
    // The AppHandle is required to call the updater plugin API.
    app: tauri::AppHandle,
    state: State<'_, Arc<AppState>>,
) -> Result<UpdateCheckResult, AppError> {
    // AUDIT-LOG-SAFE: we log only the username (not the token value).
    // The token is used only to verify the session is active; it is never
    // passed to the updater and is never included in log output.
    let session = require_session(&state, &token)?;

    info!(
        username = %session.username,
        command = "settings_check_for_updates",
        "update check initiated by user"
    );

    // Attempt the updater check.  For v2.0.0 this will fail with a DNS error
    // because the endpoint host is `updates.dfars-desktop.invalid`.  We catch
    // the error and return NotConfigured instead of propagating it, so the
    // frontend always gets a usable response.
    //
    // TODO (post-v2.0.0): when a real endpoint is configured, remove the catch-all
    // Err branch that returns NotConfigured and let NetworkError surface for
    // transient failures so the user knows to retry.
    use tauri_plugin_updater::UpdaterExt;

    match app.updater() {
        Ok(updater) => match updater.check().await {
            Ok(Some(update)) => {
                info!(
                    username = %session.username,
                    available_version = %update.version,
                    "update available"
                );
                Ok(UpdateCheckResult {
                    status: UpdateStatus::UpdateAvailable,
                    message: format!("Update available: v{}", update.version),
                    available_version: Some(update.version),
                })
            }
            Ok(None) => {
                info!(username = %session.username, "no update available");
                Ok(UpdateCheckResult {
                    status: UpdateStatus::UpToDate,
                    message: "You are on the latest version.".into(),
                    available_version: None,
                })
            }
            Err(e) => {
                // Any error (DNS failure on the placeholder host, HTTP non-200,
                // bad signature, etc.) is treated as "not configured" for v2.0.0.
                // We log the error at debug level so it appears in the log file
                // for diagnostics but is not surfaced to the user.
                //
                // AUDIT-LOG-SAFE: the error message may contain the placeholder
                // hostname ("updates.dfars-desktop.invalid") which is not
                // sensitive — it is already present in tauri.conf.json.
                tracing::debug!(
                    username = %session.username,
                    error = %e,
                    "updater check failed (expected for placeholder endpoint)"
                );
                Ok(UpdateCheckResult {
                    status: UpdateStatus::NotConfigured,
                    message: "Update server not configured. Download updates manually from GitHub Releases.".into(),
                    available_version: None,
                })
            }
        },
        Err(e) => {
            // Updater plugin failed to initialize (e.g., placeholder pubkey,
            // or the plugin is not registered).  Treat as NotConfigured.
            tracing::debug!(
                username = %session.username,
                error = %e,
                "updater plugin not available (placeholder pubkey)"
            );
            Ok(UpdateCheckResult {
                status: UpdateStatus::NotConfigured,
                message: "Update server not configured. Download updates manually from GitHub Releases.".into(),
                available_version: None,
            })
        }
    }
}
