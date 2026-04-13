mod audit;
pub mod auth;
mod commands;
pub mod crypto;
pub mod db;
pub mod error;
pub mod reports;
pub mod state;
pub mod uploads;

// Test helpers — compiled only in test builds.
// Provides ephemeral DB setup, test CryptoState construction, etc.
#[cfg(test)]
#[allow(dead_code, unused_imports)] // helpers may be unused by the current test set but are kept for future phases
pub(crate) mod test_helpers;

use std::sync::Arc;

use tauri::Manager;
use tracing_appender::rolling;
use tracing_subscriber::{fmt, layer::SubscriberExt, util::SubscriberInitExt, EnvFilter};

use commands::{
    auth_cmd::{
        auth_change_password, auth_current_user, auth_login, auth_logout,
        auth_mfa_disable, auth_mfa_enroll_confirm, auth_mfa_enroll_start,
        auth_setup_first_run, auth_tokens_create, auth_tokens_list, auth_tokens_revoke,
        auth_verify_mfa,
    },
    cases_cmd::{case_create, case_delete, case_get, case_update, cases_list},
    files_cmd::{
        evidence_files_download, evidence_files_list, evidence_files_purge,
        evidence_files_soft_delete, evidence_files_upload,
        settings_acknowledge_onedrive_risk,
    },
    records_cmd::{
        analysis_add, analysis_list_for_case, analysis_list_for_evidence,
        custody_add, custody_delete, custody_list_for_case, custody_list_for_evidence,
        custody_update, evidence_add, evidence_delete, evidence_get,
        evidence_list_for_case, hash_add, hash_list_for_case, hash_list_for_evidence,
        tool_add, tool_list_for_case, tool_list_for_evidence,
    },
    reports_cmd::{case_report_generate, case_report_preview},
    system_cmd::settings_get_security_posture,
};

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_opener::init())
        .setup(|app| {
            // ── Logging ───────────────────────────────────────────────────────
            // Write to %LOCALAPPDATA%\DFARS\Logs\dfars-desktop.log
            // Rolling daily, keep 7 files.
            let log_dir = app
                .path()
                .app_log_dir()
                .unwrap_or_else(|_| std::path::PathBuf::from("logs"));
            std::fs::create_dir_all(&log_dir)
                .expect("failed to create log directory");

            let file_appender = rolling::daily(&log_dir, "dfars-desktop.log");
            let (non_blocking, _guard) = tracing_appender::non_blocking(file_appender);

            // Keep the guard alive for the process lifetime by leaking it.
            // This is intentional: we want the log writer to stay alive until exit.
            std::mem::forget(_guard);

            tracing_subscriber::registry()
                .with(EnvFilter::try_from_default_env().unwrap_or_else(|_| {
                    EnvFilter::new("dfars_desktop_lib=info,warn")
                }))
                .with(fmt::layer().with_writer(non_blocking))
                .init();

            tracing::info!(version = env!("CARGO_PKG_VERSION"), "DFARS Desktop starting");

            // ── Paths ─────────────────────────────────────────────────────────
            let app_data = app
                .path()
                .app_data_dir()
                .expect("failed to resolve AppData dir");
            std::fs::create_dir_all(&app_data)?;

            let forensics_path = app_data.join("forensics.db");
            let auth_path = app_data.join("auth.db");

            // ── Database ──────────────────────────────────────────────────────
            let app_db = tauri::async_runtime::block_on(async {
                db::init(&forensics_path, &auth_path).await
            })
            .expect("failed to initialise database");

            // ── Crypto ────────────────────────────────────────────────────────
            let crypto_state = crypto::init().expect("failed to initialise crypto layer");

            // ── AppState ──────────────────────────────────────────────────────
            let app_state = Arc::new(state::AppState::new(app_db, crypto_state));

            // ── Hydrate lockout map from DB ────────────────────────────────────
            // Do this before any command can be invoked. Handles both empty DBs
            // (fresh install) and DBs with locked users (v1 upgrade path).
            {
                let state_clone = Arc::clone(&app_state);
                tauri::async_runtime::block_on(async move {
                    if let Err(e) = state_clone
                        .lockout
                        .hydrate_from_db(&state_clone.db.auth)
                        .await
                    {
                        tracing::warn!("lockout hydration error (non-fatal): {e}");
                    }
                });
            }

            app.manage(app_state);
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            // Auth commands
            auth_setup_first_run,
            auth_login,
            auth_verify_mfa,
            auth_logout,
            auth_change_password,
            auth_current_user,
            auth_mfa_enroll_start,
            auth_mfa_enroll_confirm,
            auth_mfa_disable,
            auth_tokens_list,
            auth_tokens_create,
            auth_tokens_revoke,
            // Case commands (Phase 2)
            cases_list,
            case_get,
            case_create,
            case_update,
            case_delete,
            // Evidence commands (Phase 3a)
            evidence_add,
            evidence_get,
            evidence_list_for_case,
            evidence_delete,
            // Chain-of-custody commands (Phase 3a)
            custody_add,
            custody_list_for_evidence,
            custody_list_for_case,
            custody_update,
            custody_delete,
            // Hash verification commands (Phase 3a)
            hash_add,
            hash_list_for_evidence,
            hash_list_for_case,
            // Tool usage commands (Phase 3a)
            tool_add,
            tool_list_for_case,
            tool_list_for_evidence,
            // Analysis note commands (Phase 3a)
            analysis_add,
            analysis_list_for_case,
            analysis_list_for_evidence,
            // Evidence file commands (Phase 3b)
            evidence_files_upload,
            evidence_files_list,
            evidence_files_download,
            evidence_files_soft_delete,
            evidence_files_purge,
            settings_acknowledge_onedrive_risk,
            // Report commands (Phase 3b)
            case_report_preview,
            case_report_generate,
            // System commands
            settings_get_security_posture,
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
