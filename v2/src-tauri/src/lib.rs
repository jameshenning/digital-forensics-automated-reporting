mod audit;
mod auth;
mod commands;
mod crypto;
mod db;
mod error;
mod state;

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
            // System commands
            settings_get_security_posture,
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
