pub mod agent_zero;
mod audit;
pub mod auth;
pub mod axum_server;
mod commands;
pub mod config;
pub mod crypto;
pub mod db;
pub mod drives;
pub mod error;
pub mod mailer;
pub mod reports;
pub mod state;
pub mod uploads;

// Test helpers — compiled only in test builds.
// Provides ephemeral DB setup, test CryptoState construction, etc.
#[cfg(test)]
#[allow(dead_code, unused_imports)] // helpers may be unused by the current test set but are kept for future phases
pub(crate) mod test_helpers;

use std::path::Path;
use std::sync::Arc;

use tauri::Manager;
use tracing_appender::non_blocking::WorkerGuard;
use tracing_appender::rolling::{RollingFileAppender, Rotation};
use tracing_subscriber::{fmt, layer::SubscriberExt, util::SubscriberInitExt, EnvFilter};

use commands::{
    ai_cmd::{ai_classify, ai_enhance, ai_summarize_case, evidence_forensic_analyze},
    auth_cmd::{
        auth_change_password, auth_current_user, auth_login, auth_logout,
        auth_mfa_disable, auth_mfa_enroll_confirm, auth_mfa_enroll_start,
        auth_setup_first_run, auth_tokens_create, auth_tokens_list, auth_tokens_revoke,
        auth_verify_mfa,
    },
    cases_cmd::{case_create, case_delete, case_get, case_update, cases_list},
    drives_cmd::{drive_scan, drives_list},
    files_cmd::{
        evidence_files_download, evidence_files_list, evidence_files_purge,
        evidence_files_soft_delete, evidence_files_upload,
        settings_acknowledge_onedrive_risk,
    },
    integrations_cmd::{
        settings_acknowledge_ai_consent, settings_get_agent_zero, settings_get_smtp,
        settings_set_agent_zero, settings_set_smtp, settings_test_agent_zero,
        settings_test_smtp,
    },
    link_analysis_cmd::{
        case_crime_line, case_graph,
        entity_add, entity_delete, entity_get, entity_list_for_case, entity_update,
        event_add, event_delete, event_list_for_case, event_update,
        link_add, link_delete, link_list_for_case,
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
    updates_cmd::settings_check_for_updates,
};

// ─── Public re-exports for integration test access ────────────────────────────
// Integration tests live in `tests/` and can only access `pub` items from the
// crate root.  Re-export the types they need here.
pub use commands::updates_cmd::{UpdateCheckResult, UpdateStatus};

// ─── Tracing initializer ───────────────────────────────────────────────────────

/// Initialize the tracing subscriber with a rolling file appender and a stdout layer.
///
/// Call this exactly ONCE per process, before `tauri::Builder::default()`.
/// Returns a `WorkerGuard` that MUST be kept alive for the entire process
/// lifetime.  Dropping it causes the non-blocking writer to flush synchronously
/// from the calling thread rather than from the background writer thread,
/// potentially blocking the Tauri main thread during shutdown.
///
/// **Load-bearing: do not drop the returned guard early.**
///
/// # Rotation strategy
/// Daily rotation with max 7 files (~1 week of logs).  The `tracing-appender`
/// 0.2 crate exposes time-based rotation only (HOURLY / DAILY / NEVER); size-
/// based rotation is not available without a third-party crate.  DAILY rotation
/// is appropriate for a forensic desktop app — it gives 1-week coverage without
/// accumulating unbounded disk space.
///
/// # Idempotency
/// Uses `try_init()` so that calling this function twice (e.g., in a test that
/// initialises its own subscriber first) does not panic — the second call is
/// silently ignored.
pub fn init_tracing(log_dir: &Path) -> Result<WorkerGuard, crate::error::AppError> {
    std::fs::create_dir_all(log_dir).map_err(|e| {
        crate::error::AppError::Io(format!("create log dir {}: {e}", log_dir.display()))
    })?;

    let file_appender = RollingFileAppender::builder()
        .rotation(Rotation::DAILY)
        .filename_prefix("dfars-desktop")
        .filename_suffix("log")
        .max_log_files(7)
        .build(log_dir)
        .map_err(|e| crate::error::AppError::Io(format!("rolling appender: {e}")))?;

    let (non_blocking, guard) = tracing_appender::non_blocking(file_appender);

    // File layer: plain text, no ANSI escape codes, with target + line numbers.
    // AUDIT-LOG-SAFE: no secrets are formatted into log fields anywhere in this
    // crate (see redaction audit in Phase 6 implementation notes).
    let file_layer = fmt::layer()
        .with_writer(non_blocking)
        .with_ansi(false)
        .with_target(true)
        .with_line_number(true)
        .with_thread_ids(false);

    // Stdout layer: colored output for terminal debugging during development.
    let stdout_layer = fmt::layer()
        .with_ansi(true)
        .with_target(true);

    let filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new("dfars_desktop_lib=info,tauri=info,warn"));

    // try_init() is idempotent-safe: if a subscriber is already set (e.g., in
    // tests that install their own subscriber), the error is silently ignored.
    let _ = tracing_subscriber::registry()
        .with(filter)
        .with(file_layer)
        .with(stdout_layer)
        .try_init();

    Ok(guard)
}

// ─── App entry point ───────────────────────────────────────────────────────────

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    // ── Tracing ───────────────────────────────────────────────────────────────
    // Resolve %LOCALAPPDATA%\DFARS\Logs\ via the `directories` crate.
    // This runs BEFORE tauri::Builder::default() so the very first log line
    // (version + log_dir) appears in the file appender output.
    let log_dir = directories::BaseDirs::new()
        .map(|b| b.data_local_dir().join("DFARS").join("Logs"))
        .unwrap_or_else(|| std::path::PathBuf::from("logs"));

    // The guard is moved into Tauri's managed state below so it lives for the
    // entire process lifetime.  This is the approved pattern (vs. mem::forget):
    // Tauri drops managed state at process exit in the correct order, flushing
    // the non-blocking writer before the process exits.
    //
    // Load-bearing: do not remove this field from managed state.
    let log_guard = init_tracing(&log_dir)
        .unwrap_or_else(|e| {
            // Can't log yet — print to stderr and continue without file logging.
            eprintln!("DFARS: failed to initialize tracing: {e}");
            // Create a no-op guard by using a /dev/null-equivalent: a
            // non_blocking writer over a sink, so we still get a WorkerGuard.
            let (_, guard) = tracing_appender::non_blocking(std::io::sink());
            guard
        });

    tracing::info!(
        version = env!("CARGO_PKG_VERSION"),
        log_dir = %log_dir.display(),
        "DFARS Desktop starting"
    );

    // ── Tauri builder ─────────────────────────────────────────────────────────
    tauri::Builder::default()
        .plugin(tauri_plugin_opener::init())
        // Note: tauri-plugin-updater was wired here in Phase 6 as an inert
        // placeholder. Removed per SEC-9 before v2.0.0 release — shipping a
        // placeholder pubkey + unreachable endpoint is worse than no updater
        // at all. Auto-update reintroduced post-v2.0.0 once hosting is chosen.
        // See docs/sec-9-final-release-review.md and v2-migration-spec.md §11.
        .setup(|app| {
            // Move the guard into Tauri managed state so it is held alive for
            // the entire process.  Tauri drops managed state at process exit.
            //
            // Load-bearing: do not remove — dropping it makes log writes
            // synchronous and may block the Tauri main thread during shutdown.
            app.manage(log_guard);

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

            // ── Config ────────────────────────────────────────────────────────
            let config_path = app_data.join("config.json");
            let app_config = config::load(&config_path)
                .expect("failed to load config.json");

            // ── Agent Zero client ─────────────────────────────────────────────
            let agent_zero_state = tauri::async_runtime::block_on(async {
                agent_zero::AgentZeroState::from_config(&app_config, &crypto_state).await
            })
            .expect("failed to init Agent Zero state");

            // ── AppState ──────────────────────────────────────────────────────
            let app_state = Arc::new(state::AppState::new_with_config(
                app_db,
                crypto_state,
                app_config.clone(),
                config_path,
                agent_zero_state,
            ));

            // ── Hydrate lockout map from DB ────────────────────────────────────
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

            // ── axum REST API server ──────────────────────────────────────────
            // Starts only if bind_host is valid and the bind-host gate passes
            // (SEC-5 MUST-DO 5). A None means the gate refused (non-loopback
            // without allow_network_bind = true) — logged inside axum_server::start.
            {
                let state_clone = Arc::clone(&app_state);
                let bind_host = app_config.bind_host.clone();
                let port = app_config.axum_port;
                let axum_handle = tauri::async_runtime::block_on(async move {
                    match axum_server::start(state_clone, &bind_host, port).await {
                        Ok(handle) => Some(handle),
                        Err(crate::error::AppError::NetworkBindRefused { bind_host }) => {
                            tracing::warn!(
                                bind_host,
                                "axum server NOT started: non-loopback bind refused \
                                 (allow_network_bind = false)"
                            );
                            None
                        }
                        Err(e) => {
                            tracing::error!("axum server failed to start: {e}");
                            None
                        }
                    }
                });
                app.manage(axum_handle);
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
            // Entity commands (Phase 4)
            entity_add,
            entity_get,
            entity_list_for_case,
            entity_update,
            entity_delete,
            // Link commands (Phase 4)
            link_add,
            link_list_for_case,
            link_delete,
            // Case event commands (Phase 4)
            event_add,
            event_list_for_case,
            event_update,
            event_delete,
            // Graph aggregate commands (Phase 4)
            case_graph,
            case_crime_line,
            // System commands
            settings_get_security_posture,
            // AI commands (Phase 5)
            ai_enhance,
            ai_classify,
            ai_summarize_case,
            evidence_forensic_analyze,
            // Drive commands (Phase 5)
            drives_list,
            drive_scan,
            // Integration settings commands (Phase 5)
            settings_get_agent_zero,
            settings_set_agent_zero,
            settings_test_agent_zero,
            settings_get_smtp,
            settings_set_smtp,
            settings_test_smtp,
            settings_acknowledge_ai_consent,
            // Update commands (Phase 6)
            settings_check_for_updates,
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
