/// Report Tauri commands — Phase 3b.
///
/// MUST-DO 3 (SEC-1): every command starts with `require_session()`.
///
/// Commands:
///   - `case_report_preview`   — returns the markdown string (no file I/O)
///   - `case_report_generate`  — writes to disk, returns absolute path as String
use std::sync::Arc;

use tauri::State;
use tracing::info;

use crate::{
    audit,
    auth::session::require_session,
    error::AppError,
    reports::{self, ReportFormat},
    state::AppState,
};

// ─── Preview (markdown string) ────────────────────────────────────────────────

/// Generate a markdown preview of the case report.
///
/// Returns the full markdown as a `String` without writing to disk.
/// The React frontend can render this in a preview pane.
#[tauri::command(rename_all = "snake_case")]
pub async fn case_report_preview(
    token: String,
    case_id: String,
    state: State<'_, Arc<AppState>>,
) -> Result<String, AppError> {
    let _session = require_session(&state, &token)?;

    reports::preview_markdown(&state, &case_id).await
}

// ─── Generate (write to disk) ─────────────────────────────────────────────────

/// Generate and save a case report.
///
/// `format` must be `"markdown"` or `"html"`.  Defaults to `"markdown"` if
/// the value is unrecognized.
///
/// Returns the absolute path to the generated file as a `String`.
#[tauri::command(rename_all = "snake_case")]
pub async fn case_report_generate(
    token: String,
    case_id: String,
    format: String,
    state: State<'_, Arc<AppState>>,
) -> Result<String, AppError> {
    let session = require_session(&state, &token)?;

    let report_format = match format.to_lowercase().as_str() {
        "html" => ReportFormat::Html,
        _ => ReportFormat::Markdown,
    };

    let reports_dir = reports::default_reports_dir();
    let out_path = reports::generate_report(&state, &case_id, report_format, &reports_dir).await?;

    let path_str = out_path.display().to_string();

    audit::log_case(
        &case_id,
        &session.username,
        audit::REPORT_GENERATED,
        &format!("report saved to {path_str}"),
    );

    info!(
        username = %session.username,
        case_id = %case_id,
        path = %path_str,
        "case report generated"
    );

    Ok(path_str)
}
