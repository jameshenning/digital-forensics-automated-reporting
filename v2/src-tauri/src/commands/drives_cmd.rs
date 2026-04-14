/// Drive enumeration and scan Tauri commands — Phase 5.
use std::path::PathBuf;
use std::sync::Arc;

use tauri::State;

use crate::auth::session::require_session;
use crate::drives::{self, Drive, DriveScanResult};
use crate::error::AppError;
use crate::state::AppState;

/// List all drives visible to the OS.
#[tauri::command]
pub async fn drives_list(
    token: String,
    state: State<'_, Arc<AppState>>,
) -> Result<Vec<Drive>, AppError> {
    require_session(&state, &token)?;
    drives::list_drives().await
}

/// Scan a directory tree and return aggregate statistics.
///
/// `path` is the root to scan.  `case_id` is used for audit logging only.
#[tauri::command]
pub async fn drive_scan(
    token: String,
    _case_id: String,
    path: String,
    state: State<'_, Arc<AppState>>,
) -> Result<DriveScanResult, AppError> {
    let _session = require_session(&state, &token)?;
    let root = PathBuf::from(&path);
    if !root.exists() {
        return Err(AppError::ValidationError {
            field: "path".into(),
            message: format!("path does not exist: {path}"),
        });
    }
    drives::scan_drive(&root, 10, 100_000).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_helpers::build_test_state;

    #[tokio::test]
    async fn drives_list_empty_token_unauthorized() {
        let (state, _pool) = build_test_state().await;
        let result = require_session(&state, "");
        assert!(matches!(result, Err(AppError::Unauthorized)));
    }
}
