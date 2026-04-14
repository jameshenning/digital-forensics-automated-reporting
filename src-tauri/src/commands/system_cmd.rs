/// System / settings commands.
///
/// Includes `settings_get_security_posture()` (SEC-1 SHOULD-DO 6) which
/// returns a JSON payload the UI uses to surface a "Upgrade to keyring"
/// warning when the file-fallback key path is active.
use std::sync::Arc;

use serde::Serialize;
use tauri::State;
use tracing::info;

use crate::{
    auth,
    auth::session::require_session,
    crypto::KeySource,
    error::AppError,
    state::AppState,
};

/// wire: { session_token: string } -> SecurityPostureInfo
///
/// SEC-1 SHOULD-DO 6: surface key-source and MFA status to the UI so the
/// user can be warned if they're running with the less-secure file fallback.
#[derive(Debug, Serialize)]
pub struct SecurityPostureInfo {
    /// True if the Fernet key came from Windows Credential Manager.
    /// False means file fallback is active — the UI should warn the user.
    pub keyring_active: bool,
    /// Which path the key came from: "keyring" | "keyfile" | "new"
    pub key_source: String,
    /// True if the current user has TOTP MFA enabled.
    pub mfa_enabled: bool,
    /// Number of unused one-time recovery codes remaining.
    pub recovery_codes_remaining: u32,
}

#[tauri::command]
pub async fn settings_get_security_posture(
    session_token: String,
    state: State<'_, Arc<AppState>>,
) -> Result<SecurityPostureInfo, AppError> {
    info!(command = "settings_get_security_posture");

    // MUST-DO 3: session guard.
    let session = require_session(&state, &session_token)?;
    let username = session.username;

    let user = auth::get_user(&state.db.auth, &username)
        .await?
        .ok_or(AppError::UserNotFound)?;

    let recovery_remaining = auth::remaining_recovery_codes(&state.db.auth, &username).await?;

    let (keyring_active, key_source_str) = match &state.crypto.key_source {
        KeySource::Keyring => (true, "keyring".to_owned()),
        KeySource::Keyfile => (false, "keyfile".to_owned()),
        KeySource::New => (false, "new".to_owned()),
    };

    Ok(SecurityPostureInfo {
        keyring_active,
        key_source: key_source_str,
        mfa_enabled: user.mfa_active(),
        recovery_codes_remaining: recovery_remaining,
    })
}
