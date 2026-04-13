/// Authentication Tauri commands.
///
/// Every command that mutates auth-related data after first-run setup calls
/// `require_session()` as its first statement (MUST-DO 3, SEC-1).
///
/// Wire shapes are documented in `// wire:` comments above each function.
/// The React frontend agent discovers them via `serde_json` inference.
use std::sync::Arc;

use serde::Serialize;
use tauri::State;
use tracing::{info, warn};

use crate::{
    audit,
    auth::{
        self,
        recovery,
        session::{require_pending_session, require_session},
        tokens,
        totp,
    },
    error::AppError,
    state::AppState,
};

// ─── Return types (wire shapes) ───────────────────────────────────────────────

/// Status of a login attempt.
/// `AccountLocked` is not returned as a variant here — callers receive
/// `Err(AppError::AccountLocked)` directly, which the frontend discriminates
/// on the error `code` field.
#[derive(Debug, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum LoginStatus {
    Success,
    MfaRequired,
}

/// Minimal session info returned to the frontend.
#[derive(Debug, Serialize)]
pub struct SessionInfo {
    pub token: String,
    pub username: String,
    pub mfa_enabled: bool,
}

/// Return type of `auth_login`.
#[derive(Debug, Serialize)]
pub struct LoginResult {
    pub status: LoginStatus,
    /// Present on `Success` or when MFA step is needed (pending token in that case).
    pub session: Option<SessionInfo>,
}

/// Return type of `auth_setup_first_run`.
#[derive(Debug, Serialize)]
pub struct SetupResult {
    pub session: SessionInfo,
}

/// Return type of `auth_mfa_enroll_start`.
#[derive(Debug, Serialize)]
pub struct MfaEnrollment {
    pub secret_b32: String,
    pub provisioning_uri: String,
}

/// Return type of `auth_mfa_enroll_confirm`.
#[derive(Debug, Serialize)]
pub struct MfaConfirmResult {
    pub recovery_codes: Vec<String>,
}

/// Return type of `auth_current_user`.
#[derive(Debug, Serialize)]
pub struct CurrentUserInfo {
    pub username: String,
    pub mfa_enabled: bool,
    pub last_login: Option<String>,
    pub recovery_codes_remaining: u32,
}

/// Return type of `auth_tokens_create`.
#[derive(Debug, Serialize)]
pub struct NewTokenResult {
    pub id: i64,
    pub name: String,
    pub plaintext: String,
    pub token_preview: String,
}

// ─── First-run setup ──────────────────────────────────────────────────────────

/// wire: { username: string, password: string } -> SetupResult
///
/// Creates the single application user. Only succeeds if no user exists.
/// Returns a fully-verified `SessionInfo` — first setup logs in immediately
/// without MFA (MFA enrollment is a separate later call).
#[tauri::command]
pub async fn auth_setup_first_run(
    username: String,
    password: String,
    state: State<'_, Arc<AppState>>,
) -> Result<SetupResult, AppError> {
    info!(command = "auth_setup_first_run");

    auth::create_user(&state.db.auth, &username, &password).await?;

    let token = state.sessions.create_verified(username.trim());

    audit::log_auth(username.trim(), audit::SETUP_ACCOUNT, "Initial account created");

    Ok(SetupResult {
        session: SessionInfo {
            token,
            username: username.trim().to_owned(),
            mfa_enabled: false,
        },
    })
}

// ─── Login (step 1: password) ────────────────────────────────────────────────

/// wire: { username: string, password: string } -> LoginResult
///
/// Verifies password credentials.
/// - If MFA is enabled: returns `LoginResult { status: MfaRequired, session: Some(pending_session) }`.
///   The pending session token is used for `auth_verify_mfa`.
/// - If no MFA: returns `LoginResult { status: Success, session: Some(verified_session) }`.
/// - On locked account: returns `Err(AppError::AccountLocked)`.
#[tauri::command]
pub async fn auth_login(
    username: String,
    password: String,
    state: State<'_, Arc<AppState>>,
) -> Result<LoginResult, AppError> {
    info!(command = "auth_login");

    match auth::verify_credentials(
        &state.db.auth,
        &state.lockout,
        &state.dummy_hash,
        &username,
        &password,
    )
    .await
    {
        Ok(user) => {
            let mfa_active = user.mfa_active();
            let username = user.username.clone();
            if mfa_active {
                // Create a pending session — MFA step required.
                let token = state.sessions.create_pending(&username, None);
                audit::log_auth(&username, audit::LOGIN_SUCCESS, "Password OK, MFA pending");
                Ok(LoginResult {
                    status: LoginStatus::MfaRequired,
                    session: Some(SessionInfo {
                        token,
                        username,
                        mfa_enabled: true,
                    }),
                })
            } else {
                let token = state.sessions.create_verified(&username);
                audit::log_auth(&username, audit::LOGIN_SUCCESS, "Login complete (no MFA)");
                Ok(LoginResult {
                    status: LoginStatus::Success,
                    session: Some(SessionInfo {
                        token,
                        username,
                        mfa_enabled: false,
                    }),
                })
            }
        }
        Err(AppError::AccountLocked { seconds_remaining }) => {
            audit::log_auth(
                &username,
                audit::LOGIN_FAILED,
                &format!("Account locked, {seconds_remaining}s remaining"),
            );
            Err(AppError::AccountLocked { seconds_remaining })
        }
        Err(AppError::InvalidCredentials) => {
            audit::log_auth(&username, audit::LOGIN_FAILED, "Bad credentials");
            Err(AppError::InvalidCredentials)
        }
        Err(e) => Err(e),
    }
}

// ─── Login (step 2: MFA verify) ──────────────────────────────────────────────

/// wire: { session_token: string, code: string, use_recovery: bool } -> SessionInfo
///
/// Completes the MFA step for a pending session.
/// - `code` can be a TOTP code (6 digits) or a recovery code.
/// - `use_recovery: true` → treat `code` as a recovery code.
/// - On success, the pending session is promoted to verified.
/// - After `MAX_MFA_FAILURES` consecutive failures, the pending session is
///   cleared and the user must restart from the password step.
#[tauri::command]
pub async fn auth_verify_mfa(
    session_token: String,
    code: String,
    use_recovery: bool,
    state: State<'_, Arc<AppState>>,
) -> Result<SessionInfo, AppError> {
    info!(command = "auth_verify_mfa");

    let session_data = require_pending_session(&state, &session_token)?;
    let username = session_data.username.clone();

    if use_recovery {
        // Recovery code path.
        let user = auth::get_user(&state.db.auth, &username)
            .await?
            .ok_or(AppError::UserNotFound)?;

        match recovery::verify_and_consume(&state.db.auth, user.id, &code).await {
            Ok(true) => {
                state.sessions.promote_to_verified(&session_token)?;
                let remaining = recovery::remaining(&state.db.auth, user.id).await?;
                audit::log_auth(
                    &username,
                    audit::MFA_RECOVERY_USED,
                    &format!("{remaining} codes remaining"),
                );
                return Ok(SessionInfo {
                    token: session_token,
                    username,
                    mfa_enabled: true,
                });
            }
            Ok(false) => {
                // Record MFA failure.
                audit::log_auth(&username, audit::LOGIN_FAILED, "Invalid recovery code");
                match state.sessions.record_mfa_failure(&session_token) {
                    Ok(()) => return Err(AppError::InvalidMfaCode),
                    Err(_) => {
                        warn!(username = %username, "session invalidated after MFA failure limit");
                        return Err(AppError::Unauthorized);
                    }
                }
            }
            Err(AppError::NoRecoveryCodesRemaining) => {
                return Err(AppError::NoRecoveryCodesRemaining);
            }
            Err(e) => return Err(e),
        }
    } else {
        // TOTP path.
        let totp_secret = auth::get_totp_secret(&state.db.auth, &state.crypto, &username)
            .await?
            .ok_or(AppError::InvalidMfaCode)?;

        if totp::verify_code(&totp_secret, &code) {
            state.sessions.promote_to_verified(&session_token)?;
            audit::log_auth(&username, audit::MFA_VERIFIED, "TOTP verified, login complete");
            Ok(SessionInfo {
                token: session_token,
                username,
                mfa_enabled: true,
            })
        } else {
            audit::log_auth(&username, audit::LOGIN_FAILED, "Invalid TOTP code");
            match state.sessions.record_mfa_failure(&session_token) {
                Ok(()) => Err(AppError::InvalidMfaCode),
                Err(_) => {
                    warn!(username = %username, "session invalidated after MFA failure limit");
                    Err(AppError::Unauthorized)
                }
            }
        }
    }
}

// ─── Logout ───────────────────────────────────────────────────────────────────

/// wire: { session_token: string } -> ()
#[tauri::command]
pub async fn auth_logout(
    session_token: String,
    state: State<'_, Arc<AppState>>,
) -> Result<(), AppError> {
    info!(command = "auth_logout");

    // Best-effort: read the username before invalidating so we can audit-log it.
    let username = state
        .sessions
        .get_and_touch(&session_token)
        .map(|d| d.username)
        .unwrap_or_else(|_| "unknown".to_owned());

    state.sessions.invalidate(&session_token);
    audit::log_auth(&username, audit::LOGOUT, "User logged out");
    Ok(())
}

// ─── Change password ──────────────────────────────────────────────────────────

/// wire: { session_token: string, current_password: string, new_password: string } -> ()
#[tauri::command]
pub async fn auth_change_password(
    session_token: String,
    current_password: String,
    new_password: String,
    state: State<'_, Arc<AppState>>,
) -> Result<(), AppError> {
    info!(command = "auth_change_password");

    // MUST-DO 3: session guard.
    let session = require_session(&state, &session_token)?;
    let username = session.username;

    auth::update_password(
        &state.db.auth,
        &state.lockout,
        &state.dummy_hash,
        &username,
        &current_password,
        &new_password,
    )
    .await?;

    audit::log_auth(&username, audit::PASSWORD_CHANGED, "Password updated");
    Ok(())
}

// ─── Current user ─────────────────────────────────────────────────────────────

/// wire: { session_token: string } -> CurrentUserInfo | null
#[tauri::command]
pub async fn auth_current_user(
    session_token: String,
    state: State<'_, Arc<AppState>>,
) -> Result<Option<CurrentUserInfo>, AppError> {
    info!(command = "auth_current_user");

    match require_session(&state, &session_token) {
        Ok(session) => {
            let username = session.username;
            let user = auth::get_user(&state.db.auth, &username)
                .await?
                .ok_or(AppError::UserNotFound)?;
            let recovery_remaining =
                auth::remaining_recovery_codes(&state.db.auth, &username).await?;
            let mfa_enabled = user.mfa_active();
            Ok(Some(CurrentUserInfo {
                username: user.username,
                mfa_enabled,
                last_login: user.last_login,
                recovery_codes_remaining: recovery_remaining,
            }))
        }
        Err(AppError::Unauthorized) => Ok(None),
        Err(e) => Err(e),
    }
}

// ─── MFA enrollment ───────────────────────────────────────────────────────────

/// wire: { session_token: string } -> MfaEnrollment
///
/// Starts MFA enrollment: generates a fresh TOTP secret, stores it in the
/// session (NOT in the DB yet), and returns the Base32 secret + QR URI.
/// The secret lives in memory until `auth_mfa_enroll_confirm` is called.
/// SEC-1: pending_totp_secret is stored in session state, not re-fetched from DB.
#[tauri::command]
pub async fn auth_mfa_enroll_start(
    session_token: String,
    state: State<'_, Arc<AppState>>,
) -> Result<MfaEnrollment, AppError> {
    info!(command = "auth_mfa_enroll_start");

    let session = require_session(&state, &session_token)?;
    let username = session.username;

    // Check not already enrolled.
    let user = auth::get_user(&state.db.auth, &username)
        .await?
        .ok_or(AppError::UserNotFound)?;
    if user.mfa_active() {
        return Err(AppError::Internal(
            "MFA is already enabled. Disable it first to re-enroll.".into(),
        ));
    }

    let secret_b32 = totp::generate_secret();
    let provisioning_uri = totp::enrollment_uri(&secret_b32, &username)?;

    // Store the pending secret in the session to prevent substitution attacks.
    state
        .sessions
        .set_pending_totp_secret(&session_token, Some(secret_b32.clone()))?;

    Ok(MfaEnrollment {
        secret_b32,
        provisioning_uri,
    })
}

/// wire: { session_token: string, code: string } -> MfaConfirmResult
///
/// Confirms MFA enrollment: verifies the code against the in-session pending
/// secret (NOT fetched from DB), then persists the encrypted secret and
/// generates recovery codes.
#[tauri::command]
pub async fn auth_mfa_enroll_confirm(
    session_token: String,
    code: String,
    state: State<'_, Arc<AppState>>,
) -> Result<MfaConfirmResult, AppError> {
    info!(command = "auth_mfa_enroll_confirm");

    let session = require_session(&state, &session_token)?;
    let username = session.username;

    // Read the pending secret from session state — never re-fetch from DB.
    let pending_secret = state.sessions.get_pending_totp_secret(&session_token)?;

    let secret_b32 = pending_secret
        .ok_or_else(|| AppError::Internal("No pending TOTP secret in session".into()))?;

    if !totp::verify_code(&secret_b32, &code) {
        return Err(AppError::InvalidMfaCode);
    }

    // Persist encrypted secret and mark MFA enabled.
    auth::enable_mfa(&state.db.auth, &state.crypto, &username, &secret_b32).await?;

    // Generate recovery codes.
    let user = auth::get_user(&state.db.auth, &username)
        .await?
        .ok_or(AppError::UserNotFound)?;
    let codes = recovery::generate_and_store(&state.db.auth, user.id).await?;

    // Clear the pending secret from session.
    let _ = state.sessions.set_pending_totp_secret(&session_token, None);

    audit::log_auth(
        &username,
        audit::MFA_ENROLLED,
        &format!("TOTP enrolled, {} recovery codes generated", codes.len()),
    );

    Ok(MfaConfirmResult {
        recovery_codes: codes,
    })
}

// ─── MFA disable ─────────────────────────────────────────────────────────────

/// wire: { session_token: string, password: string } -> ()
///
/// Disables MFA. Requires password re-entry as defense against session hijack.
/// Also revokes all outstanding recovery codes.
#[tauri::command]
pub async fn auth_mfa_disable(
    session_token: String,
    password: String,
    state: State<'_, Arc<AppState>>,
) -> Result<(), AppError> {
    info!(command = "auth_mfa_disable");

    // MUST-DO 3: session guard.
    let session = require_session(&state, &session_token)?;
    let username = session.username;

    auth::disable_mfa(
        &state.db.auth,
        &state.lockout,
        &state.dummy_hash,
        &state.crypto,
        &username,
        &password,
    )
    .await?;

    audit::log_auth(&username, audit::MFA_DISABLED, "MFA disabled");
    Ok(())
}

// ─── API token management ─────────────────────────────────────────────────────

/// wire: { session_token: string } -> Vec<ApiTokenListItem>
#[tauri::command]
pub async fn auth_tokens_list(
    session_token: String,
    state: State<'_, Arc<AppState>>,
) -> Result<Vec<tokens::ApiTokenListItem>, AppError> {
    info!(command = "auth_tokens_list");

    // MUST-DO 3: session guard.
    let session = require_session(&state, &session_token)?;
    let username = session.username;

    let user = auth::get_user(&state.db.auth, &username)
        .await?
        .ok_or(AppError::UserNotFound)?;

    tokens::list_for_user(&state.db.auth, user.id).await
}

/// wire: { session_token: string, name: string } -> NewTokenResult
///
/// Creates an API token. The plaintext is shown exactly once — caller must
/// display it to the user immediately.
#[tauri::command]
pub async fn auth_tokens_create(
    session_token: String,
    name: String,
    state: State<'_, Arc<AppState>>,
) -> Result<NewTokenResult, AppError> {
    info!(command = "auth_tokens_create");

    // MUST-DO 3: session guard.
    let session = require_session(&state, &session_token)?;
    let username = session.username;

    let user = auth::get_user(&state.db.auth, &username)
        .await?
        .ok_or(AppError::UserNotFound)?;

    let token = tokens::create(&state.db.auth, user.id, &name).await?;

    audit::log_auth(
        &username,
        audit::API_TOKEN_CREATED,
        &format!("Token '{}' (id={})", token.name, token.id),
    );

    // NOTE: `token.plaintext` must be shown to the user by the React frontend.
    // It is included in the response and never stored again.
    Ok(NewTokenResult {
        id: token.id,
        name: token.name,
        plaintext: token.plaintext,
        token_preview: token.token_preview,
    })
}

/// wire: { session_token: string, token_id: number } -> ()
#[tauri::command]
pub async fn auth_tokens_revoke(
    session_token: String,
    token_id: i64,
    state: State<'_, Arc<AppState>>,
) -> Result<(), AppError> {
    info!(command = "auth_tokens_revoke");

    // MUST-DO 3: session guard.
    let session = require_session(&state, &session_token)?;
    let username = session.username;

    let user = auth::get_user(&state.db.auth, &username)
        .await?
        .ok_or(AppError::UserNotFound)?;

    if tokens::revoke(&state.db.auth, token_id, user.id).await? {
        audit::log_auth(
            &username,
            audit::API_TOKEN_REVOKED,
            &format!("Token id={token_id}"),
        );
        Ok(())
    } else {
        Err(AppError::Internal("Token not found.".into()))
    }
}
