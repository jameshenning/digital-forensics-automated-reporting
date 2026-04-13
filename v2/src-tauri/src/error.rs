/// AppError — every fallible operation in the backend returns this type.
///
/// Implements `serde::Serialize` so Tauri's IPC bridge can transmit it to the
/// React frontend as `{ "code": "...", "message": "..." }`.  The frontend
/// discriminates on `code` to decide which UI to show.
use serde::Serialize;
use thiserror::Error;

#[derive(Debug, Error, Serialize)]
#[serde(tag = "code", content = "message")]
pub enum AppError {
    #[error("unauthorized")]
    Unauthorized,

    #[error("invalid credentials")]
    InvalidCredentials,

    #[error("account locked for {seconds_remaining} more seconds")]
    AccountLocked { seconds_remaining: u64 },

    #[error("MFA verification required")]
    MfaRequired,

    #[error("invalid MFA code")]
    InvalidMfaCode,

    #[error("no recovery codes remaining")]
    NoRecoveryCodesRemaining,

    #[error("user already exists")]
    UserAlreadyExists,

    #[error("user not found")]
    UserNotFound,

    #[error("password policy violation: {0}")]
    PasswordPolicy(String),

    #[error("database error: {0}")]
    Db(String),

    #[error("crypto error: {0}")]
    Crypto(String),

    /// Used by crypto.rs when keyring operations fail — not yet surfaced in commands.
    #[allow(dead_code)]
    #[error("keyring error: {0}")]
    Keyring(String),

    #[error("case not found: {case_id}")]
    CaseNotFound { case_id: String },

    #[error("case already exists: {case_id}")]
    CaseAlreadyExists { case_id: String },

    #[error("case has evidence and cannot be deleted: {case_id}")]
    CaseHasEvidence { case_id: String },

    #[error("validation error on field '{field}': {message}")]
    ValidationError { field: String, message: String },

    #[error("I/O error: {0}")]
    Io(String),

    #[error("internal error: {0}")]
    Internal(String),
}

impl From<sqlx::Error> for AppError {
    fn from(e: sqlx::Error) -> Self {
        AppError::Db(e.to_string())
    }
}

impl From<std::io::Error> for AppError {
    fn from(e: std::io::Error) -> Self {
        AppError::Io(e.to_string())
    }
}
