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

    #[error("evidence not found: {evidence_id}")]
    EvidenceNotFound { evidence_id: String },

    #[error("evidence already exists: {evidence_id}")]
    EvidenceAlreadyExists { evidence_id: String },

    #[error("evidence has dependents and cannot be deleted: {evidence_id}")]
    EvidenceHasDependents { evidence_id: String },

    #[error("custody event not found: {custody_id}")]
    CustodyNotFound { custody_id: i64 },

    #[error("hash record not found: {hash_id}")]
    HashNotFound { hash_id: i64 },

    #[error("validation error on field '{field}': {message}")]
    ValidationError { field: String, message: String },

    #[error("I/O error: {0}")]
    Io(String),

    #[error("internal error: {0}")]
    Internal(String),

    // ─── Phase 4: link analysis ───────────────────────────────────────────────

    #[error("entity not found: entity_id={entity_id}")]
    EntityNotFound { entity_id: i64 },

    #[error("entity cycle detected: entity_id={entity_id} would create a cycle in the parent chain")]
    EntityCycle { entity_id: i64 },

    #[error("link not found: link_id={link_id}")]
    LinkNotFound { link_id: i64 },

    #[error("link endpoint missing: {kind} id={id} does not exist in this case")]
    LinkEndpointMissing { kind: String, id: String },

    #[error("event not found: event_id={event_id}")]
    EventNotFound { event_id: i64 },

    // ─── Phase 3b: evidence files ─────────────────────────────────────────────

    #[error("evidence file not found: file_id={file_id}")]
    EvidenceFileNotFound { file_id: i64 },

    #[error("file too large: size={size} bytes exceeds limit={limit} bytes")]
    EvidenceFileTooLarge { size: u64, limit: u64 },

    #[error("invalid filename: {message}")]
    InvalidFilename { message: String },

    #[error("path traversal blocked: attempted={attempted_path}")]
    PathTraversalBlocked { attempted_path: String },

    #[error("OneDrive sync warning: appdata_path={appdata_path}, onedrive_path={onedrive_path}")]
    OneDriveSyncWarning { appdata_path: String, onedrive_path: String },

    #[error("hash mismatch on download: file_id={file_id}, expected={expected}, actual={actual}")]
    HashMismatchOnDownload { file_id: i64, expected: String, actual: String },

    // ─── Phase 3b: reports ───────────────────────────────────────────────────

    #[error("report generation failed: {reason}")]
    ReportGenerationFailed { reason: String },
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
