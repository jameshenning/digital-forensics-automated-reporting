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

    // ─── Persons — photo upload (migration 0002) ─────────────────────────────

    #[error("person photo too large: size={size} bytes exceeds limit={limit} bytes")]
    PersonPhotoTooLarge { size: u64, limit: u64 },

    #[error("person photo is not an image: detected={detected}")]
    PersonPhotoNotAnImage { detected: String },

    #[error("entity is not a person: entity_id={entity_id}, entity_type={entity_type}")]
    EntityNotAPerson { entity_id: i64, entity_type: String },

    // ─── Persons — identifiers (migration 0004) ──────────────────────────────

    #[error("person identifier not found: identifier_id={identifier_id}")]
    PersonIdentifierNotFound { identifier_id: i64 },

    // ─── Businesses — identifiers (migration 0005) ──────────────────────────

    #[error("entity is not a business: entity_id={entity_id}, entity_type={entity_type}")]
    EntityNotABusiness { entity_id: i64, entity_type: String },

    #[error("business identifier not found: identifier_id={identifier_id}")]
    BusinessIdentifierNotFound { identifier_id: i64 },

    // ─── Businesses — logo upload ─────────────────────────────────────────

    #[error("business logo too large: size={size} bytes exceeds limit={limit} bytes")]
    BusinessLogoTooLarge { size: u64, limit: u64 },

    #[error("business logo is not an image: detected={detected}")]
    BusinessLogoNotAnImage { detected: String },

    // ─── Phase 3b: reports ───────────────────────────────────────────────────

    #[error("report generation failed: {reason}")]
    ReportGenerationFailed { reason: String },

    // ─── Phase 5: network / Agent Zero / SMTP / drives ───────────────────────

    /// SEC-5 MUST-DO 5: non-loopback bind refused without explicit opt-in.
    #[error("network bind refused for host '{bind_host}': set allow_network_bind = true to allow")]
    NetworkBindRefused { bind_host: String },

    /// SEC-4 MUST-DO 6: Agent Zero URL not on the allowlist.
    #[error("Agent Zero URL rejected: '{url}'")]
    AgentZeroUrlRejected { url: String },

    /// Agent Zero not configured (URL or key missing).
    #[error("Agent Zero is not configured")]
    AgentZeroNotConfigured,

    /// Agent Zero request timed out.
    #[error("Agent Zero request to '{endpoint}' timed out after {seconds}s")]
    AgentZeroTimeout { endpoint: String, seconds: u64 },

    /// Agent Zero returned a non-2xx HTTP status.
    #[error("Agent Zero server error {status}: {message}")]
    AgentZeroServerError { status: u16, message: String },

    /// Response body exceeded the per-endpoint cap (MUST-DO 7).
    #[error("response payload too large: exceeded {limit} byte limit")]
    PayloadTooLarge { limit: usize },

    /// SEC-4 MUST-DO 8: one-time consent gate for ai_summarize_case.
    #[error("AI summarize consent required")]
    AiSummarizeConsentRequired,

    /// One-time consent gate for Agent Zero OSINT runs against a person.
    /// Separate from the case-summary consent because OSINT sends PII to
    /// external sources and is meaningfully more invasive.
    #[error("AI OSINT consent required")]
    AiOsintConsentRequired,

    /// The investigator enabled `tor_enabled` in Agent Zero settings, but
    /// the container does not have a reachable Tor daemon. Surfaced from
    /// the Agent Zero plugin's preflight check so the investigator sees
    /// a specific error message instead of a silent OSINT no-op or a
    /// generic timeout. Fix: verify `tor` + `torsocks` are installed and
    /// the `tor` service is running inside the Kali container.
    #[error("Tor daemon is not reachable inside the Agent Zero container")]
    TorUnavailable,

    /// SMTP connection failed.
    #[error("SMTP connection failed: {reason}")]
    SmtpConnectFailed { reason: String },

    /// SMTP send failed.
    #[error("SMTP send failed: {reason}")]
    SmtpSendFailed { reason: String },

    /// Drive scan exceeded the file-count limit.
    #[error("drive scan aborted: file_count={file_count} exceeded limit={limit}")]
    DriveScanTooLarge { file_count: u64, limit: u64 },
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
