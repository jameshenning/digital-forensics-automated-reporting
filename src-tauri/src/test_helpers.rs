//! Test helpers — ephemeral DB builder and shared utilities.
//!
//! This module is compiled only under `#[cfg(test)]`. It provides:
//!   - `test_auth_db()` — an ephemeral in-memory SQLite pool with the auth
//!     schema applied, ready for use in unit and integration tests.
//!   - `build_test_state()` — a minimal AppState wired to an ephemeral auth DB
//!     with a freshly-generated Fernet key (no keyring needed in tests).
//!
//! Usage in any `#[cfg(test)]` block:
//! ```ignore
//! use crate::test_helpers::{test_auth_db, build_test_state};
//! ```
#![allow(dead_code, unused_imports)] // helpers may be unused by the current test set but are kept for future phases

use std::sync::Arc;

use sqlx::{sqlite::{SqliteConnectOptions, SqlitePoolOptions}, SqlitePool};

use std::path::PathBuf;

use crate::{
    agent_zero::AgentZeroState,
    auth::lockout::LockoutMap,
    auth::session::SessionState,
    auth::argon,
    config::AppConfig,
    crypto::CryptoState,
    db::AppDb,
    state::AppState,
};

/// Create an ephemeral in-memory SQLite pool with the auth schema migrated.
///
/// Each call returns an independent pool — tests do not share state.
pub async fn test_auth_db() -> SqlitePool {
    let opts = SqliteConnectOptions::new()
        .filename(":memory:")
        .create_if_missing(true);

    let pool = SqlitePoolOptions::new()
        .max_connections(1)
        .connect_with(opts)
        .await
        .expect("test_auth_db: failed to open :memory: pool");

    // Apply the auth schema directly (same DDL as migrations/auth/0001_init.sql).
    // Using a literal here avoids a dependency on sqlx::migrate! in test context.
    sqlx::raw_sql(
        r#"
        PRAGMA foreign_keys = ON;

        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            last_login TIMESTAMP,
            failed_login_count INTEGER NOT NULL DEFAULT 0,
            locked_until TIMESTAMP,
            mfa_enabled INTEGER NOT NULL DEFAULT 0,
            totp_secret TEXT,
            mfa_enrolled_at TIMESTAMP
        );

        CREATE TABLE IF NOT EXISTS recovery_codes (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            code_hash TEXT NOT NULL,
            used_at TIMESTAMP,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
        );

        CREATE INDEX IF NOT EXISTS idx_recovery_codes_user_id ON recovery_codes(user_id);
        CREATE INDEX IF NOT EXISTS idx_users_username ON users(username);

        CREATE TABLE IF NOT EXISTS api_tokens (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            name TEXT NOT NULL,
            token_hash TEXT NOT NULL,
            token_preview TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            last_used_at TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
        );

        CREATE INDEX IF NOT EXISTS idx_api_tokens_user_id ON api_tokens(user_id);
        "#,
    )
    .execute(&pool)
    .await
    .expect("test_auth_db: failed to apply auth schema");

    pool
}

/// Also create a minimal forensics pool (empty schema) so AppDb can be constructed.
async fn test_forensics_db_empty() -> SqlitePool {
    let opts = SqliteConnectOptions::new()
        .filename(":memory:")
        .create_if_missing(true);

    SqlitePoolOptions::new()
        .max_connections(1)
        .connect_with(opts)
        .await
        .expect("test_forensics_db_empty: failed to open :memory: pool")
}

// The full forensics DDL (verbatim copy of migrations/forensics/0001_init.sql)
// used by Phase 2+ integration tests.
pub const FORENSICS_SCHEMA: &str = r#"
PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS cases (
    case_id TEXT PRIMARY KEY,
    case_name TEXT NOT NULL,
    description TEXT,
    investigator TEXT NOT NULL,
    agency TEXT,
    start_date DATE NOT NULL,
    end_date DATE,
    status TEXT DEFAULT 'Active',
    priority TEXT DEFAULT 'Medium',
    classification TEXT,
    evidence_drive_path TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS evidence (
    evidence_id TEXT PRIMARY KEY,
    case_id TEXT NOT NULL,
    description TEXT NOT NULL,
    collected_by TEXT NOT NULL,
    collection_datetime TIMESTAMP NOT NULL,
    location TEXT,
    status TEXT DEFAULT 'Collected',
    evidence_type TEXT,
    make_model TEXT,
    serial_number TEXT,
    storage_location TEXT,
    FOREIGN KEY (case_id) REFERENCES cases (case_id) ON DELETE RESTRICT
);

CREATE TABLE IF NOT EXISTS hash_verification (
    hash_id INTEGER PRIMARY KEY AUTOINCREMENT,
    evidence_id TEXT NOT NULL,
    algorithm TEXT NOT NULL,
    hash_value TEXT NOT NULL,
    verified_by TEXT NOT NULL,
    verification_datetime TIMESTAMP NOT NULL,
    notes TEXT,
    FOREIGN KEY (evidence_id) REFERENCES evidence (evidence_id) ON DELETE RESTRICT
);

CREATE TABLE IF NOT EXISTS chain_of_custody (
    custody_id INTEGER PRIMARY KEY AUTOINCREMENT,
    evidence_id TEXT NOT NULL,
    custody_sequence INTEGER NOT NULL,
    action TEXT NOT NULL,
    from_party TEXT NOT NULL,
    to_party TEXT NOT NULL,
    location TEXT,
    custody_datetime TIMESTAMP NOT NULL,
    purpose TEXT,
    notes TEXT,
    FOREIGN KEY (evidence_id) REFERENCES evidence (evidence_id) ON DELETE RESTRICT
);

CREATE TABLE IF NOT EXISTS tool_usage (
    tool_id INTEGER PRIMARY KEY AUTOINCREMENT,
    case_id TEXT NOT NULL,
    evidence_id TEXT,
    tool_name TEXT NOT NULL,
    version TEXT,
    purpose TEXT NOT NULL,
    command_used TEXT,
    input_file TEXT,
    output_file TEXT,
    execution_datetime TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    operator TEXT NOT NULL,
    -- migration 0003: tool reproduction fields
    input_sha256 TEXT,
    output_sha256 TEXT,
    environment_notes TEXT,
    reproduction_notes TEXT,
    FOREIGN KEY (case_id) REFERENCES cases (case_id) ON DELETE RESTRICT
);

CREATE INDEX IF NOT EXISTS idx_tool_evidence_id ON tool_usage(evidence_id);

CREATE TABLE IF NOT EXISTS analysis_notes (
    note_id INTEGER PRIMARY KEY AUTOINCREMENT,
    case_id TEXT NOT NULL,
    evidence_id TEXT,
    category TEXT NOT NULL,
    finding TEXT NOT NULL,
    description TEXT,
    confidence_level TEXT DEFAULT 'Medium',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (case_id) REFERENCES cases (case_id) ON DELETE RESTRICT,
    FOREIGN KEY (evidence_id) REFERENCES evidence (evidence_id) ON DELETE SET NULL
);

CREATE TABLE IF NOT EXISTS case_tags (
    tag_id INTEGER PRIMARY KEY AUTOINCREMENT,
    case_id TEXT NOT NULL,
    tag TEXT NOT NULL,
    FOREIGN KEY (case_id) REFERENCES cases (case_id) ON DELETE RESTRICT,
    UNIQUE(case_id, tag)
);

CREATE TABLE IF NOT EXISTS report_templates (
    template_id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    description TEXT,
    template_content TEXT NOT NULL,
    format_type TEXT DEFAULT 'markdown',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_evidence_case_id ON evidence(case_id);
CREATE INDEX IF NOT EXISTS idx_hash_evidence_id ON hash_verification(evidence_id);
CREATE INDEX IF NOT EXISTS idx_custody_evidence_id ON chain_of_custody(evidence_id);
CREATE INDEX IF NOT EXISTS idx_tool_case_id ON tool_usage(case_id);
CREATE INDEX IF NOT EXISTS idx_analysis_case_id ON analysis_notes(case_id);
CREATE INDEX IF NOT EXISTS idx_tags_case_id ON case_tags(case_id);

CREATE TABLE IF NOT EXISTS entities (
    entity_id INTEGER PRIMARY KEY AUTOINCREMENT,
    case_id TEXT NOT NULL,
    entity_type TEXT NOT NULL,
    display_name TEXT NOT NULL,
    subtype TEXT,
    organizational_rank TEXT,
    parent_entity_id INTEGER,
    notes TEXT,
    metadata_json TEXT,
    is_deleted INTEGER DEFAULT 0,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    -- migration 0002: person sub-type columns
    photo_path TEXT,
    email TEXT,
    phone TEXT,
    username TEXT,
    employer TEXT,
    dob TEXT,
    FOREIGN KEY (case_id) REFERENCES cases (case_id) ON DELETE RESTRICT,
    FOREIGN KEY (parent_entity_id) REFERENCES entities (entity_id) ON DELETE SET NULL
);

CREATE INDEX IF NOT EXISTS idx_entities_case ON entities(case_id);
CREATE INDEX IF NOT EXISTS idx_entities_case_type ON entities(case_id, entity_type);
CREATE INDEX IF NOT EXISTS idx_entities_parent ON entities(parent_entity_id);

-- migration 0004: person_identifiers (+ 0006 discovered_via_tool)
CREATE TABLE IF NOT EXISTS person_identifiers (
    identifier_id INTEGER PRIMARY KEY AUTOINCREMENT,
    entity_id INTEGER NOT NULL,
    kind TEXT NOT NULL,
    value TEXT NOT NULL,
    platform TEXT,
    notes TEXT,
    discovered_via_tool TEXT,
    is_deleted INTEGER DEFAULT 0,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (entity_id) REFERENCES entities (entity_id) ON DELETE RESTRICT
);

CREATE INDEX IF NOT EXISTS idx_person_identifiers_entity
    ON person_identifiers(entity_id, is_deleted);
CREATE INDEX IF NOT EXISTS idx_person_identifiers_kind
    ON person_identifiers(entity_id, kind, is_deleted);
CREATE INDEX IF NOT EXISTS idx_person_identifiers_discovered_via_tool
    ON person_identifiers(discovered_via_tool);

-- migration 0005: business_identifiers (+ 0006 discovered_via_tool)
CREATE TABLE IF NOT EXISTS business_identifiers (
    identifier_id INTEGER PRIMARY KEY AUTOINCREMENT,
    entity_id INTEGER NOT NULL,
    kind TEXT NOT NULL,
    value TEXT NOT NULL,
    platform TEXT,
    notes TEXT,
    discovered_via_tool TEXT,
    is_deleted INTEGER DEFAULT 0,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (entity_id) REFERENCES entities (entity_id) ON DELETE RESTRICT
);

CREATE INDEX IF NOT EXISTS idx_business_identifiers_entity
    ON business_identifiers(entity_id, is_deleted);
CREATE INDEX IF NOT EXISTS idx_business_identifiers_kind
    ON business_identifiers(entity_id, kind, is_deleted);
CREATE INDEX IF NOT EXISTS idx_business_identifiers_discovered_via_tool
    ON business_identifiers(discovered_via_tool);

CREATE TABLE IF NOT EXISTS entity_links (
    link_id INTEGER PRIMARY KEY AUTOINCREMENT,
    case_id TEXT NOT NULL,
    source_type TEXT NOT NULL,
    source_id TEXT NOT NULL,
    target_type TEXT NOT NULL,
    target_id TEXT NOT NULL,
    link_label TEXT,
    directional INTEGER DEFAULT 1,
    weight REAL DEFAULT 1.0,
    notes TEXT,
    is_deleted INTEGER DEFAULT 0,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (case_id) REFERENCES cases (case_id) ON DELETE RESTRICT
);

CREATE TABLE IF NOT EXISTS case_events (
    event_id INTEGER PRIMARY KEY AUTOINCREMENT,
    case_id TEXT NOT NULL,
    title TEXT NOT NULL,
    description TEXT,
    event_datetime TIMESTAMP NOT NULL,
    event_end_datetime TIMESTAMP,
    category TEXT,
    related_entity_id INTEGER,
    related_evidence_id TEXT,
    is_deleted INTEGER DEFAULT 0,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (case_id) REFERENCES cases (case_id) ON DELETE RESTRICT,
    FOREIGN KEY (related_entity_id) REFERENCES entities (entity_id) ON DELETE SET NULL,
    FOREIGN KEY (related_evidence_id) REFERENCES evidence (evidence_id) ON DELETE SET NULL
);

CREATE TABLE IF NOT EXISTS evidence_files (
    file_id INTEGER PRIMARY KEY AUTOINCREMENT,
    evidence_id TEXT NOT NULL,
    original_filename TEXT NOT NULL,
    stored_path TEXT NOT NULL,
    sha256 TEXT NOT NULL,
    size_bytes INTEGER NOT NULL,
    mime_type TEXT,
    metadata_json TEXT,
    is_deleted INTEGER DEFAULT 0,
    uploaded_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (evidence_id) REFERENCES evidence (evidence_id) ON DELETE RESTRICT
);

CREATE TABLE IF NOT EXISTS evidence_analyses (
    analysis_id INTEGER PRIMARY KEY AUTOINCREMENT,
    evidence_id TEXT NOT NULL,
    osint_narrative TEXT,
    files_snapshot_json TEXT,
    report_markdown TEXT,
    tools_used TEXT,
    platforms_used TEXT,
    status TEXT DEFAULT 'completed',
    error_message TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (evidence_id) REFERENCES evidence (evidence_id) ON DELETE RESTRICT
);

CREATE TABLE IF NOT EXISTS case_shares (
    share_id INTEGER PRIMARY KEY AUTOINCREMENT,
    case_id TEXT NOT NULL,
    record_type TEXT NOT NULL,
    record_id TEXT NOT NULL,
    record_summary TEXT,
    action TEXT NOT NULL,
    recipient TEXT,
    file_path TEXT,
    file_hash TEXT NOT NULL,
    narrative TEXT NOT NULL,
    shared_by TEXT NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (case_id) REFERENCES cases (case_id) ON DELETE RESTRICT
);
"#;

/// Create an ephemeral in-memory forensics pool with the full forensics schema applied.
///
/// Used by Phase 2+ integration tests.  Each call returns an independent pool.
pub async fn test_forensics_db_with_schema() -> SqlitePool {
    let opts = SqliteConnectOptions::new()
        .filename(":memory:")
        .create_if_missing(true);

    let pool = SqlitePoolOptions::new()
        .max_connections(1)
        .connect_with(opts)
        .await
        .expect("test_forensics_db_with_schema: failed to open :memory: pool");

    sqlx::raw_sql(FORENSICS_SCHEMA)
        .execute(&pool)
        .await
        .expect("test_forensics_db_with_schema: failed to apply forensics schema");

    pool
}

/// Build a test CryptoState with a freshly-generated Fernet key.
/// This does NOT touch Windows Credential Manager.
pub fn test_crypto() -> CryptoState {
    CryptoState::new_with_random_key()
}

/// Build a complete AppState suitable for integration tests.
///
/// Returns `(Arc<AppState>, SqlitePool)` — the pool is the auth pool so tests
/// can run raw SQL assertions against it.
pub async fn build_test_state() -> (Arc<AppState>, SqlitePool) {
    let auth_pool = test_auth_db().await;
    let forensics_pool = test_forensics_db_empty().await;

    let db = AppDb {
        forensics: forensics_pool,
        auth: auth_pool.clone(),
    };

    let crypto = test_crypto();
    let dummy_hash = argon::make_dummy_hash();

    let state = Arc::new(AppState {
        db,
        crypto,
        lockout: LockoutMap::new(),
        sessions: SessionState::new(),
        dummy_hash,
        config: AppConfig::default(),
        config_path: PathBuf::new(),
        agent_zero: AgentZeroState::new(),
        osint_consent_runtime: std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false)),
    });

    (state, auth_pool)
}

/// Insert a test user directly into the DB. Returns the user's id.
pub async fn insert_test_user(
    pool: &SqlitePool,
    username: &str,
    password_hash: &str,
) -> i64 {
    sqlx::query(
        "INSERT INTO users (username, password_hash) VALUES (?, ?)"
    )
    .bind(username)
    .bind(password_hash)
    .execute(pool)
    .await
    .expect("insert_test_user: INSERT failed")
    .last_insert_rowid()
}

/// Insert a test user with a known password. Returns the user's id.
pub async fn insert_user_with_password(
    pool: &SqlitePool,
    username: &str,
    password: &str,
) -> i64 {
    let hash = argon::hash_password(password).expect("hash must not fail");
    insert_test_user(pool, username, &hash).await
}
