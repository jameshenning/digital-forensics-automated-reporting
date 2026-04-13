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

use crate::{
    auth::lockout::LockoutMap,
    auth::session::SessionState,
    auth::argon,
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
async fn test_forensics_db() -> SqlitePool {
    let opts = SqliteConnectOptions::new()
        .filename(":memory:")
        .create_if_missing(true);

    SqlitePoolOptions::new()
        .max_connections(1)
        .connect_with(opts)
        .await
        .expect("test_forensics_db: failed to open :memory: pool")
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
    let forensics_pool = test_forensics_db().await;

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
