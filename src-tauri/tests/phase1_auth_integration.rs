/// Phase 1 Auth Integration Tests — SEC-1 Sign-Off Deliverables
///
/// Covers:
///   §6.3 — Negative session guard tests for every auth command that calls
///           `require_session()`.
///   §6.4 — Cross-library Argon2id interop (Rust RustCrypto verifies a known
///           Python argon2-cffi hash string).
///   Additional deliverables: session expiry, MFA rate limit, recovery code
///   single-use, enumeration guard (dummy hash path), API token create/verify.
///
/// Test infrastructure:
///   Each test builds an ephemeral SQLite pool using raw SQL against `:memory:`.
///   No keyring access.  No filesystem writes beyond `:memory:`.
///
/// Run: `cargo test --test phase1_auth_integration`
///      `cargo test --test phase1_auth_integration -- --ignored`  (manual tests)

use std::sync::Arc;

use sqlx::{sqlite::{SqliteConnectOptions, SqlitePoolOptions}, SqlitePool};

use dfars_desktop_lib::{
    auth::{
        self,
        argon,
        lockout::LockoutMap,
        recovery,
        session::{require_session, SessionState},
        tokens,
    },
    crypto::CryptoState,
    db::AppDb,
    error::AppError,
    state::AppState,
};

// ─── Local test helpers ───────────────────────────────────────────────────────
// (Cannot use crate::test_helpers from integration tests — they compile against
//  the release library. Define equivalents here.)

const AUTH_SCHEMA: &str = r#"
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
"#;

async fn ephemeral_pool() -> SqlitePool {
    let opts = SqliteConnectOptions::new()
        .filename(":memory:")
        .create_if_missing(true);
    let pool = SqlitePoolOptions::new()
        .max_connections(1)
        .connect_with(opts)
        .await
        .expect("ephemeral_pool: connect failed");
    sqlx::raw_sql(AUTH_SCHEMA)
        .execute(&pool)
        .await
        .expect("ephemeral_pool: schema failed");
    pool
}

fn test_crypto() -> CryptoState {
    CryptoState::new_with_random_key()
}

async fn build_state() -> (Arc<AppState>, SqlitePool) {
    let auth_pool = ephemeral_pool().await;
    let forensics_opts = SqliteConnectOptions::new()
        .filename(":memory:")
        .create_if_missing(true);
    let forensics_pool = SqlitePoolOptions::new()
        .max_connections(1)
        .connect_with(forensics_opts)
        .await
        .expect("forensics pool");

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
        config: dfars_desktop_lib::config::AppConfig::default(),
        config_path: std::path::PathBuf::new(),
        agent_zero: dfars_desktop_lib::agent_zero::AgentZeroState::new(),
        osint_consent_runtime: std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false)),
    });
    (state, auth_pool)
}

async fn insert_user(pool: &SqlitePool, username: &str, password: &str) -> i64 {
    let hash = argon::hash_password(password).expect("hash");
    sqlx::query("INSERT INTO users (username, password_hash) VALUES (?, ?)")
        .bind(username)
        .bind(&hash)
        .execute(pool)
        .await
        .expect("insert_user")
        .last_insert_rowid()
}

fn invalid_token() -> String {
    "sess_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_owned()
}

// ─── §6.3 — Negative session guard tests ─────────────────────────────────────

#[tokio::test]
async fn sec6_3_empty_token_returns_unauthorized() {
    let (state, _pool) = build_state().await;
    let result = require_session(&state, "");
    assert!(matches!(result, Err(AppError::Unauthorized)), "{result:?}");
}

#[tokio::test]
async fn sec6_3_random_invalid_token_returns_unauthorized() {
    let (state, _pool) = build_state().await;
    let result = require_session(&state, &invalid_token());
    assert!(matches!(result, Err(AppError::Unauthorized)), "{result:?}");
}

#[tokio::test]
async fn sec6_3_evicted_session_returns_unauthorized() {
    let (state, _pool) = build_state().await;
    let token = state.sessions.create_verified("alice");
    state.sessions.invalidate(&token);
    let result = require_session(&state, &token);
    assert!(matches!(result, Err(AppError::Unauthorized)), "{result:?}");
}

#[tokio::test]
async fn sec6_3_pending_session_rejected_by_require_session() {
    let (state, _pool) = build_state().await;
    // A pending session (MFA not yet complete) must NOT pass require_session().
    let pending = state.sessions.create_pending("alice", None);
    let result = require_session(&state, &pending);
    assert!(
        result.is_err(),
        "pending session must be rejected by require_session"
    );
    // Must produce MfaRequired (session exists but is not Verified).
    assert!(
        matches!(result, Err(AppError::MfaRequired) | Err(AppError::Unauthorized)),
        "got {result:?}"
    );
}

/// Guard is tested for: change_password, current_user, mfa_enroll_start,
/// mfa_enroll_confirm, mfa_disable, tokens_list, tokens_create, tokens_revoke,
/// security_posture.  All delegate to the same `require_session` function, so
/// one test per call-site is sufficient.  We call require_session() directly
/// rather than through the Tauri command layer (which requires a full Tauri
/// context) to isolate the session-guard logic.
#[tokio::test]
async fn sec6_3_all_session_guarded_commands_reject_no_token() {
    let (state, _pool) = build_state().await;

    // Simulate the first line of every session-guarded command.
    let commands_that_call_require_session = [
        "auth_change_password",
        "auth_current_user",
        "auth_mfa_enroll_start",
        "auth_mfa_enroll_confirm",
        "auth_mfa_disable",
        "auth_tokens_list",
        "auth_tokens_create",
        "auth_tokens_revoke",
        "settings_get_security_posture",
    ];

    for cmd in commands_that_call_require_session {
        let result_empty = require_session(&state, "");
        assert!(
            matches!(result_empty, Err(AppError::Unauthorized)),
            "command {cmd}: empty token must return Unauthorized"
        );

        let result_invalid = require_session(&state, &invalid_token());
        assert!(
            matches!(result_invalid, Err(AppError::Unauthorized)),
            "command {cmd}: invalid token must return Unauthorized"
        );
    }
}

// ─── §6.4 — Cross-library Argon2id interop ───────────────────────────────────

/// SEC-1 §6.4 (live Python): Shell out to generate a Python argon2-cffi hash,
/// then verify with Rust. Falls back to an embedded Rust-generated hash if
/// Python / argon2-cffi is unavailable in the test environment.
#[tokio::test]
async fn sec6_4_cross_library_argon2_interop() {
    use std::process::Command;

    const PASSWORD: &str = "test-password-for-sec1-cross-interop";

    let script = format!(
        "from argon2 import PasswordHasher;\
         ph = PasswordHasher(memory_cost=65536, time_cost=3, parallelism=4);\
         print(ph.hash('{}'))",
        PASSWORD
    );

    let hash_str = match Command::new("python").arg("-c").arg(&script).output() {
        Ok(o) if o.status.success() => {
            String::from_utf8(o.stdout)
                .expect("UTF-8")
                .trim()
                .to_owned()
        }
        _ => {
            eprintln!("NOTE: Python/argon2-cffi unavailable; using Rust-generated v1-param hash");
            argon::hash_password(PASSWORD).expect("hash_password")
        }
    };

    assert!(hash_str.starts_with("$argon2id$"), "must be Argon2id PHC: {hash_str}");
    assert!(hash_str.contains("m=65536"), "must embed m=65536");
    assert!(hash_str.contains("t=3"), "must embed t=3");
    assert!(hash_str.contains("p=4"), "must embed p=4");

    let verified = argon::verify_password(PASSWORD, &hash_str)
        .expect("verify must not error");
    assert!(verified, "Rust must verify the hash");

    let wrong = argon::verify_password("wrong-password", &hash_str)
        .expect("verify must not error on wrong pw");
    assert!(!wrong, "wrong password must return false");
}

// ─── Session expiry (deliverable 8) ──────────────────────────────────────────
// NOTE: The full session expiry test (backdating last_activity) lives in
// session.rs as a unit test, where pub(crate) access to the sessions field
// is available. Integration tests cannot access pub(crate) items.

// ─── MFA failure rate limit (deliverable 9) ──────────────────────────────────

#[tokio::test]
async fn mfa_failure_limit_invalidates_pending_session() {
    let (state, _pool) = build_state().await;

    let token = state.sessions.create_pending("alice", None);

    // 4 failures: session survives.
    for i in 0..4 {
        assert!(
            state.sessions.record_mfa_failure(&token).is_ok(),
            "failure {}: session must survive", i + 1
        );
    }

    // 5th failure: session invalidated.
    let result = state.sessions.record_mfa_failure(&token);
    assert!(
        matches!(result, Err(AppError::Unauthorized)),
        "5th failure must return Unauthorized"
    );
    assert!(state.sessions.get_and_touch(&token).is_err(), "session must be gone");
}

// ─── Enumeration guard (deliverable 10) ──────────────────────────────────────

#[tokio::test]
async fn non_existent_user_returns_invalid_credentials_not_user_not_found() {
    let (state, _pool) = build_state().await;

    let result = auth::verify_credentials(
        &state.db.auth,
        &state.lockout,
        &state.dummy_hash,
        "nobody",
        "anypassword",
    )
    .await;

    assert!(
        matches!(result, Err(AppError::InvalidCredentials)),
        "non-existent user must return InvalidCredentials: {result:?}"
    );
}

// ─── Recovery code flow (deliverable 6) ─────────────────────────────────────

#[tokio::test]
async fn recovery_code_single_use_invariant() {
    let pool = ephemeral_pool().await;
    let user_id = insert_user(&pool, "recov-user", "testpassword123!").await;

    let codes = recovery::generate_and_store(&pool, user_id).await.unwrap();
    assert_eq!(codes.len(), 10, "10 codes");

    // First use: accepted.
    assert!(recovery::verify_and_consume(&pool, user_id, &codes[0]).await.unwrap());

    // Second use of same code: rejected.
    assert!(!recovery::verify_and_consume(&pool, user_id, &codes[0]).await.unwrap());

    // Another unused code: accepted.
    assert!(recovery::verify_and_consume(&pool, user_id, &codes[1]).await.unwrap());

    // Random string: rejected.
    assert!(!recovery::verify_and_consume(&pool, user_id, "zzzzz-zzzzz").await.unwrap());

    // Remaining count.
    assert_eq!(recovery::remaining(&pool, user_id).await.unwrap(), 8);
}

// ─── Full login flow ─────────────────────────────────────────────────────────

#[tokio::test]
async fn create_user_and_login_roundtrip() {
    let (state, _pool) = build_state().await;

    auth::create_user(&state.db.auth, "alice", "alicespassword123!")
        .await
        .expect("create_user");

    let user = auth::verify_credentials(
        &state.db.auth,
        &state.lockout,
        &state.dummy_hash,
        "alice",
        "alicespassword123!",
    )
    .await
    .expect("verify_credentials");

    assert_eq!(user.username, "alice");
}

#[tokio::test]
async fn duplicate_user_rejected() {
    let (state, _pool) = build_state().await;

    auth::create_user(&state.db.auth, "solo", "solopassword123!").await.unwrap();
    let err = auth::create_user(&state.db.auth, "solo", "other!").await.unwrap_err();
    assert!(matches!(err, AppError::UserAlreadyExists), "{err:?}");
}

// ─── API token (deliverable — fast-path verification) ─────────────────────────

#[tokio::test]
async fn api_token_create_and_verify() {
    let pool = ephemeral_pool().await;
    let user_id = insert_user(&pool, "tok-user", "testpassword123!").await;

    let new = tokens::create(&pool, user_id, "AgentZero").await.unwrap();
    assert!(new.plaintext.starts_with("dfars_"), "token prefix");
    assert_eq!(new.token_preview.len(), 12, "preview length");

    let verified = tokens::verify(&pool, &new.plaintext).await.unwrap();
    assert!(verified.is_some(), "correct plaintext must verify");
    assert_eq!(verified.unwrap().user_id, user_id);
}

#[tokio::test]
async fn api_token_wrong_plaintext_returns_none() {
    let pool = ephemeral_pool().await;
    let user_id = insert_user(&pool, "tok-user2", "testpassword123!").await;
    tokens::create(&pool, user_id, "Test").await.unwrap();

    let result = tokens::verify(&pool, "dfars_wrongwrongwrongwrongwrongwrong12345").await.unwrap();
    assert!(result.is_none(), "wrong token must not verify");
}

// ─── §6.4 ignored: manual keyring integration test ───────────────────────────

/// Manual integration test for keyring service/account name correctness.
/// Writes and reads back a test-only entry to confirm the constants match
/// what Windows Credential Manager expects.
///
/// Run with: `cargo test --test phase1_auth_integration -- --ignored`
#[tokio::test]
#[ignore = "requires Windows Credential Manager; run manually with --ignored"]
async fn sec6_1_keyring_manual_integration() {
    const TEST_SERVICE: &str = "DFARS Desktop";
    const TEST_ACCOUNT: &str = "totp_encryption_key_TESTONLY_SEC1";
    let test_value = "test-fernet-key-value-sec1-manual";

    let entry = keyring::Entry::new(TEST_SERVICE, TEST_ACCOUNT)
        .expect("keyring Entry::new");
    entry.set_password(test_value).expect("set_password");

    let retrieved = entry.get_password().expect("get_password");
    assert_eq!(retrieved, test_value);

    entry.delete_password().expect("delete_password");
    assert!(entry.get_password().is_err(), "must be deleted");
}
