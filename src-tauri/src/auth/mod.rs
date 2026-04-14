/// Auth module — argon2, TOTP, sessions, recovery codes, API tokens, lockout.
///
/// Public sub-modules:
///   - `argon`    — password hashing + verification (Argon2id)
///   - `totp`     — TOTP enrollment + verification (RFC 6238 SHA-1)
///   - `recovery` — one-time recovery code generation + verification
///   - `lockout`  — monotonic in-memory lockout tracker (MUST-DO 2)
///   - `session`  — in-memory session store + `require_session()` guard
///   - `tokens`   — API bearer token management
pub mod argon;
pub mod lockout;
pub mod recovery;
pub mod session;
pub mod tokens;
pub mod totp;

use sqlx::SqlitePool;
use tracing::info;

use crate::crypto::CryptoState;
use crate::error::AppError;

// ─── Validation constants (mirroring v1's auth.py) ────────────────────────────

pub const MIN_USERNAME_LEN: usize = 3;
pub const MAX_USERNAME_LEN: usize = 64;
pub const MIN_PASSWORD_LEN: usize = argon::MIN_PASSWORD_LEN; // 10
pub const MAX_PASSWORD_LEN: usize = argon::MAX_PASSWORD_LEN; // 1024
#[allow(dead_code)]
pub const MAX_FAILED_ATTEMPTS: u32 = lockout::MAX_FAILED_ATTEMPTS; // 5

// ─── Validation helpers ───────────────────────────────────────────────────────

/// Validate and normalise a username.  Mirrors v1's `_validate_username()`.
pub fn validate_username(username: &str) -> Result<String, AppError> {
    let u = username.trim().to_owned();
    if u.is_empty() {
        return Err(AppError::PasswordPolicy("Username is required.".into()));
    }
    if u.len() < MIN_USERNAME_LEN {
        return Err(AppError::PasswordPolicy(format!(
            "Username must be at least {MIN_USERNAME_LEN} characters."
        )));
    }
    if u.len() > MAX_USERNAME_LEN {
        return Err(AppError::PasswordPolicy(
            "Username is too long (max 64 characters).".into(),
        ));
    }
    if !u.chars().all(|c| c.is_alphanumeric() || "._-".contains(c)) {
        return Err(AppError::PasswordPolicy(
            "Username may only contain letters, digits, '.', '_', or '-'.".into(),
        ));
    }
    Ok(u)
}

/// Validate a password.  Mirrors v1's `_validate_password()`.
pub fn validate_password(password: &str) -> Result<(), AppError> {
    if password.len() < MIN_PASSWORD_LEN {
        return Err(AppError::PasswordPolicy(format!(
            "Password must be at least {MIN_PASSWORD_LEN} characters."
        )));
    }
    if password.len() > MAX_PASSWORD_LEN {
        return Err(AppError::PasswordPolicy("Password is too long.".into()));
    }
    Ok(())
}

// ─── User row struct ─────────────────────────────────────────────────────────

/// Mirrors the `users` table row.
#[derive(Debug, Clone, serde::Serialize)]
pub struct UserRow {
    pub id: i64,
    pub username: String,
    #[serde(skip)]
    pub password_hash: String,
    pub created_at: Option<String>,
    pub last_login: Option<String>,
    pub failed_login_count: i64,
    pub locked_until: Option<String>,
    pub mfa_enabled: i64,
    #[serde(skip)]
    pub totp_secret: Option<String>,
    pub mfa_enrolled_at: Option<String>,
}

impl UserRow {
    pub fn mfa_active(&self) -> bool {
        self.mfa_enabled != 0 && self.totp_secret.is_some()
    }
}

fn row_to_user(row: &sqlx::sqlite::SqliteRow) -> Result<UserRow, sqlx::Error> {
    use sqlx::Row;
    Ok(UserRow {
        id: row.try_get("id")?,
        username: row.try_get("username")?,
        password_hash: row.try_get("password_hash")?,
        created_at: row.try_get("created_at")?,
        last_login: row.try_get("last_login")?,
        failed_login_count: row.try_get("failed_login_count")?,
        locked_until: row.try_get("locked_until")?,
        mfa_enabled: row.try_get("mfa_enabled")?,
        totp_secret: row.try_get("totp_secret")?,
        mfa_enrolled_at: row.try_get("mfa_enrolled_at")?,
    })
}

// ─── DB helper queries ────────────────────────────────────────────────────────

/// Check if any user exists (used to gate first-run setup).
pub async fn user_exists(pool: &SqlitePool) -> Result<bool, AppError> {
    use sqlx::Row;
    let row = sqlx::query("SELECT COUNT(*) as cnt FROM users")
        .fetch_one(pool)
        .await?;
    let cnt: i64 = row.try_get("cnt")?;
    Ok(cnt > 0)
}

/// Fetch a user by username, returning `None` if not found.
pub async fn get_user(pool: &SqlitePool, username: &str) -> Result<Option<UserRow>, AppError> {
    let row = sqlx::query(
        "SELECT id, username, password_hash, created_at, last_login,
                failed_login_count, locked_until, mfa_enabled, totp_secret, mfa_enrolled_at
           FROM users WHERE username = ?"
    )
    .bind(username)
    .fetch_optional(pool)
    .await?;
    row.map(|r| row_to_user(&r).map_err(AppError::from)).transpose()
}

/// Fetch a user by numeric ID.
#[allow(dead_code)]
pub async fn get_user_by_id(pool: &SqlitePool, user_id: i64) -> Result<Option<UserRow>, AppError> {
    let row = sqlx::query(
        "SELECT id, username, password_hash, created_at, last_login,
                failed_login_count, locked_until, mfa_enabled, totp_secret, mfa_enrolled_at
           FROM users WHERE id = ?"
    )
    .bind(user_id)
    .fetch_optional(pool)
    .await?;
    row.map(|r| row_to_user(&r).map_err(AppError::from)).transpose()
}

// ─── Create user ──────────────────────────────────────────────────────────────

/// Create the single application user.  Refuses if any user already exists.
/// Returns the new user's ID.
pub async fn create_user(
    pool: &SqlitePool,
    username: &str,
    password: &str,
) -> Result<i64, AppError> {
    if user_exists(pool).await? {
        return Err(AppError::UserAlreadyExists);
    }

    let username = validate_username(username)?;
    validate_password(password)?;

    let hash = argon::hash_password(password)?;

    let id = sqlx::query(
        "INSERT INTO users (username, password_hash) VALUES (?, ?)"
    )
    .bind(&username)
    .bind(&hash)
    .execute(pool)
    .await
    .map_err(|e: sqlx::Error| {
        if e.to_string().contains("UNIQUE") {
            AppError::UserAlreadyExists
        } else {
            AppError::Db(e.to_string())
        }
    })?
    .last_insert_rowid();

    info!(username = %username, "user account created");
    Ok(id)
}

// ─── Password verification ────────────────────────────────────────────────────

/// Verify credentials.  On success, returns the fresh UserRow.
/// Integrates with the in-memory lockout map.
pub async fn verify_credentials(
    pool: &SqlitePool,
    lockout: &lockout::LockoutMap,
    dummy_hash: &str,
    username: &str,
    password: &str,
) -> Result<UserRow, AppError> {
    let user_opt = get_user(pool, username).await?;

    if user_opt.is_none() {
        // Constant-time guard — run Argon2 anyway so the caller can't distinguish
        // "user not found" from "wrong password" by timing.
        let _ = argon::verify_password(password, dummy_hash);
        return Err(AppError::InvalidCredentials);
    }

    let user = user_opt.unwrap();

    // Check lockout using the monotonic in-memory map (MUST-DO 2).
    lockout.check(&user.username)?;

    match argon::verify_password(password, &user.password_hash)? {
        true => {
            lockout.clear_on_success(&user.username);
            lockout::persist_success(pool, &user.username).await?;
            let fresh = get_user(pool, username)
                .await?
                .ok_or(AppError::UserNotFound)?;
            Ok(fresh)
        }
        false => {
            let info = lockout.register_failure(&user.username);
            let (count, locked_until) = lockout.get_count_for_db(&user.username);
            lockout::persist_to_db(pool, &user.username, count, locked_until).await?;

            if let Some(li) = info {
                return Err(AppError::AccountLocked {
                    seconds_remaining: li.seconds_remaining,
                });
            }
            Err(AppError::InvalidCredentials)
        }
    }
}

// ─── Password change ─────────────────────────────────────────────────────────

pub async fn update_password(
    pool: &SqlitePool,
    lockout: &lockout::LockoutMap,
    dummy_hash: &str,
    username: &str,
    current_password: &str,
    new_password: &str,
) -> Result<(), AppError> {
    verify_credentials(pool, lockout, dummy_hash, username, current_password).await?;
    validate_password(new_password)?;

    let new_hash = argon::hash_password(new_password)?;
    sqlx::query("UPDATE users SET password_hash = ? WHERE username = ?")
        .bind(&new_hash)
        .bind(username)
        .execute(pool)
        .await?;

    info!(username = %username, "password updated");
    Ok(())
}

// ─── MFA helpers ──────────────────────────────────────────────────────────────

/// Encrypt and persist a TOTP secret after the user confirms enrollment.
pub async fn enable_mfa(
    pool: &SqlitePool,
    crypto: &CryptoState,
    username: &str,
    secret_b32: &str,
) -> Result<(), AppError> {
    let encrypted = crypto.encrypt(secret_b32.as_bytes());
    let now = chrono::Utc::now().format("%Y-%m-%dT%H:%M:%S").to_string();
    sqlx::query(
        "UPDATE users SET totp_secret = ?, mfa_enabled = 1, mfa_enrolled_at = ? WHERE username = ?"
    )
    .bind(&encrypted)
    .bind(&now)
    .bind(username)
    .execute(pool)
    .await?;
    info!(username = %username, "MFA enabled");
    Ok(())
}

/// Disable MFA and revoke all recovery codes (requires password re-entry).
pub async fn disable_mfa(
    pool: &SqlitePool,
    lockout: &lockout::LockoutMap,
    dummy_hash: &str,
    _crypto: &CryptoState,
    username: &str,
    current_password: &str,
) -> Result<(), AppError> {
    verify_credentials(pool, lockout, dummy_hash, username, current_password).await?;

    let user = get_user(pool, username)
        .await?
        .ok_or(AppError::UserNotFound)?;

    sqlx::query(
        "UPDATE users SET totp_secret = NULL, mfa_enabled = 0, mfa_enrolled_at = NULL WHERE username = ?"
    )
    .bind(username)
    .execute(pool)
    .await?;

    recovery::revoke_all(pool, user.id).await?;

    info!(username = %username, "MFA disabled");
    Ok(())
}

/// Decrypt and return the TOTP Base32 secret for a user.
pub async fn get_totp_secret(
    pool: &SqlitePool,
    crypto: &CryptoState,
    username: &str,
) -> Result<Option<String>, AppError> {
    let user = match get_user(pool, username).await? {
        Some(u) => u,
        None => return Ok(None),
    };
    let encrypted = match user.totp_secret {
        Some(e) => e,
        None => return Ok(None),
    };
    match crypto.decrypt(&encrypted) {
        Ok(bytes) => {
            let secret = String::from_utf8(bytes)
                .map_err(|_| AppError::Crypto("TOTP secret is not valid UTF-8".into()))?;
            Ok(Some(secret))
        }
        Err(_) => {
            tracing::warn!(
                username = %username,
                "Failed to decrypt TOTP secret — key may have been rotated"
            );
            Ok(None)
        }
    }
}

/// Count unused recovery codes for a user.
pub async fn remaining_recovery_codes(pool: &SqlitePool, username: &str) -> Result<u32, AppError> {
    let user = match get_user(pool, username).await? {
        Some(u) => u,
        None => return Ok(0),
    };
    recovery::remaining(pool, user.id).await
}
