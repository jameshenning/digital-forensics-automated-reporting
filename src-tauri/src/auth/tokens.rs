/// API bearer token management.
///
/// Token format: `"dfars_"` + URL-safe base64 of 32 random bytes.
/// The `dfars_` prefix matches v1 and enables GitHub / etc. secret scanning.
///
/// Storage: Argon2id hash + first 12 chars of plaintext (`token_preview`).
///
/// Verification fast path (SEC-1 SHOULD-DO 4):
///   The `token_preview` column holds the first 12 plaintext chars, already
///   displayed in the management UI.  We use it to do an indexed lookup
///   (O(1)) before running the expensive Argon2 verification, reducing
///   Argon2 calls from O(n tokens) to O(1) regardless of token count.
///
/// Timing-oracle invariant (SEC-5 MUST-DO 1):
///   Both the "no preview match" and "wrong hash" code paths must take
///   approximately equal time (~100ms, the Argon2 verify cost).  This is
///   enforced by `dummy_verify`: callers (axum middleware) MUST call it
///   whenever they would otherwise return early without running Argon2.
///   See `bearer_auth_middleware` in `axum_server.rs` for usage.
///
/// ISOLATION INVARIANT (SEC-5 MUST-DO 2):
///   Session tokens (`sess_...`, in-memory only) and API bearer tokens
///   (`dfars_...`, persisted in `api_tokens`) are STRICTLY DISJOINT.
///   - An API bearer token MUST NEVER be inserted into the session HashMap.
///   - A session token MUST NEVER be stored in `api_tokens`.
///   Tests for both directions live in `tests/phase5_network_integration.rs`.
use sqlx::SqlitePool;
use tracing::info;
use zeroize::Zeroizing;

use crate::auth::argon;
use crate::error::AppError;
use crate::state::AppState;

const TOKEN_PREFIX: &str = "dfars_";
const TOKEN_BYTES: usize = 32;
const PREVIEW_LEN: usize = 12;

// ─── Token generation ────────────────────────────────────────────────────────

fn generate_plaintext() -> Zeroizing<String> {
    use rand::RngCore;
    use base64::Engine as _;
    let mut bytes = [0u8; TOKEN_BYTES];
    rand::rngs::OsRng.fill_bytes(&mut bytes);
    let encoded = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes);
    Zeroizing::new(format!("{TOKEN_PREFIX}{encoded}"))
}

// ─── Publicly-visible list item ──────────────────────────────────────────────

#[derive(Debug, serde::Serialize)]
pub struct ApiTokenListItem {
    pub id: i64,
    pub name: String,
    pub token_preview: String,
    pub created_at: Option<String>,
    pub last_used_at: Option<String>,
}

/// Returned by `create()` — the plaintext is shown to the user exactly once.
#[derive(Debug, serde::Serialize)]
pub struct NewToken {
    pub id: i64,
    pub name: String,
    pub plaintext: String,
    pub token_preview: String,
}

/// Create a new API token for `user_id`.  Returns `NewToken` including the
/// plaintext (caller MUST display it and discard it — never stored again).
pub async fn create(pool: &SqlitePool, user_id: i64, name: &str) -> Result<NewToken, AppError> {
    let name = name.trim();
    if name.is_empty() {
        return Err(AppError::PasswordPolicy("Token name is required.".into()));
    }
    if name.len() > 100 {
        return Err(AppError::PasswordPolicy("Token name too long (max 100 chars).".into()));
    }

    let plaintext = generate_plaintext();
    let token_hash = argon::hash_secret(&plaintext)?;
    let preview = &plaintext[..PREVIEW_LEN];

    let id = sqlx::query(
        "INSERT INTO api_tokens (user_id, name, token_hash, token_preview) VALUES (?, ?, ?, ?)"
    )
    .bind(user_id)
    .bind(name)
    .bind(&token_hash)
    .bind(preview)
    .execute(pool)
    .await?
    .last_insert_rowid();

    info!(token_id = id, name = %name, "API token created");

    Ok(NewToken {
        id,
        name: name.to_owned(),
        plaintext: plaintext.to_string(),
        token_preview: preview.to_owned(),
    })
}

/// List all tokens for a user (no plaintext or hash exposed).
pub async fn list_for_user(pool: &SqlitePool, user_id: i64) -> Result<Vec<ApiTokenListItem>, AppError> {
    use sqlx::Row;

    let rows = sqlx::query(
        "SELECT id, name, token_preview, created_at, last_used_at
           FROM api_tokens
          WHERE user_id = ?
          ORDER BY created_at DESC"
    )
    .bind(user_id)
    .fetch_all(pool)
    .await?;

    rows.iter().map(|row| {
        Ok(ApiTokenListItem {
            id: row.try_get("id")?,
            name: row.try_get("name")?,
            token_preview: row.try_get("token_preview")?,
            created_at: row.try_get("created_at")?,
            last_used_at: row.try_get("last_used_at")?,
        })
    }).collect()
}

/// Revoke a token by ID.  The `user_id` guard prevents cross-user revocation.
/// Returns `Ok(true)` if a row was deleted.
pub async fn revoke(pool: &SqlitePool, token_id: i64, user_id: i64) -> Result<bool, AppError> {
    let rows_affected = sqlx::query(
        "DELETE FROM api_tokens WHERE id = ? AND user_id = ?"
    )
    .bind(token_id)
    .bind(user_id)
    .execute(pool)
    .await?
    .rows_affected();

    if rows_affected > 0 {
        info!(token_id, "API token revoked");
    }
    Ok(rows_affected > 0)
}

// ─── Verification (bearer auth) ──────────────────────────────────────────────

/// Verify a plaintext bearer token.
///
/// Fast path (SEC-1 SHOULD-DO 4): the `token_preview` (first 12 chars of
/// plaintext) is used as a DB lookup key.  This reduces Argon2 calls to O(1)
/// regardless of how many tokens the user has.
///
/// Returns the token row joined with `username` on success, `None` on failure.
/// Used by the axum REST server in Phase 5.
#[allow(dead_code)]
pub async fn verify(pool: &SqlitePool, plaintext: &str) -> Result<Option<VerifiedToken>, AppError> {
    use sqlx::Row;

    if !plaintext.starts_with(TOKEN_PREFIX) {
        return Ok(None);
    }
    if plaintext.len() < PREVIEW_LEN {
        return Ok(None);
    }

    let preview = &plaintext[..PREVIEW_LEN];

    // Fast-path indexed lookup by preview.
    let row = sqlx::query(
        "SELECT t.id, t.user_id, t.name, t.token_hash, t.token_preview
           FROM api_tokens t
          WHERE t.token_preview = ?"
    )
    .bind(preview)
    .fetch_optional(pool)
    .await?;

    let row = match row {
        Some(r) => r,
        None => {
            // MUST-DO 1 (SEC-5): Run a dummy Argon2 verify so the no-match path
            // takes ~100ms (same as the real Argon2 verify below), eliminating
            // the timing oracle that distinguishes "no preview match" (~µs) from
            // "wrong hash" (~100ms).  Callers must NOT short-circuit before this.
            // See also: `dummy_verify()` called from `bearer_auth_middleware`.
            let _ = argon::verify_password("dummy-plaintext-does-not-match", &_dummy_placeholder());
            return Ok(None);
        }
    };

    let token_hash: String = row.try_get("token_hash")?;
    let token_id: i64 = row.try_get("id")?;
    let user_id: i64 = row.try_get("user_id")?;
    let name: String = row.try_get("name")?;

    // Argon2 verification.
    if !argon::verify_secret(plaintext, &token_hash)? {
        return Ok(None);
    }

    // Update last_used_at.
    let now = chrono::Utc::now().format("%Y-%m-%dT%H:%M:%S").to_string();
    sqlx::query("UPDATE api_tokens SET last_used_at = ? WHERE id = ?")
        .bind(&now)
        .bind(token_id)
        .execute(pool)
        .await?;

    // Fetch the username for the caller.
    let user_row = sqlx::query("SELECT username FROM users WHERE id = ?")
        .bind(user_id)
        .fetch_one(pool)
        .await?;
    let username: String = user_row.try_get("username")?;

    Ok(Some(VerifiedToken {
        token_id,
        user_id,
        name,
        username,
    }))
}

#[derive(Debug, Clone)]
pub struct VerifiedToken {
    pub token_id: i64,
    pub user_id: i64,
    pub name: String,
    pub username: String,
}

// ─── Timing-oracle mitigation helpers (SEC-5 MUST-DO 1) ─────────────────────

/// Run a dummy Argon2 verify against the app's pre-computed dummy hash.
///
/// Called by `bearer_auth_middleware` whenever a token prefix is invalid
/// (e.g. `sess_...`) so that the rejection path is not measurably faster
/// than the "no preview match" path.
///
/// Invariant: this function must execute a full Argon2 verify and take
/// approximately the same time as a real token verification failure.
pub async fn dummy_verify(state: &AppState) {
    // Use the dummy hash from AppState so we don't need to call hash() here.
    let _ = argon::verify_password("dummy-plaintext-timing-guard", &state.dummy_hash);
}

/// Internal placeholder — returns a valid Argon2 PHC hash of a dummy secret.
/// Used inside `verify()` for the no-preview-match path.
fn _dummy_placeholder() -> String {
    // This is intentionally pre-computed at call time using the cheaper
    // `make_dummy_hash()` function. In practice the axum middleware calls
    // `dummy_verify(state)` which uses the AppState.dummy_hash instead, so
    // this path only fires if verify() is called directly.
    argon::make_dummy_hash()
}
