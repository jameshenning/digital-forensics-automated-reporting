/// One-time recovery codes for MFA fallback.
///
/// Each code format: two 5-char hex groups separated by a hyphen — "xxxxx-xxxxx".
/// This exactly matches v1's `_format_recovery_code()`:
///   `secrets.token_hex(3)[:5] + "-" + secrets.token_hex(3)[:5]`
/// 3 bytes = 6 hex chars, truncated to 5.  40 bits total entropy per code.
///
/// Each code is Argon2id-hashed with v1-compatible parameters before storage.
/// Verification iterates unused codes, Argon2-verifies each, marks used on match.
///
/// SEC-1 SHOULD-DO 2: MFA failure counter lives in session (see session.rs).
use sqlx::SqlitePool;
use tracing::warn;

use crate::auth::argon;
use crate::error::AppError;

const RECOVERY_CODE_COUNT: usize = 10;
const GROUP_LEN: usize = 5;

// ─── Code generation ─────────────────────────────────────────────────────────

/// Generate a single `xxxxx-xxxxx` hex recovery code.
fn format_recovery_code() -> String {
    use rand::RngCore;
    let mut buf = [0u8; 4];
    rand::rngs::OsRng.fill_bytes(&mut buf);
    let hex1 = hex_encode(&buf[..3]);
    let mut buf2 = [0u8; 4];
    rand::rngs::OsRng.fill_bytes(&mut buf2);
    let hex2 = hex_encode(&buf2[..3]);
    format!("{}-{}", &hex1[..GROUP_LEN], &hex2[..GROUP_LEN])
}

fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// Normalise a code for comparison: lowercase + remove whitespace.
/// Mirrors v1's `_normalize_recovery_code()`.
fn normalize(code: &str) -> String {
    code.chars()
        .filter(|c| !c.is_whitespace())
        .map(|c| c.to_ascii_lowercase())
        .collect()
}

/// Generate 10 recovery codes, hash them, delete old ones, insert new ones.
/// Returns the plaintext codes — these are the ONLY time they are visible.
pub async fn generate_and_store(
    pool: &SqlitePool,
    user_id: i64,
) -> Result<Vec<String>, AppError> {
    let codes: Vec<String> = (0..RECOVERY_CODE_COUNT)
        .map(|_| format_recovery_code())
        .collect();

    let hashes: Vec<String> = codes
        .iter()
        .map(|c| argon::hash_secret(&normalize(c)))
        .collect::<Result<Vec<_>, _>>()?;

    // Revoke all prior codes for this user, then insert the new batch.
    sqlx::query("DELETE FROM recovery_codes WHERE user_id = ?")
        .bind(user_id)
        .execute(pool)
        .await?;

    for hash in &hashes {
        sqlx::query("INSERT INTO recovery_codes (user_id, code_hash) VALUES (?, ?)")
            .bind(user_id)
            .bind(hash)
            .execute(pool)
            .await?;
    }

    Ok(codes)
}

/// Count unused recovery codes remaining for the user.
pub async fn remaining(pool: &SqlitePool, user_id: i64) -> Result<u32, AppError> {
    use sqlx::Row;
    let row = sqlx::query(
        "SELECT COUNT(*) as cnt FROM recovery_codes WHERE user_id = ? AND used_at IS NULL"
    )
    .bind(user_id)
    .fetch_one(pool)
    .await?;
    let cnt: i64 = row.try_get("cnt")?;
    Ok(cnt as u32)
}

/// Verify a plaintext recovery code and consume it (mark used_at) if valid.
///
/// Returns `Ok(true)` on a match, `Ok(false)` on no match.
/// Returns `Err(AppError::NoRecoveryCodesRemaining)` if all codes are used.
pub async fn verify_and_consume(
    pool: &SqlitePool,
    user_id: i64,
    code_plaintext: &str,
) -> Result<bool, AppError> {
    use sqlx::Row;

    let cleaned = normalize(code_plaintext);
    if cleaned.is_empty() {
        return Ok(false);
    }

    let rows = sqlx::query(
        "SELECT id, code_hash FROM recovery_codes WHERE user_id = ? AND used_at IS NULL"
    )
    .bind(user_id)
    .fetch_all(pool)
    .await?;

    if rows.is_empty() {
        return Err(AppError::NoRecoveryCodesRemaining);
    }

    for row in &rows {
        let id: i64 = row.try_get("id")?;
        let code_hash: String = row.try_get("code_hash")?;

        match argon::verify_secret(&cleaned, &code_hash) {
            Ok(true) => {
                // Match — mark as used.
                let now = chrono::Utc::now().format("%Y-%m-%dT%H:%M:%S").to_string();
                sqlx::query("UPDATE recovery_codes SET used_at = ? WHERE id = ?")
                    .bind(now)
                    .bind(id)
                    .execute(pool)
                    .await?;
                return Ok(true);
            }
            Ok(false) => continue,
            Err(e) => {
                warn!("recovery code hash parse error for id={id}: {e}");
                continue;
            }
        }
    }

    Ok(false)
}

/// Delete all recovery codes for the user (called on MFA disable / re-enroll).
pub async fn revoke_all(pool: &SqlitePool, user_id: i64) -> Result<(), AppError> {
    sqlx::query("DELETE FROM recovery_codes WHERE user_id = ?")
        .bind(user_id)
        .execute(pool)
        .await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn format_produces_correct_shape() {
        let code = format_recovery_code();
        let parts: Vec<&str> = code.split('-').collect();
        assert_eq!(parts.len(), 2, "should have exactly one hyphen");
        assert_eq!(parts[0].len(), GROUP_LEN);
        assert_eq!(parts[1].len(), GROUP_LEN);
        for ch in code.chars().filter(|c| *c != '-') {
            assert!(ch.is_ascii_hexdigit(), "char '{ch}' should be hex");
        }
    }

    #[test]
    fn normalize_strips_spaces_and_lowercases() {
        assert_eq!(normalize("  AB CDE-FGHIJ  "), "abcde-fghij");
    }

    #[test]
    fn generate_ten_unique_codes() {
        let codes: Vec<_> = (0..10).map(|_| format_recovery_code()).collect();
        let unique: std::collections::HashSet<_> = codes.iter().collect();
        assert_eq!(unique.len(), 10);
    }
}
