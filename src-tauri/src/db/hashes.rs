/// Hash verification database queries — Phase 3a.
///
/// Manages the `hash_verification` table: add (append-only) and list.
///
/// No delete — once a hash is recorded it is part of the evidentiary trail.
/// Matches v1 behavior (v1's add_hash_verification uses INSERT OR REPLACE, but
/// there is no delete endpoint in v1's routes.py).
///
/// Public surface:
///   - `add_hash`          — INSERT with full validation
///   - `list_for_evidence` — ordered by verification_datetime ASC
///   - `list_for_case`     — JOIN against evidence; ordered by evidence_id, datetime
///
/// Validation:
///   - algorithm allowlist: MD5 | SHA1 | SHA256 | SHA512 | SHA3-256 | SHA3-512
///   - hash_value: hex string, lowercased server-side, exact expected length per algorithm
///   - verified_by: required, max 100 chars
use chrono::NaiveDateTime;
use serde::{Deserialize, Serialize};
use sqlx::SqlitePool;

use crate::error::AppError;

// ─── Validation constants ────────────────────────────────────────────────────

/// Allowed algorithms and their expected hex-encoded output lengths.
const ALGORITHM_LENGTHS: &[(&str, usize)] = &[
    ("MD5", 32),
    ("SHA1", 40),
    ("SHA256", 64),
    ("SHA512", 128),
    ("SHA3-256", 64),
    ("SHA3-512", 128),
];

const VERIFIED_BY_MAX_LEN: usize = 100;

// ─── Public data types ────────────────────────────────────────────────────────

/// Full hash verification row, maps 1:1 to the `hash_verification` table.
/// `verification_datetime` is a `String` for v1 compat — see `db::cases::Case`.
#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct HashRecord {
    pub hash_id: i64,
    pub evidence_id: String,
    pub algorithm: String,
    pub hash_value: String,
    pub verified_by: String,
    pub verification_datetime: String,
    pub notes: Option<String>,
}

/// Writable fields for recording a new hash.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HashInput {
    pub algorithm: String,
    pub hash_value: String,
    pub verified_by: String,
    pub verification_datetime: NaiveDateTime,
    pub notes: Option<String>,
}

// ─── Validation helpers ───────────────────────────────────────────────────────

/// Validate hash algorithm and value.
///
/// - Normalises hash_value to lowercase.
/// - Checks that the algorithm is in the allowlist.
/// - Checks that the hex string has the exact expected length.
/// - Rejects any non-hex characters.
///
/// Returns the normalised (lowercased) hash value on success.
pub(crate) fn validate_hash(algorithm: &str, hash_value: &str) -> Result<String, AppError> {
    // Find expected length
    let expected_len = ALGORITHM_LENGTHS
        .iter()
        .find(|(alg, _)| *alg == algorithm)
        .map(|(_, len)| *len)
        .ok_or_else(|| AppError::ValidationError {
            field: "algorithm".into(),
            message: format!(
                "algorithm must be one of: {}",
                ALGORITHM_LENGTHS
                    .iter()
                    .map(|(a, _)| *a)
                    .collect::<Vec<_>>()
                    .join(", ")
            ),
        })?;

    let normalised = hash_value.to_lowercase();

    // Check length
    if normalised.len() != expected_len {
        return Err(AppError::ValidationError {
            field: "hash_value".into(),
            message: format!(
                "{algorithm} must be {expected_len} hex chars, got {}",
                normalised.len()
            ),
        });
    }

    // Check all chars are hex
    if !normalised.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(AppError::ValidationError {
            field: "hash_value".into(),
            message: format!("{algorithm} hash_value must contain only hex characters (0-9, a-f)"),
        });
    }

    Ok(normalised)
}

/// Validate verified_by field.
fn validate_verified_by(verified_by: &str) -> Result<(), AppError> {
    if verified_by.is_empty() {
        return Err(AppError::ValidationError {
            field: "verified_by".into(),
            message: "verified_by must not be empty".into(),
        });
    }
    if verified_by.len() > VERIFIED_BY_MAX_LEN {
        return Err(AppError::ValidationError {
            field: "verified_by".into(),
            message: format!("verified_by must not exceed {VERIFIED_BY_MAX_LEN} characters"),
        });
    }
    Ok(())
}

// ─── Public query functions ───────────────────────────────────────────────────

/// Add a new hash verification record.
///
/// `hash_value` is lowercased server-side before storage, even if the client
/// sends uppercase hex characters.
pub async fn add_hash(
    pool: &SqlitePool,
    evidence_id: &str,
    input: &HashInput,
) -> Result<HashRecord, AppError> {
    let normalised_hash = validate_hash(&input.algorithm, &input.hash_value)?;
    validate_verified_by(&input.verified_by)?;

    let row_id = sqlx::query(
        r#"
        INSERT INTO hash_verification (
            evidence_id, algorithm, hash_value, verified_by,
            verification_datetime, notes
        ) VALUES (?, ?, ?, ?, ?, ?)
        "#,
    )
    .bind(evidence_id)
    .bind(&input.algorithm)
    .bind(&normalised_hash)
    .bind(&input.verified_by)
    .bind(input.verification_datetime)
    .bind(&input.notes)
    .execute(pool)
    .await?
    .last_insert_rowid();

    let record = sqlx::query_as::<_, HashRecord>(
        r#"
        SELECT
            hash_id, evidence_id, algorithm, hash_value,
            verified_by, verification_datetime, notes
        FROM hash_verification
        WHERE hash_id = ?
        "#,
    )
    .bind(row_id)
    .fetch_one(pool)
    .await?;

    Ok(record)
}

/// List all hash records for a specific evidence item,
/// ordered by verification_datetime ASC.
pub async fn list_for_evidence(
    pool: &SqlitePool,
    evidence_id: &str,
) -> Result<Vec<HashRecord>, AppError> {
    let rows = sqlx::query_as::<_, HashRecord>(
        r#"
        SELECT
            hash_id, evidence_id, algorithm, hash_value,
            verified_by, verification_datetime, notes
        FROM hash_verification
        WHERE evidence_id = ?
        ORDER BY verification_datetime ASC
        "#,
    )
    .bind(evidence_id)
    .fetch_all(pool)
    .await?;
    Ok(rows)
}

/// List all hash records for a case, aggregated across all evidence items.
///
/// JOINs against evidence to identify items belonging to the case.
/// Ordered by evidence_id, verification_datetime.
pub async fn list_for_case(
    pool: &SqlitePool,
    case_id: &str,
) -> Result<Vec<HashRecord>, AppError> {
    let rows = sqlx::query_as::<_, HashRecord>(
        r#"
        SELECT
            h.hash_id, h.evidence_id, h.algorithm, h.hash_value,
            h.verified_by, h.verification_datetime, h.notes
        FROM hash_verification h
        INNER JOIN evidence e ON h.evidence_id = e.evidence_id
        WHERE e.case_id = ?
        ORDER BY h.evidence_id, h.verification_datetime ASC
        "#,
    )
    .bind(case_id)
    .fetch_all(pool)
    .await?;
    Ok(rows)
}

// ─── Inline unit tests ────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::validate_hash;
    use crate::error::AppError;

    // Reference valid hashes for each algorithm (all lowercase hex)
    const VALID_MD5: &str = "d41d8cd98f00b204e9800998ecf8427e"; // 32 chars
    const VALID_SHA1: &str = "da39a3ee5e6b4b0d3255bfef95601890afd80709"; // 40 chars
    const VALID_SHA256: &str =
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"; // 64 chars
    const VALID_SHA512: &str =
        "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce\
         47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e"; // 128 chars
    const VALID_SHA3_256: &str =
        "a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a"; // 64 chars
    const VALID_SHA3_512: &str =
        "a69f73cca23a9ac5c8b567dc185a756e97c982164fe25859e0d1dcc1475c80a6\
         15b2123af1f5f94c11e3e9402c3ac558f500199d95b6d3e301758586281dcd26"; // 128 chars

    #[test]
    fn test_valid_hashes() {
        assert!(validate_hash("MD5", VALID_MD5).is_ok());
        assert!(validate_hash("SHA1", VALID_SHA1).is_ok());
        assert!(validate_hash("SHA256", VALID_SHA256).is_ok());
        assert!(validate_hash("SHA512", VALID_SHA512).is_ok());
        assert!(validate_hash("SHA3-256", VALID_SHA3_256).is_ok());
        assert!(validate_hash("SHA3-512", VALID_SHA3_512).is_ok());
    }

    #[test]
    fn test_uppercase_normalised() {
        let upper = VALID_SHA256.to_uppercase();
        let result = validate_hash("SHA256", &upper).unwrap();
        assert_eq!(result, VALID_SHA256, "uppercase input must be lowercased");
    }

    #[test]
    fn test_wrong_length_sha256() {
        // 50 hex chars instead of 64
        let short = "a".repeat(50);
        let err = validate_hash("SHA256", &short).unwrap_err();
        assert!(
            matches!(err, AppError::ValidationError { ref field, .. } if field == "hash_value"),
            "expected ValidationError on hash_value, got: {err:?}"
        );
    }

    #[test]
    fn test_non_hex_chars() {
        // 32 chars but contains 'g'
        let bad = "d41d8cd98f00b204e9800998ecf8427g";
        let err = validate_hash("MD5", bad).unwrap_err();
        assert!(
            matches!(err, AppError::ValidationError { ref field, .. } if field == "hash_value"),
            "expected ValidationError on hash_value, got: {err:?}"
        );
    }

    #[test]
    fn test_unknown_algorithm() {
        let err = validate_hash("BLAKE2b", VALID_SHA256).unwrap_err();
        assert!(
            matches!(err, AppError::ValidationError { ref field, .. } if field == "algorithm"),
            "expected ValidationError on algorithm, got: {err:?}"
        );
    }

    #[test]
    fn test_md5_wrong_length() {
        // MD5 is 32; giving a SHA256 (64 chars)
        let err = validate_hash("MD5", VALID_SHA256).unwrap_err();
        assert!(
            matches!(err, AppError::ValidationError { ref field, .. } if field == "hash_value")
        );
    }
}
