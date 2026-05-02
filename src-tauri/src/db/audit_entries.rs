/// Hash-chained audit log — database layer (migration 0010).
///
/// Every entry carries a SHA-256 that incorporates the previous entry's hash,
/// producing a tamper-evident chain. The genesis entry uses "GENESIS" as
/// prev_hash.
///
/// Public surface:
///   - `add_entry`      — INSERT with hash computation
///   - `list_for_case`  — ordered chronologically for a given case
///   - `list_all`       — global audit tail (for auth events or cross-case review)
///   - `verify_chain`   — validate every entry_hash and linkage
///
/// The hash payload format is stable and documented so `dfars-verify`
/// can recompute independently:
///   SHA-256("{prev_hash}:{timestamp}:{actor}:{action}:{details}")
///
/// Colons are used as delimiters because the pipe (`|`) appears in the
/// legacy flat-file format; keeping them distinct prevents confusion.

use serde::{Deserialize, Serialize};
use sqlx::SqlitePool;

use crate::error::AppError;

// ─── Public data types ────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct AuditEntry {
    pub entry_id: i64,
    pub case_id: Option<String>,
    pub timestamp: String,
    pub actor: String,
    pub action: String,
    pub details: Option<String>,
    pub prev_hash: String,
    pub entry_hash: String,
}

/// Audit entry with the associated case name for display purposes.
#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct AuditEntryWithCaseName {
    pub entry_id: i64,
    pub case_id: Option<String>,
    pub case_name: Option<String>,
    pub timestamp: String,
    pub actor: String,
    pub action: String,
    pub details: Option<String>,
    pub prev_hash: String,
    pub entry_hash: String,
}

/// Input for writing a new audit entry.
#[derive(Debug, Clone)]
pub struct AuditEntryInput {
    pub case_id: Option<String>,
    pub actor: String,
    pub action: String,
    pub details: Option<String>,
}

// ─── Hash chain helpers ───────────────────────────────────────────────────────

/// Compute the SHA-256 hex digest for an audit entry.
///
/// Format (stable, versioned by this comment):
///   payload = "{prev_hash}:{timestamp}:{actor}:{action}:{details}"
///
/// `details` is omitted from the payload when None, producing a trailing
/// colon (which is still part of the signed payload).
pub fn compute_entry_hash(prev_hash: &str, timestamp: &str, actor: &str, action: &str, details: Option<&str>) -> String {
    use sha2::{Sha256, Digest};
    let payload = match details {
        Some(d) => format!("{prev_hash}:{timestamp}:{actor}:{action}:{d}"),
        None => format!("{prev_hash}:{timestamp}:{actor}:{action}:"),
    };
    let hash = Sha256::digest(payload.as_bytes());
    data_encoding::HEXLOWER.encode(&hash)
}

/// Fetch the latest entry_hash for a given case (or global when case_id=None).
/// Returns "GENESIS" when no prior entry exists.
async fn fetch_prev_hash(pool: &SqlitePool, case_id: Option<&str>) -> Result<String, sqlx::Error> {
    let last: Option<(String,)> = match case_id {
        Some(cid) => {
            sqlx::query_as("SELECT entry_hash FROM audit_entries WHERE case_id = ? ORDER BY entry_id DESC LIMIT 1")
                .bind(cid)
                .fetch_optional(pool)
                .await?
        }
        None => {
            sqlx::query_as("SELECT entry_hash FROM audit_entries WHERE case_id IS NULL ORDER BY entry_id DESC LIMIT 1")
                .fetch_optional(pool)
                .await?
        }
    };
    Ok(last.map(|r| r.0).unwrap_or_else(|| "GENESIS".to_string()))
}

// ─── Public query functions ───────────────────────────────────────────────────

/// Append a new audit entry to the hash chain.
///
/// The timestamp is captured at insert time (UTC, microsecond precision).
/// The hash is computed from the prev_hash (looked up) + the captured
/// timestamp + actor + action + details.
pub async fn add_entry(
    pool: &SqlitePool,
    input: &AuditEntryInput,
) -> Result<AuditEntry, AppError> {
    let timestamp = chrono::Utc::now().format("%Y-%m-%dT%H:%M:%S%.6f").to_string();
    let prev_hash = fetch_prev_hash(pool, input.case_id.as_deref()).await
        .map_err(|e| AppError::Db(e.to_string()))?;

    let entry_hash = compute_entry_hash(
        &prev_hash,
        &timestamp,
        &input.actor,
        &input.action,
        input.details.as_deref(),
    );

    let row_id = sqlx::query(
        r#"
        INSERT INTO audit_entries (case_id, timestamp, actor, action, details, prev_hash, entry_hash)
        VALUES (?, ?, ?, ?, ?, ?, ?)
        "#,
    )
    .bind(&input.case_id)
    .bind(&timestamp)
    .bind(&input.actor)
    .bind(&input.action)
    .bind(&input.details)
    .bind(&prev_hash)
    .bind(&entry_hash)
    .execute(pool)
    .await
    .map_err(|e| AppError::Db(e.to_string()))?
    .last_insert_rowid();

    let entry = sqlx::query_as::<_, AuditEntry>(
        r#"
        SELECT entry_id, case_id, timestamp, actor, action, details, prev_hash, entry_hash
        FROM audit_entries
        WHERE entry_id = ?
        "#,
    )
    .bind(row_id)
    .fetch_one(pool)
    .await
    .map_err(|e| AppError::Db(e.to_string()))?;

    Ok(entry)
}

/// List audit entries for a case, ordered chronologically (entry_id ASC).
pub async fn list_for_case(
    pool: &SqlitePool,
    case_id: &str,
) -> Result<Vec<AuditEntry>, AppError> {
    let rows = sqlx::query_as::<_, AuditEntry>(
        r#"
        SELECT entry_id, case_id, timestamp, actor, action, details, prev_hash, entry_hash
        FROM audit_entries
        WHERE case_id = ?
        ORDER BY entry_id ASC
        "#,
    )
    .bind(case_id)
    .fetch_all(pool)
    .await
    .map_err(|e| AppError::Db(e.to_string()))?;
    Ok(rows)
}

/// List global (case_id IS NULL) audit entries, ordered chronologically.
pub async fn list_global(
    pool: &SqlitePool,
) -> Result<Vec<AuditEntry>, AppError> {
    let rows = sqlx::query_as::<_, AuditEntry>(
        r#"
        SELECT entry_id, case_id, timestamp, actor, action, details, prev_hash, entry_hash
        FROM audit_entries
        WHERE case_id IS NULL
        ORDER BY entry_id ASC
        "#,
    )
    .fetch_all(pool)
    .await
    .map_err(|e| AppError::Db(e.to_string()))?;
    Ok(rows)
}

/// List the most recent audit entries across all cases, ordered newest first.
pub async fn list_recent(
    pool: &SqlitePool,
    limit: i64,
) -> Result<Vec<AuditEntryWithCaseName>, AppError> {
    let rows = sqlx::query_as::<_, AuditEntryWithCaseName>(
        r#"
        SELECT
            ae.entry_id,
            ae.case_id,
            c.case_name,
            ae.timestamp,
            ae.actor,
            ae.action,
            ae.details,
            ae.prev_hash,
            ae.entry_hash
        FROM audit_entries ae
        LEFT JOIN cases c ON ae.case_id = c.case_id
        ORDER BY ae.entry_id DESC
        LIMIT ?
        "#,
    )
    .bind(limit)
    .fetch_all(pool)
    .await
    .map_err(|e| AppError::Db(e.to_string()))?;
    Ok(rows)
}

/// Verify the integrity of an audit chain.
///
/// Returns `Ok(())` if every entry's hash recomputes correctly and every
/// prev_hash links to the preceding entry's entry_hash. Returns
/// `Err(AppError::ValidationError)` with a descriptive message on the first
/// break in the chain.
pub fn verify_chain(entries: &[AuditEntry]) -> Result<(), AppError> {
    for window in entries.windows(2) {
        let prev = &window[0];
        let curr = &window[1];

        if curr.prev_hash != prev.entry_hash {
            return Err(AppError::ValidationError {
                field: "audit_chain".into(),
                message: format!(
                    "chain break at entry_id {}: prev_hash ({}) does not match previous entry_hash ({})",
                    curr.entry_id, curr.prev_hash, prev.entry_hash
                ),
            });
        }
    }

    for entry in entries {
        let recomputed = compute_entry_hash(
            &entry.prev_hash,
            &entry.timestamp,
            &entry.actor,
            &entry.action,
            entry.details.as_deref(),
        );
        if recomputed != entry.entry_hash {
            return Err(AppError::ValidationError {
                field: "audit_entry_hash".into(),
                message: format!(
                    "hash mismatch at entry_id {}: stored={} recomputed={}",
                    entry.entry_id, entry.entry_hash, recomputed
                ),
            });
        }
    }

    Ok(())
}

// ─── Inline unit tests ────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn compute_entry_hash_is_deterministic() {
        let h1 = compute_entry_hash("GENESIS", "2026-04-26T12:00:00.000000", "user:jane", "CASE_CREATED", Some("case_id=C1"));
        let h2 = compute_entry_hash("GENESIS", "2026-04-26T12:00:00.000000", "user:jane", "CASE_CREATED", Some("case_id=C1"));
        assert_eq!(h1, h2);
        assert_eq!(h1.len(), 64); // hex-encoded SHA-256
    }

    #[test]
    fn compute_entry_hash_differs_with_details_none() {
        let with_detail = compute_entry_hash("GENESIS", "ts", "actor", "ACTION", Some("detail"));
        let without = compute_entry_hash("GENESIS", "ts", "actor", "ACTION", None);
        assert_ne!(with_detail, without);
    }

    #[test]
    fn verify_chain_passes_for_valid_sequence() {
        let mut entries = Vec::new();

        let ts = "2026-04-26T12:00:00.000000";
        let h1 = compute_entry_hash("GENESIS", ts, "user:a", "CASE_CREATED", None);
        entries.push(AuditEntry {
            entry_id: 1,
            case_id: Some("C1".into()),
            timestamp: ts.into(),
            actor: "user:a".into(),
            action: "CASE_CREATED".into(),
            details: None,
            prev_hash: "GENESIS".into(),
            entry_hash: h1.clone(),
        });

        let h2 = compute_entry_hash(&h1, ts, "user:a", "EVIDENCE_ADDED", None);
        entries.push(AuditEntry {
            entry_id: 2,
            case_id: Some("C1".into()),
            timestamp: ts.into(),
            actor: "user:a".into(),
            action: "EVIDENCE_ADDED".into(),
            details: None,
            prev_hash: h1.clone(),
            entry_hash: h2,
        });

        assert!(verify_chain(&entries).is_ok());
    }

    #[test]
    fn verify_chain_fails_on_tampered_hash() {
        let ts = "2026-04-26T12:00:00.000000";
        let h1 = compute_entry_hash("GENESIS", ts, "user:a", "CASE_CREATED", None);
        let mut entries = vec![AuditEntry {
            entry_id: 1,
            case_id: Some("C1".into()),
            timestamp: ts.into(),
            actor: "user:a".into(),
            action: "CASE_CREATED".into(),
            details: None,
            prev_hash: "GENESIS".into(),
            entry_hash: h1.clone(),
        }];

        let h2 = compute_entry_hash(&h1, ts, "user:a", "EVIDENCE_ADDED", None);
        entries.push(AuditEntry {
            entry_id: 2,
            case_id: Some("C1".into()),
            timestamp: ts.into(),
            actor: "user:a".into(),
            action: "EVIDENCE_ADDED".into(),
            details: None,
            prev_hash: h1.clone(),
            entry_hash: h2,
        });

        // Tamper entry 1's hash. Because entry 2's prev_hash still points to
        // the original h1, the chain break between entry 1 and entry 2 is
        // detected before the hash mismatch on entry 1 itself.
        entries[0].entry_hash = "0000000000000000000000000000000000000000000000000000000000000000".into();
        let err = verify_chain(&entries).unwrap_err();
        let msg = format!("{err:?}");
        assert!(msg.contains("chain break"), "expected chain break error after tampering, got: {msg}");
    }

    #[test]
    fn verify_chain_fails_on_broken_link() {
        let ts = "2026-04-26T12:00:00.000000";
        let h1 = compute_entry_hash("GENESIS", ts, "user:a", "CASE_CREATED", None);
        let mut entries = vec![AuditEntry {
            entry_id: 1,
            case_id: Some("C1".into()),
            timestamp: ts.into(),
            actor: "user:a".into(),
            action: "CASE_CREATED".into(),
            details: None,
            prev_hash: "GENESIS".into(),
            entry_hash: h1.clone(),
        }];

        let h2 = compute_entry_hash(&h1, ts, "user:a", "EVIDENCE_ADDED", None);
        entries.push(AuditEntry {
            entry_id: 2,
            case_id: Some("C1".into()),
            timestamp: ts.into(),
            actor: "user:a".into(),
            action: "EVIDENCE_ADDED".into(),
            details: None,
            prev_hash: "WRONG_HASH".into(), // broken link
            entry_hash: h2,
        });

        let err = verify_chain(&entries).unwrap_err();
        let msg = format!("{err:?}");
        assert!(msg.contains("chain break"), "expected chain break error, got: {msg}");
    }
}
