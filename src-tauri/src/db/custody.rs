/// Chain-of-custody database queries — Phase 3a.
///
/// Manages the `chain_of_custody` table: add (with sequence auto-increment),
/// get, list for evidence (ordered), list for case (JOIN), update, delete.
///
/// Public surface:
///   - `get_next_sequence`   — SELECT COALESCE(MAX(custody_sequence), 0) + 1
///   - `add_custody`         — transactional: sequence + INSERT
///   - `get_custody`         — fetch single event by custody_id
///   - `list_for_evidence`   — ordered by custody_sequence ASC
///   - `list_for_case`       — JOIN against evidence; ordered by evidence_id, custody_sequence
///   - `update_custody`      — UPDATE (action, parties, location, datetime, purpose, notes)
///   - `delete_custody`      — simple DELETE by custody_id
///
/// `action` allowlist: Seized | Transferred | Received | Analyzed |
///                     Returned | Destroyed | Sealed | Unsealed
/// (v2 improvement — v1 was freeform)
use chrono::NaiveDateTime;
use serde::{Deserialize, Serialize};
use sqlx::{sqlite::Sqlite, SqlitePool, Transaction};

use crate::error::AppError;

// ─── Validation constants ────────────────────────────────────────────────────

const VALID_ACTIONS: &[&str] = &[
    "Seized",
    "Transferred",
    "Received",
    "Analyzed",
    "Returned",
    "Destroyed",
    "Sealed",
    "Unsealed",
];

// ─── Public data types ────────────────────────────────────────────────────────

/// Full chain-of-custody row, maps 1:1 to the `chain_of_custody` table.
#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct CustodyEvent {
    pub custody_id: i64,
    pub evidence_id: String,
    pub custody_sequence: i64,
    pub action: String,
    pub from_party: String,
    pub to_party: String,
    pub location: Option<String>,
    pub custody_datetime: NaiveDateTime,
    pub purpose: Option<String>,
    pub notes: Option<String>,
}

/// Writable fields for creating or updating a custody event.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CustodyInput {
    pub action: String,
    pub from_party: String,
    pub to_party: String,
    pub location: Option<String>,
    pub custody_datetime: NaiveDateTime,
    pub purpose: Option<String>,
    pub notes: Option<String>,
}

// ─── Validation helpers ───────────────────────────────────────────────────────

/// Validate that `action` is in the allowed action set.
pub(crate) fn validate_action(action: &str) -> Result<(), AppError> {
    if !VALID_ACTIONS.contains(&action) {
        return Err(AppError::ValidationError {
            field: "action".into(),
            message: format!(
                "action must be one of: {}",
                VALID_ACTIONS.join(", ")
            ),
        });
    }
    Ok(())
}

// ─── Public query functions ───────────────────────────────────────────────────

/// Get the next custody sequence number for an evidence item.
///
/// Uses `SELECT COALESCE(MAX(custody_sequence), 0) + 1` — matching v1's logic.
/// Returns 1 if no custody events exist yet for this evidence.
///
/// Designed to be called inside a transaction so the sequence cannot
/// be stolen by a concurrent insert (SQLite serialises writers, so
/// concurrent sequence conflicts are not possible, but the tx boundary
/// makes the intent clear).
pub async fn get_next_sequence(pool: &SqlitePool, evidence_id: &str) -> Result<i64, AppError> {
    let row: (i64,) = sqlx::query_as(
        "SELECT COALESCE(MAX(custody_sequence), 0) + 1 FROM chain_of_custody WHERE evidence_id = ?",
    )
    .bind(evidence_id)
    .fetch_one(pool)
    .await?;
    Ok(row.0)
}

/// Get the next sequence inside an active transaction.
async fn get_next_sequence_tx(
    tx: &mut Transaction<'_, Sqlite>,
    evidence_id: &str,
) -> Result<i64, AppError> {
    let row: (i64,) = sqlx::query_as(
        "SELECT COALESCE(MAX(custody_sequence), 0) + 1 FROM chain_of_custody WHERE evidence_id = ?",
    )
    .bind(evidence_id)
    .fetch_one(&mut **tx)
    .await?;
    Ok(row.0)
}

/// Add a new custody event.
///
/// Validates `action` allowlist.
/// Runs in a transaction: sequence computed inside the tx, then INSERT.
/// Returns the full saved row.
pub async fn add_custody(
    pool: &SqlitePool,
    evidence_id: &str,
    input: &CustodyInput,
) -> Result<CustodyEvent, AppError> {
    validate_action(&input.action)?;

    let mut tx = pool.begin().await?;

    let seq = get_next_sequence_tx(&mut tx, evidence_id).await?;

    let row_id = sqlx::query(
        r#"
        INSERT INTO chain_of_custody (
            evidence_id, custody_sequence, action, from_party, to_party,
            location, custody_datetime, purpose, notes
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        "#,
    )
    .bind(evidence_id)
    .bind(seq)
    .bind(&input.action)
    .bind(&input.from_party)
    .bind(&input.to_party)
    .bind(&input.location)
    .bind(input.custody_datetime)
    .bind(&input.purpose)
    .bind(&input.notes)
    .execute(&mut *tx)
    .await?
    .last_insert_rowid();

    tx.commit().await?;

    get_custody(pool, row_id).await
}

/// Fetch a single custody event by custody_id.
///
/// Returns `AppError::CustodyNotFound` if no row exists.
pub async fn get_custody(pool: &SqlitePool, custody_id: i64) -> Result<CustodyEvent, AppError> {
    sqlx::query_as::<_, CustodyEvent>(
        r#"
        SELECT
            custody_id, evidence_id, custody_sequence, action,
            from_party, to_party, location, custody_datetime, purpose, notes
        FROM chain_of_custody
        WHERE custody_id = ?
        "#,
    )
    .bind(custody_id)
    .fetch_optional(pool)
    .await?
    .ok_or_else(|| AppError::CustodyNotFound { custody_id })
}

/// List custody events for a specific evidence item, ordered by custody_sequence ASC.
pub async fn list_for_evidence(
    pool: &SqlitePool,
    evidence_id: &str,
) -> Result<Vec<CustodyEvent>, AppError> {
    let rows = sqlx::query_as::<_, CustodyEvent>(
        r#"
        SELECT
            custody_id, evidence_id, custody_sequence, action,
            from_party, to_party, location, custody_datetime, purpose, notes
        FROM chain_of_custody
        WHERE evidence_id = ?
        ORDER BY custody_sequence ASC
        "#,
    )
    .bind(evidence_id)
    .fetch_all(pool)
    .await?;
    Ok(rows)
}

/// List all custody events for a case (across all evidence items).
///
/// JOINs against the evidence table to find all evidence belonging to the case.
/// Ordered by evidence_id, custody_sequence — so all events for one evidence
/// item group together.
pub async fn list_for_case(
    pool: &SqlitePool,
    case_id: &str,
) -> Result<Vec<CustodyEvent>, AppError> {
    let rows = sqlx::query_as::<_, CustodyEvent>(
        r#"
        SELECT
            c.custody_id, c.evidence_id, c.custody_sequence, c.action,
            c.from_party, c.to_party, c.location, c.custody_datetime,
            c.purpose, c.notes
        FROM chain_of_custody c
        INNER JOIN evidence e ON c.evidence_id = e.evidence_id
        WHERE e.case_id = ?
        ORDER BY c.evidence_id, c.custody_sequence
        "#,
    )
    .bind(case_id)
    .fetch_all(pool)
    .await?;
    Ok(rows)
}

/// Update a custody event's mutable fields.
///
/// Validates `action` allowlist.
/// Does NOT change `custody_sequence` or `evidence_id` — those are immutable
/// once set. Returns the updated row.
///
/// Returns `AppError::CustodyNotFound` if the custody_id doesn't exist.
pub async fn update_custody(
    pool: &SqlitePool,
    custody_id: i64,
    input: &CustodyInput,
) -> Result<CustodyEvent, AppError> {
    validate_action(&input.action)?;

    let rows_affected = sqlx::query(
        r#"
        UPDATE chain_of_custody SET
            action = ?,
            from_party = ?,
            to_party = ?,
            location = ?,
            custody_datetime = ?,
            purpose = ?,
            notes = ?
        WHERE custody_id = ?
        "#,
    )
    .bind(&input.action)
    .bind(&input.from_party)
    .bind(&input.to_party)
    .bind(&input.location)
    .bind(input.custody_datetime)
    .bind(&input.purpose)
    .bind(&input.notes)
    .bind(custody_id)
    .execute(pool)
    .await?
    .rows_affected();

    if rows_affected == 0 {
        return Err(AppError::CustodyNotFound { custody_id });
    }

    get_custody(pool, custody_id).await
}

/// Delete a custody event by custody_id.
///
/// Returns `AppError::CustodyNotFound` if no row was deleted.
pub async fn delete_custody(pool: &SqlitePool, custody_id: i64) -> Result<(), AppError> {
    let rows_affected = sqlx::query("DELETE FROM chain_of_custody WHERE custody_id = ?")
        .bind(custody_id)
        .execute(pool)
        .await?
        .rows_affected();

    if rows_affected == 0 {
        return Err(AppError::CustodyNotFound { custody_id });
    }
    Ok(())
}

// ─── Inline unit tests ────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::validate_action;
    use crate::error::AppError;

    #[test]
    fn test_valid_actions() {
        for action in &[
            "Seized",
            "Transferred",
            "Received",
            "Analyzed",
            "Returned",
            "Destroyed",
            "Sealed",
            "Unsealed",
        ] {
            assert!(
                validate_action(action).is_ok(),
                "action '{action}' should be valid"
            );
        }
    }

    #[test]
    fn test_invalid_action() {
        for bad in &["Collected", "Processed", "seized", "transferred", ""] {
            let err = validate_action(bad).unwrap_err();
            assert!(
                matches!(err, AppError::ValidationError { ref field, .. } if field == "action"),
                "expected ValidationError for action {bad:?}"
            );
        }
    }
}
