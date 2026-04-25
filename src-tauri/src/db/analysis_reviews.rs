//! Analysis review records — migration 0007 (validation principles).
//!
//! Peer-review stamping for `analysis_notes`. A bounded UPDATE on
//! `analysis_notes` would overwrite prior reviewers if a note were
//! reviewed twice, and would break the table-level "this app never
//! mutates analytical records" invariant that the app relies on for
//! forensic defensibility.
//!
//! This table is **append-only** — no update, no delete. Multiple rows
//! per parent note are a feature: a review history is forensically
//! stronger than a single reviewer field.
//!
//! Public surface:
//!   - `add_review`          — INSERT with validation + parent existence check
//!   - `list_for_note`       — reviews on one note, ASC by created_at
//!   - `list_for_case`       — all reviews for a case, grouped by note_id
//!                             (for the report aggregate at render time)

use serde::{Deserialize, Serialize};
use sqlx::SqlitePool;

use crate::db::graph::parse_loose_datetime;
use crate::error::AppError;

// ─── Validation constants ─────────────────────────────────────────────────────

const REVIEWED_BY_MAX_LEN: usize = 200;
const REVIEW_NOTES_MAX_LEN: usize = 2000;
/// Defensive cap on `reviewed_at` BEFORE handing the string to
/// `parse_loose_datetime`. Without this, a megabyte-sized pasted
/// string would burn parser time and bloat the audit log before
/// being rejected. Real ISO datetimes are ≤30 chars; 64 leaves
/// slack for fractional seconds and offset suffixes.
const REVIEWED_AT_MAX_LEN: usize = 64;

// ─── Public data types ────────────────────────────────────────────────────────

/// Full analysis_reviews row. `reviewed_at` and `created_at` are
/// `String` for v1-compat (see `db::cases::Case`).
#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct AnalysisReview {
    pub review_id: i64,
    pub note_id: i64,
    pub reviewed_by: String,
    pub reviewed_at: String,
    pub review_notes: Option<String>,
    pub created_at: String,
}

/// Writable fields for adding a review.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnalysisReviewInput {
    pub reviewed_by: String,
    /// ISO datetime — accepts either `"YYYY-MM-DDTHH:MM:SS"` (from HTML
    /// datetime-local) or `"YYYY-MM-DD HH:MM:SS"` (v1 format). Parsed
    /// via `parse_loose_datetime` for validation; stored as-is for
    /// round-trip fidelity.
    pub reviewed_at: String,
    pub review_notes: Option<String>,
}

// ─── Validation ───────────────────────────────────────────────────────────────

fn validate_input(input: &AnalysisReviewInput) -> Result<(), AppError> {
    let reviewer = input.reviewed_by.trim();
    if reviewer.is_empty() {
        return Err(AppError::ValidationError {
            field: "reviewed_by".into(),
            message: "reviewed_by must not be empty".into(),
        });
    }
    if reviewer.chars().count() > REVIEWED_BY_MAX_LEN {
        return Err(AppError::ValidationError {
            field: "reviewed_by".into(),
            message: format!("reviewed_by must not exceed {REVIEWED_BY_MAX_LEN} characters"),
        });
    }

    let reviewed_at = input.reviewed_at.trim();
    if reviewed_at.chars().count() > REVIEWED_AT_MAX_LEN {
        return Err(AppError::ValidationError {
            field: "reviewed_at".into(),
            message: format!(
                "reviewed_at must not exceed {REVIEWED_AT_MAX_LEN} characters"
            ),
        });
    }
    if parse_loose_datetime(reviewed_at).is_none() {
        return Err(AppError::ValidationError {
            field: "reviewed_at".into(),
            message: "reviewed_at must be an ISO datetime".into(),
        });
    }

    if let Some(notes) = &input.review_notes {
        if notes.chars().count() > REVIEW_NOTES_MAX_LEN {
            return Err(AppError::ValidationError {
                field: "review_notes".into(),
                message: format!("review_notes must not exceed {REVIEW_NOTES_MAX_LEN} characters"),
            });
        }
    }

    Ok(())
}

// ─── Public query functions ───────────────────────────────────────────────────

/// Append a review row for `note_id`. Parent existence is verified
/// first so a stale / spoofed note_id returns `ValidationError` rather
/// than a raw FK violation.
pub async fn add_review(
    pool: &SqlitePool,
    note_id: i64,
    input: &AnalysisReviewInput,
) -> Result<AnalysisReview, AppError> {
    validate_input(input)?;

    let parent_exists: Option<i64> = sqlx::query_scalar(
        r#"SELECT note_id FROM analysis_notes WHERE note_id = ?"#,
    )
    .bind(note_id)
    .fetch_optional(pool)
    .await?;

    if parent_exists.is_none() {
        return Err(AppError::ValidationError {
            field: "note_id".into(),
            message: format!("analysis note {note_id} does not exist"),
        });
    }

    let row_id = sqlx::query(
        r#"
        INSERT INTO analysis_reviews (note_id, reviewed_by, reviewed_at, review_notes)
        VALUES (?, ?, ?, ?)
        "#,
    )
    .bind(note_id)
    .bind(input.reviewed_by.trim())
    .bind(input.reviewed_at.trim())
    .bind(&input.review_notes)
    .execute(pool)
    .await?
    .last_insert_rowid();

    let review = sqlx::query_as::<_, AnalysisReview>(
        r#"
        SELECT review_id, note_id, reviewed_by, reviewed_at, review_notes, created_at
        FROM analysis_reviews
        WHERE review_id = ?
        "#,
    )
    .bind(row_id)
    .fetch_one(pool)
    .await?;

    Ok(review)
}

/// All reviews for a given note, oldest first (so the UI can show the
/// review history chronologically).
///
/// `created_at` is SQLite-second precision; two reviews stamped in the
/// same second tie on the timestamp. `review_id ASC` is added as
/// tiebreaker so the surfaced ordering is deterministic across runs —
/// matters for both UI display and report rendering.
pub async fn list_for_note(
    pool: &SqlitePool,
    note_id: i64,
) -> Result<Vec<AnalysisReview>, AppError> {
    let rows = sqlx::query_as::<_, AnalysisReview>(
        r#"
        SELECT review_id, note_id, reviewed_by, reviewed_at, review_notes, created_at
        FROM analysis_reviews
        WHERE note_id = ?
        ORDER BY created_at ASC, review_id ASC
        "#,
    )
    .bind(note_id)
    .fetch_all(pool)
    .await?;
    Ok(rows)
}

/// All reviews for every note in a case — for the report aggregate
/// AND the AnalysisPanel's one-shot fetch (replacing what would
/// otherwise be N+1 per-note queries from each note card).
///
/// Same `review_id` tiebreaker as `list_for_note`.
pub async fn list_for_case(
    pool: &SqlitePool,
    case_id: &str,
) -> Result<Vec<AnalysisReview>, AppError> {
    let rows = sqlx::query_as::<_, AnalysisReview>(
        r#"
        SELECT r.review_id, r.note_id, r.reviewed_by, r.reviewed_at, r.review_notes, r.created_at
        FROM analysis_reviews r
        JOIN analysis_notes n ON r.note_id = n.note_id
        WHERE n.case_id = ?
        ORDER BY r.note_id ASC, r.created_at ASC, r.review_id ASC
        "#,
    )
    .bind(case_id)
    .fetch_all(pool)
    .await?;
    Ok(rows)
}
