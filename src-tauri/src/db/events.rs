/// Case events database queries — Phase 4.
///
/// Manages the `case_events` table: add, get, list for case, update, soft-delete.
/// All deletes are soft (is_deleted = 1).
///
/// Public surface:
///   - `add_event`     — INSERT with full validation
///   - `get_event`     — fetch single row by event_id
///   - `list_for_case` — active rows only, ordered by event_datetime ASC
///   - `update_event`  — UPDATE mutable fields
///   - `soft_delete`   — sets is_deleted = 1
///
/// Validation:
///   - title: required, 1–200 chars
///   - category allowlist: observation | communication | movement | custodial | other
///   - event_datetime: required, must not be in the future
///   - event_end_datetime: must be >= event_datetime if provided
///   - related_entity_id: must exist in same case (not soft-deleted) if provided
///   - related_evidence_id: must exist in same case if provided
///   - description: optional, max 5000 chars
use chrono::{NaiveDateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::SqlitePool;

use crate::error::AppError;

// ─── Validation constants ─────────────────────────────────────────────────────

const VALID_CATEGORIES: &[&str] = &[
    "observation", "communication", "movement", "custodial", "other",
];

const TITLE_MAX_LEN: usize = 200;
const DESCRIPTION_MAX_LEN: usize = 5000;

// ─── Public data types ────────────────────────────────────────────────────────

/// Full case_events row, maps 1:1 to the `case_events` table.
#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct CaseEvent {
    pub event_id: i64,
    pub case_id: String,
    pub title: String,
    pub description: Option<String>,
    pub event_datetime: NaiveDateTime,
    pub event_end_datetime: Option<NaiveDateTime>,
    pub category: Option<String>,
    pub related_entity_id: Option<i64>,
    pub related_evidence_id: Option<String>,
    pub is_deleted: i64,
    pub created_at: NaiveDateTime,
}

/// Writable fields for creating or updating a case event.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EventInput {
    pub title: String,
    pub description: Option<String>,
    pub event_datetime: NaiveDateTime,
    pub event_end_datetime: Option<NaiveDateTime>,
    pub category: Option<String>,
    pub related_entity_id: Option<i64>,
    pub related_evidence_id: Option<String>,
}

// ─── Validation helpers ───────────────────────────────────────────────────────

async fn validate_event_input(
    pool: &SqlitePool,
    case_id: &str,
    input: &EventInput,
) -> Result<(), AppError> {
    // title: required, 1–200 chars
    let title = input.title.trim();
    if title.is_empty() {
        return Err(AppError::ValidationError {
            field: "title".into(),
            message: "title must not be empty".into(),
        });
    }
    if title.len() > TITLE_MAX_LEN {
        return Err(AppError::ValidationError {
            field: "title".into(),
            message: format!("title must not exceed {TITLE_MAX_LEN} characters"),
        });
    }

    // description: optional, max 5000 chars
    if let Some(ref desc) = input.description {
        if desc.len() > DESCRIPTION_MAX_LEN {
            return Err(AppError::ValidationError {
                field: "description".into(),
                message: format!("description must not exceed {DESCRIPTION_MAX_LEN} characters"),
            });
        }
    }

    // category allowlist (None is allowed)
    if let Some(ref cat) = input.category {
        if !VALID_CATEGORIES.contains(&cat.as_str()) {
            return Err(AppError::ValidationError {
                field: "category".into(),
                message: format!(
                    "category must be one of: {}",
                    VALID_CATEGORIES.join(", ")
                ),
            });
        }
    }

    // event_datetime must not be in the future
    let now_utc = Utc::now().naive_utc();
    if input.event_datetime > now_utc {
        return Err(AppError::ValidationError {
            field: "event_datetime".into(),
            message: "event_datetime must not be in the future".into(),
        });
    }

    // event_end_datetime must be >= event_datetime if provided
    if let Some(end_dt) = input.event_end_datetime {
        if end_dt < input.event_datetime {
            return Err(AppError::ValidationError {
                field: "event_end_datetime".into(),
                message: "event_end_datetime must be >= event_datetime".into(),
            });
        }
    }

    // related_entity_id: must exist in same case (not soft-deleted)
    if let Some(entity_id) = input.related_entity_id {
        let exists: (i64,) = sqlx::query_as(
            "SELECT COUNT(*) FROM entities WHERE entity_id = ? AND case_id = ? AND is_deleted = 0",
        )
        .bind(entity_id)
        .bind(case_id)
        .fetch_one(pool)
        .await?;

        if exists.0 == 0 {
            return Err(AppError::ValidationError {
                field: "related_entity_id".into(),
                message: format!(
                    "related_entity_id {entity_id} does not exist in case '{case_id}'"
                ),
            });
        }
    }

    // related_evidence_id: must exist in same case
    if let Some(ref evidence_id) = input.related_evidence_id {
        let exists: (i64,) = sqlx::query_as(
            "SELECT COUNT(*) FROM evidence WHERE evidence_id = ? AND case_id = ?",
        )
        .bind(evidence_id)
        .bind(case_id)
        .fetch_one(pool)
        .await?;

        if exists.0 == 0 {
            return Err(AppError::ValidationError {
                field: "related_evidence_id".into(),
                message: format!(
                    "related_evidence_id '{evidence_id}' does not exist in case '{case_id}'"
                ),
            });
        }
    }

    Ok(())
}

// ─── Public query functions ───────────────────────────────────────────────────

/// Add a new investigator-authored event to a case.
pub async fn add_event(
    pool: &SqlitePool,
    case_id: &str,
    input: &EventInput,
) -> Result<CaseEvent, AppError> {
    validate_event_input(pool, case_id, input).await?;

    let row = sqlx::query_as::<_, CaseEvent>(
        r#"
        INSERT INTO case_events (
            case_id, title, description, event_datetime, event_end_datetime,
            category, related_entity_id, related_evidence_id
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        RETURNING
            event_id, case_id, title, description, event_datetime, event_end_datetime,
            category, related_entity_id, related_evidence_id, is_deleted, created_at
        "#,
    )
    .bind(case_id)
    .bind(input.title.trim())
    .bind(&input.description)
    .bind(input.event_datetime)
    .bind(input.event_end_datetime)
    .bind(&input.category)
    .bind(input.related_entity_id)
    .bind(&input.related_evidence_id)
    .fetch_one(pool)
    .await?;

    Ok(row)
}

/// Fetch a single event by event_id (includes soft-deleted rows for audit purposes).
pub async fn get_event(pool: &SqlitePool, event_id: i64) -> Result<CaseEvent, AppError> {
    sqlx::query_as::<_, CaseEvent>(
        r#"
        SELECT event_id, case_id, title, description, event_datetime, event_end_datetime,
               category, related_entity_id, related_evidence_id, is_deleted, created_at
        FROM case_events
        WHERE event_id = ?
        "#,
    )
    .bind(event_id)
    .fetch_optional(pool)
    .await?
    .ok_or(AppError::EventNotFound { event_id })
}

/// List all active (non-deleted) events for a case, ordered by event_datetime ASC.
pub async fn list_for_case(pool: &SqlitePool, case_id: &str) -> Result<Vec<CaseEvent>, AppError> {
    let rows = sqlx::query_as::<_, CaseEvent>(
        r#"
        SELECT event_id, case_id, title, description, event_datetime, event_end_datetime,
               category, related_entity_id, related_evidence_id, is_deleted, created_at
        FROM case_events
        WHERE case_id = ? AND is_deleted = 0
        ORDER BY event_datetime ASC
        "#,
    )
    .bind(case_id)
    .fetch_all(pool)
    .await?;

    Ok(rows)
}

/// Update mutable fields of an existing event.
///
/// Validates same rules as `add_event`.
pub async fn update_event(
    pool: &SqlitePool,
    event_id: i64,
    input: &EventInput,
) -> Result<CaseEvent, AppError> {
    // Fetch existing to get case_id for FK validation
    let existing = get_event(pool, event_id).await?;
    if existing.is_deleted != 0 {
        return Err(AppError::EventNotFound { event_id });
    }

    validate_event_input(pool, &existing.case_id, input).await?;

    let row = sqlx::query_as::<_, CaseEvent>(
        r#"
        UPDATE case_events SET
            title = ?,
            description = ?,
            event_datetime = ?,
            event_end_datetime = ?,
            category = ?,
            related_entity_id = ?,
            related_evidence_id = ?
        WHERE event_id = ? AND is_deleted = 0
        RETURNING
            event_id, case_id, title, description, event_datetime, event_end_datetime,
            category, related_entity_id, related_evidence_id, is_deleted, created_at
        "#,
    )
    .bind(input.title.trim())
    .bind(&input.description)
    .bind(input.event_datetime)
    .bind(input.event_end_datetime)
    .bind(&input.category)
    .bind(input.related_entity_id)
    .bind(&input.related_evidence_id)
    .bind(event_id)
    .fetch_optional(pool)
    .await?
    .ok_or(AppError::EventNotFound { event_id })?;

    Ok(row)
}

/// Soft-delete an event by event_id.
pub async fn soft_delete(pool: &SqlitePool, event_id: i64) -> Result<(), AppError> {
    let rows_affected = sqlx::query(
        "UPDATE case_events SET is_deleted = 1 WHERE event_id = ? AND is_deleted = 0",
    )
    .bind(event_id)
    .execute(pool)
    .await?
    .rows_affected();

    if rows_affected == 0 {
        return Err(AppError::EventNotFound { event_id });
    }

    Ok(())
}
