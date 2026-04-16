/// Link analysis Tauri commands — Phase 4 + migration 0004.
///
/// MUST-DO 3 (SEC-1): every command starts with `require_session()` as its
/// first statement. This is non-negotiable — see `commands/mod.rs`.
///
/// Covers three entity tables + two aggregate queries + person identifiers:
///   - `entities`           — add, get, list for case, update, soft-delete
///   - `entity_links`       — add, list for case, soft-delete
///   - `case_events`        — add, list for case, update, soft-delete
///   - `case_graph`         — Cytoscape.js node+edge aggregate
///   - `case_crime_line`    — vis-timeline items+groups aggregate
///   - `person_identifiers` — add, list for entity, update, soft-delete
///                            (multi-valued OSINT identifiers per person)
///
/// Audit actions emitted on mutations:
///   ENTITY_ADDED, ENTITY_UPDATED, ENTITY_DELETED,
///   LINK_ADDED, LINK_DELETED,
///   EVENT_ADDED, EVENT_UPDATED, EVENT_DELETED,
///   PERSON_IDENTIFIER_ADDED, PERSON_IDENTIFIER_UPDATED, PERSON_IDENTIFIER_DELETED
use std::sync::Arc;

use tauri::State;
use tracing::info;

use crate::{
    audit,
    auth::session::require_session,
    db::{
        business_identifiers::{BusinessIdentifier, BusinessIdentifierInput},
        entities::{Entity, EntityInput},
        events::{CaseEvent, EventInput},
        graph::{GraphFilter, GraphPayload, TimelineFilter, TimelinePayload},
        links::{Link, LinkInput},
        person_identifiers::{PersonIdentifier, PersonIdentifierInput},
    },
    error::AppError,
    state::AppState,
};

// ─── Audit action constants ───────────────────────────────────────────────────

const ENTITY_ADDED: &str = "ENTITY_ADDED";
const ENTITY_UPDATED: &str = "ENTITY_UPDATED";
const ENTITY_DELETED: &str = "ENTITY_DELETED";
const LINK_ADDED: &str = "LINK_ADDED";
const LINK_DELETED: &str = "LINK_DELETED";
const EVENT_ADDED: &str = "EVENT_ADDED";
const EVENT_UPDATED: &str = "EVENT_UPDATED";
const EVENT_DELETED: &str = "EVENT_DELETED";
const PERSON_IDENTIFIER_ADDED: &str = "PERSON_IDENTIFIER_ADDED";
const PERSON_IDENTIFIER_UPDATED: &str = "PERSON_IDENTIFIER_UPDATED";
const PERSON_IDENTIFIER_DELETED: &str = "PERSON_IDENTIFIER_DELETED";
const BUSINESS_IDENTIFIER_ADDED: &str = "BUSINESS_IDENTIFIER_ADDED";
const BUSINESS_IDENTIFIER_UPDATED: &str = "BUSINESS_IDENTIFIER_UPDATED";
const BUSINESS_IDENTIFIER_DELETED: &str = "BUSINESS_IDENTIFIER_DELETED";

// ─── Entity commands ──────────────────────────────────────────────────────────

/// Add a new entity to a case.
///
/// Validates entity_type, subtype, display_name, parent_entity_id, metadata_json.
/// Logs `ENTITY_ADDED` to the case audit trail.
#[tauri::command(rename_all = "snake_case")]
pub async fn entity_add(
    token: String,
    case_id: String,
    input: EntityInput,
    state: State<'_, Arc<AppState>>,
) -> Result<Entity, AppError> {
    // MUST-DO 3 — session guard first
    let session = require_session(&state, &token)?;

    let entity = crate::db::entities::add_entity(&state.db.forensics, &case_id, &input).await?;

    info!(
        username = %session.username,
        case_id = %case_id,
        entity_id = %entity.entity_id,
        entity_type = %entity.entity_type,
        "entity added"
    );
    audit::log_case(
        &case_id,
        &session.username,
        ENTITY_ADDED,
        &format!(
            "entity_id={} type={:?} name={:?}",
            entity.entity_id, entity.entity_type, entity.display_name,
        ),
    );

    Ok(entity)
}

/// Fetch a single entity by entity_id.
#[tauri::command(rename_all = "snake_case")]
pub async fn entity_get(
    token: String,
    entity_id: i64,
    state: State<'_, Arc<AppState>>,
) -> Result<Entity, AppError> {
    // MUST-DO 3 — session guard first
    let _session = require_session(&state, &token)?;

    crate::db::entities::get_entity(&state.db.forensics, entity_id).await
}

/// List all active entities for a case.
#[tauri::command(rename_all = "snake_case")]
pub async fn entity_list_for_case(
    token: String,
    case_id: String,
    state: State<'_, Arc<AppState>>,
) -> Result<Vec<Entity>, AppError> {
    // MUST-DO 3 — session guard first
    let _session = require_session(&state, &token)?;

    crate::db::entities::list_for_case(&state.db.forensics, &case_id).await
}

/// Update an existing entity's mutable fields.
///
/// Includes cycle check on parent_entity_id.
/// Logs `ENTITY_UPDATED` to the case audit trail.
#[tauri::command(rename_all = "snake_case")]
pub async fn entity_update(
    token: String,
    entity_id: i64,
    input: EntityInput,
    state: State<'_, Arc<AppState>>,
) -> Result<Entity, AppError> {
    // MUST-DO 3 — session guard first
    let session = require_session(&state, &token)?;

    let entity =
        crate::db::entities::update_entity(&state.db.forensics, entity_id, &input).await?;

    info!(
        username = %session.username,
        entity_id = %entity_id,
        "entity updated"
    );
    audit::log_case(
        &entity.case_id,
        &session.username,
        ENTITY_UPDATED,
        &format!(
            "entity_id={entity_id} type={:?} name={:?}",
            entity.entity_type, entity.display_name,
        ),
    );

    Ok(entity)
}

/// Soft-delete an entity (cascades to entity_links atomically).
///
/// Logs `ENTITY_DELETED` to the case audit trail.
#[tauri::command(rename_all = "snake_case")]
pub async fn entity_delete(
    token: String,
    entity_id: i64,
    state: State<'_, Arc<AppState>>,
) -> Result<(), AppError> {
    // MUST-DO 3 — session guard first
    let session = require_session(&state, &token)?;

    // Fetch case_id for audit log before deleting
    let entity = crate::db::entities::get_entity(&state.db.forensics, entity_id).await?;
    let case_id = entity.case_id.clone();

    crate::db::entities::soft_delete(&state.db.forensics, entity_id).await?;

    info!(
        username = %session.username,
        entity_id = %entity_id,
        case_id = %case_id,
        "entity soft-deleted"
    );
    audit::log_case(
        &case_id,
        &session.username,
        ENTITY_DELETED,
        &format!(
            "entity_id={entity_id} type={:?} name={:?}",
            entity.entity_type, entity.display_name,
        ),
    );

    Ok(())
}

// ─── Link commands ────────────────────────────────────────────────────────────

/// Add a new link between nodes (entity or evidence) in a case.
///
/// Validates both endpoints, no self-loops, directional/weight bounds.
/// Logs `LINK_ADDED` to the case audit trail.
#[tauri::command(rename_all = "snake_case")]
pub async fn link_add(
    token: String,
    case_id: String,
    input: LinkInput,
    state: State<'_, Arc<AppState>>,
) -> Result<Link, AppError> {
    // MUST-DO 3 — session guard first
    let session = require_session(&state, &token)?;

    let link = crate::db::links::add_link(&state.db.forensics, &case_id, &input).await?;

    info!(
        username = %session.username,
        case_id = %case_id,
        link_id = %link.link_id,
        "link added"
    );
    audit::log_case(
        &case_id,
        &session.username,
        LINK_ADDED,
        &format!(
            "link_id={} {}:{} → {}:{}",
            link.link_id,
            link.source_type, link.source_id,
            link.target_type, link.target_id,
        ),
    );

    Ok(link)
}

/// List all active links for a case.
#[tauri::command(rename_all = "snake_case")]
pub async fn link_list_for_case(
    token: String,
    case_id: String,
    state: State<'_, Arc<AppState>>,
) -> Result<Vec<Link>, AppError> {
    // MUST-DO 3 — session guard first
    let _session = require_session(&state, &token)?;

    crate::db::links::list_for_case(&state.db.forensics, &case_id).await
}

/// Soft-delete a link by link_id.
///
/// Logs `LINK_DELETED` to the case audit trail.
#[tauri::command(rename_all = "snake_case")]
pub async fn link_delete(
    token: String,
    link_id: i64,
    state: State<'_, Arc<AppState>>,
) -> Result<(), AppError> {
    // MUST-DO 3 — session guard first
    let session = require_session(&state, &token)?;

    // Fetch link for audit before deleting
    let link = crate::db::links::get_link(&state.db.forensics, link_id).await?;
    let case_id = link.case_id.clone();

    crate::db::links::soft_delete(&state.db.forensics, link_id).await?;

    info!(
        username = %session.username,
        link_id = %link_id,
        case_id = %case_id,
        "link soft-deleted"
    );
    audit::log_case(
        &case_id,
        &session.username,
        LINK_DELETED,
        &format!(
            "link_id={link_id} {}:{} → {}:{}",
            link.source_type, link.source_id,
            link.target_type, link.target_id,
        ),
    );

    Ok(())
}

// ─── Event commands ───────────────────────────────────────────────────────────

/// Add a new investigator-authored event to a case.
///
/// Validates title, category, datetime bounds, related FK refs.
/// Logs `EVENT_ADDED` to the case audit trail.
#[tauri::command(rename_all = "snake_case")]
pub async fn event_add(
    token: String,
    case_id: String,
    input: EventInput,
    state: State<'_, Arc<AppState>>,
) -> Result<CaseEvent, AppError> {
    // MUST-DO 3 — session guard first
    let session = require_session(&state, &token)?;

    let event = crate::db::events::add_event(&state.db.forensics, &case_id, &input).await?;

    info!(
        username = %session.username,
        case_id = %case_id,
        event_id = %event.event_id,
        "case event added"
    );
    audit::log_case(
        &case_id,
        &session.username,
        EVENT_ADDED,
        &format!(
            "event_id={} title={:?} dt={:?}",
            event.event_id, event.title, event.event_datetime,
        ),
    );

    Ok(event)
}

/// List all active events for a case, ordered by event_datetime ASC.
#[tauri::command(rename_all = "snake_case")]
pub async fn event_list_for_case(
    token: String,
    case_id: String,
    state: State<'_, Arc<AppState>>,
) -> Result<Vec<CaseEvent>, AppError> {
    // MUST-DO 3 — session guard first
    let _session = require_session(&state, &token)?;

    crate::db::events::list_for_case(&state.db.forensics, &case_id).await
}

/// Update an existing event's mutable fields.
///
/// Logs `EVENT_UPDATED` to the case audit trail.
#[tauri::command(rename_all = "snake_case")]
pub async fn event_update(
    token: String,
    event_id: i64,
    input: EventInput,
    state: State<'_, Arc<AppState>>,
) -> Result<CaseEvent, AppError> {
    // MUST-DO 3 — session guard first
    let session = require_session(&state, &token)?;

    let event = crate::db::events::update_event(&state.db.forensics, event_id, &input).await?;

    info!(
        username = %session.username,
        event_id = %event_id,
        "case event updated"
    );
    audit::log_case(
        &event.case_id,
        &session.username,
        EVENT_UPDATED,
        &format!("event_id={event_id} title={:?}", event.title),
    );

    Ok(event)
}

/// Soft-delete a case event by event_id.
///
/// Logs `EVENT_DELETED` to the case audit trail.
#[tauri::command(rename_all = "snake_case")]
pub async fn event_delete(
    token: String,
    event_id: i64,
    state: State<'_, Arc<AppState>>,
) -> Result<(), AppError> {
    // MUST-DO 3 — session guard first
    let session = require_session(&state, &token)?;

    // Fetch case_id for audit log before deleting
    let event = crate::db::events::get_event(&state.db.forensics, event_id).await?;
    let case_id = event.case_id.clone();

    crate::db::events::soft_delete(&state.db.forensics, event_id).await?;

    info!(
        username = %session.username,
        event_id = %event_id,
        case_id = %case_id,
        "case event soft-deleted"
    );
    audit::log_case(
        &case_id,
        &session.username,
        EVENT_DELETED,
        &format!("event_id={event_id} title={:?}", event.title),
    );

    Ok(())
}

// ─── Aggregate commands ───────────────────────────────────────────────────────

/// Build the Cytoscape.js graph payload for a case.
///
/// Requires a valid session — evidentiary data is never exposed unauthenticated.
/// `filter` controls entity_type inclusion and whether evidence nodes are included.
#[tauri::command(rename_all = "snake_case")]
pub async fn case_graph(
    token: String,
    case_id: String,
    filter: GraphFilter,
    state: State<'_, Arc<AppState>>,
) -> Result<GraphPayload, AppError> {
    // MUST-DO 3 — session guard first
    let _session = require_session(&state, &token)?;

    crate::db::graph::build_graph(&state.db.forensics, &case_id, &filter).await
}

/// Build the vis-timeline crime-line payload for a case.
///
/// Requires a valid session.
/// `filter` provides optional start/end date bounds applied to all 6 event groups.
#[tauri::command(rename_all = "snake_case")]
pub async fn case_crime_line(
    token: String,
    case_id: String,
    filter: TimelineFilter,
    state: State<'_, Arc<AppState>>,
) -> Result<TimelinePayload, AppError> {
    // MUST-DO 3 — session guard first
    let _session = require_session(&state, &token)?;

    crate::db::graph::build_crime_line(&state.db.forensics, &case_id, &filter).await
}

// ─── Person identifier commands (migration 0004) ──────────────────────────────

/// Add a new identifier (email / username / handle / phone / url) to a
/// person entity. Validates kind + value + parent-entity-is-person.
/// Logs `PERSON_IDENTIFIER_ADDED` to the case audit trail.
///
/// Fetches the parent entity BEFORE calling `add_identifier` so the audit
/// log's `case_id` is already cached by the time the insert runs. If we
/// fetched after the insert and a concurrent command soft-deleted the parent
/// in the meantime, the audit log would still succeed (entity_get returns
/// soft-deleted rows for audit purposes) but the ordering would be racy.
#[tauri::command(rename_all = "snake_case")]
pub async fn person_identifier_add(
    token: String,
    entity_id: i64,
    input: PersonIdentifierInput,
    state: State<'_, Arc<AppState>>,
) -> Result<PersonIdentifier, AppError> {
    // MUST-DO 3 — session guard first
    let session = require_session(&state, &token)?;

    // Fetch the parent entity first so we have `case_id` cached for the
    // audit log. `add_identifier` will re-verify the parent is a person.
    let entity = crate::db::entities::get_entity(&state.db.forensics, entity_id).await?;

    let identifier =
        crate::db::person_identifiers::add_identifier(&state.db.forensics, entity_id, &input)
            .await?;

    info!(
        username = %session.username,
        entity_id = %entity_id,
        identifier_id = %identifier.identifier_id,
        kind = %identifier.kind,
        "person identifier added"
    );
    audit::log_case(
        &entity.case_id,
        &session.username,
        PERSON_IDENTIFIER_ADDED,
        &format!(
            "identifier_id={} entity_id={} kind={:?} platform={:?}",
            identifier.identifier_id,
            entity_id,
            identifier.kind,
            identifier.platform.as_deref().unwrap_or(""),
        ),
    );

    Ok(identifier)
}

/// List all active identifiers for a person entity (ordered by kind, created_at).
#[tauri::command(rename_all = "snake_case")]
pub async fn person_identifier_list(
    token: String,
    entity_id: i64,
    state: State<'_, Arc<AppState>>,
) -> Result<Vec<PersonIdentifier>, AppError> {
    // MUST-DO 3 — session guard first
    let _session = require_session(&state, &token)?;

    crate::db::person_identifiers::list_for_entity(&state.db.forensics, entity_id).await
}

/// Update mutable fields of an existing person identifier.
/// Logs `PERSON_IDENTIFIER_UPDATED` to the case audit trail.
///
/// Fetches the current identifier + parent entity BEFORE calling
/// `update_identifier` so `case_id` is cached for the audit log before any
/// mutation happens.
#[tauri::command(rename_all = "snake_case")]
pub async fn person_identifier_update(
    token: String,
    identifier_id: i64,
    input: PersonIdentifierInput,
    state: State<'_, Arc<AppState>>,
) -> Result<PersonIdentifier, AppError> {
    // MUST-DO 3 — session guard first
    let session = require_session(&state, &token)?;

    // Fetch the current row to find the parent entity_id (identifiers are
    // not re-homeable between entities).
    let existing =
        crate::db::person_identifiers::get_identifier(&state.db.forensics, identifier_id).await?;
    let entity =
        crate::db::entities::get_entity(&state.db.forensics, existing.entity_id).await?;

    let identifier = crate::db::person_identifiers::update_identifier(
        &state.db.forensics,
        identifier_id,
        &input,
    )
    .await?;

    info!(
        username = %session.username,
        identifier_id = %identifier_id,
        "person identifier updated"
    );
    audit::log_case(
        &entity.case_id,
        &session.username,
        PERSON_IDENTIFIER_UPDATED,
        &format!(
            "identifier_id={} entity_id={} kind={:?} platform={:?}",
            identifier_id,
            identifier.entity_id,
            identifier.kind,
            identifier.platform.as_deref().unwrap_or(""),
        ),
    );

    Ok(identifier)
}

/// Soft-delete a person identifier.
/// Logs `PERSON_IDENTIFIER_DELETED` to the case audit trail.
#[tauri::command(rename_all = "snake_case")]
pub async fn person_identifier_delete(
    token: String,
    identifier_id: i64,
    state: State<'_, Arc<AppState>>,
) -> Result<(), AppError> {
    // MUST-DO 3 — session guard first
    let session = require_session(&state, &token)?;

    // Fetch first so we can include kind/entity in the audit log.
    let existing =
        crate::db::person_identifiers::get_identifier(&state.db.forensics, identifier_id).await?;
    let entity =
        crate::db::entities::get_entity(&state.db.forensics, existing.entity_id).await?;

    crate::db::person_identifiers::soft_delete(&state.db.forensics, identifier_id).await?;

    info!(
        username = %session.username,
        identifier_id = %identifier_id,
        entity_id = %existing.entity_id,
        "person identifier soft-deleted"
    );
    audit::log_case(
        &entity.case_id,
        &session.username,
        PERSON_IDENTIFIER_DELETED,
        &format!(
            "identifier_id={} entity_id={} kind={:?}",
            identifier_id, existing.entity_id, existing.kind
        ),
    );

    Ok(())
}

// ─── Business identifier commands (migration 0005) ────────────────────────────

/// Add a new identifier (domain / registration / ein / email / phone / address /
/// social / url) to a business entity. Validates kind + value + parent-entity-is-business.
/// Logs `BUSINESS_IDENTIFIER_ADDED` to the case audit trail.
///
/// Fetches the parent entity BEFORE calling `add_identifier` so the audit
/// log's `case_id` is already cached by the time the insert runs.
#[tauri::command(rename_all = "snake_case")]
pub async fn business_identifier_add(
    token: String,
    entity_id: i64,
    input: BusinessIdentifierInput,
    state: State<'_, Arc<AppState>>,
) -> Result<BusinessIdentifier, AppError> {
    // MUST-DO 3 — session guard first
    let session = require_session(&state, &token)?;

    // Fetch the parent entity first so we have `case_id` cached for the
    // audit log. `add_identifier` will re-verify the parent is a business.
    let entity = crate::db::entities::get_entity(&state.db.forensics, entity_id).await?;

    let identifier =
        crate::db::business_identifiers::add_identifier(&state.db.forensics, entity_id, &input)
            .await?;

    info!(
        username = %session.username,
        entity_id = %entity_id,
        identifier_id = %identifier.identifier_id,
        kind = %identifier.kind,
        "business identifier added"
    );
    audit::log_case(
        &entity.case_id,
        &session.username,
        BUSINESS_IDENTIFIER_ADDED,
        &format!(
            "identifier_id={} entity_id={} kind={:?} platform={:?}",
            identifier.identifier_id,
            entity_id,
            identifier.kind,
            identifier.platform.as_deref().unwrap_or(""),
        ),
    );

    Ok(identifier)
}

/// List all active identifiers for a business entity (ordered by kind, created_at).
#[tauri::command(rename_all = "snake_case")]
pub async fn business_identifier_list(
    token: String,
    entity_id: i64,
    state: State<'_, Arc<AppState>>,
) -> Result<Vec<BusinessIdentifier>, AppError> {
    // MUST-DO 3 — session guard first
    let _session = require_session(&state, &token)?;

    crate::db::business_identifiers::list_for_entity(&state.db.forensics, entity_id).await
}

/// Update mutable fields of an existing business identifier.
/// Logs `BUSINESS_IDENTIFIER_UPDATED` to the case audit trail.
///
/// Fetches the current identifier + parent entity BEFORE calling
/// `update_identifier` so `case_id` is cached for the audit log before any
/// mutation happens.
#[tauri::command(rename_all = "snake_case")]
pub async fn business_identifier_update(
    token: String,
    identifier_id: i64,
    input: BusinessIdentifierInput,
    state: State<'_, Arc<AppState>>,
) -> Result<BusinessIdentifier, AppError> {
    // MUST-DO 3 — session guard first
    let session = require_session(&state, &token)?;

    // Fetch the current row to find the parent entity_id (identifiers are
    // not re-homeable between entities).
    let existing =
        crate::db::business_identifiers::get_identifier(&state.db.forensics, identifier_id).await?;
    let entity =
        crate::db::entities::get_entity(&state.db.forensics, existing.entity_id).await?;

    let identifier = crate::db::business_identifiers::update_identifier(
        &state.db.forensics,
        identifier_id,
        &input,
    )
    .await?;

    info!(
        username = %session.username,
        identifier_id = %identifier_id,
        "business identifier updated"
    );
    audit::log_case(
        &entity.case_id,
        &session.username,
        BUSINESS_IDENTIFIER_UPDATED,
        &format!(
            "identifier_id={} entity_id={} kind={:?} platform={:?}",
            identifier_id,
            identifier.entity_id,
            identifier.kind,
            identifier.platform.as_deref().unwrap_or(""),
        ),
    );

    Ok(identifier)
}

/// Soft-delete a business identifier.
/// Logs `BUSINESS_IDENTIFIER_DELETED` to the case audit trail.
#[tauri::command(rename_all = "snake_case")]
pub async fn business_identifier_delete(
    token: String,
    identifier_id: i64,
    state: State<'_, Arc<AppState>>,
) -> Result<(), AppError> {
    // MUST-DO 3 — session guard first
    let session = require_session(&state, &token)?;

    // Fetch first so we can include kind/entity in the audit log.
    let existing =
        crate::db::business_identifiers::get_identifier(&state.db.forensics, identifier_id).await?;
    let entity =
        crate::db::entities::get_entity(&state.db.forensics, existing.entity_id).await?;

    crate::db::business_identifiers::soft_delete(&state.db.forensics, identifier_id).await?;

    info!(
        username = %session.username,
        identifier_id = %identifier_id,
        entity_id = %existing.entity_id,
        "business identifier soft-deleted"
    );
    audit::log_case(
        &entity.case_id,
        &session.username,
        BUSINESS_IDENTIFIER_DELETED,
        &format!(
            "identifier_id={} entity_id={} kind={:?}",
            identifier_id, existing.entity_id, existing.kind
        ),
    );

    Ok(())
}
