//! Node inspector aggregate query — Phase 4 link-analysis feature #2.
//!
//! When the investigator clicks a node on the link-analysis graph, the
//! inspector panel needs entity/evidence/identifier context in a single
//! round-trip. Per-node-type Tauri commands would force the frontend to
//! orchestrate 3-5 calls and waterfall on cache state — instead we ship
//! a discriminated-union response keyed off the canvas namespaced node id
//! (`entity:<id>`, `evidence:<id>`, `identifier:<id>`).
//!
//! The inspector is a READ-ONLY aggregate — it never mutates and never
//! exposes soft-deleted rows. Counts (linked entities/evidence, hash
//! verifications) are aggregates against the active set.
//!
//! Identifier nodes are ambiguous between `person_identifiers` and
//! `business_identifiers` because the canvas canonical id is the lowest
//! `identifier_id` of either table for a given dedup key (see
//! `db::graph::build_graph`). The inspector resolves this by trying the
//! person table first then the business table, then re-querying both
//! tables by dedup key to surface ALL owners of the identifier.

use serde::{Deserialize, Serialize};
use sqlx::SqlitePool;

use crate::db::evidence::Evidence;
use crate::error::AppError;

// ─── Public types ────────────────────────────────────────────────────────────

/// Top-level discriminated payload. The `kind` tag tells the frontend
/// which rendering path to pick.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum InspectorPayload {
    Entity(EntityInspectorView),
    Evidence(EvidenceInspectorView),
    Identifier(IdentifierInspectorView),
    /// Returned when the node id can be parsed but doesn't map to any
    /// active row — useful when the graph is rendered from cached state
    /// after the underlying entity/evidence has been soft-deleted.
    NotFound,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EntityInspectorView {
    pub entity_id: i64,
    pub entity_type: String,
    pub display_name: String,
    pub subtype: Option<String>,
    pub photo_path: Option<String>,
    pub email: Option<String>,
    pub phone: Option<String>,
    pub username: Option<String>,
    pub employer: Option<String>,
    pub dob: Option<String>,
    pub notes: Option<String>,
    /// Unified projection of person_identifiers/business_identifiers for
    /// this entity — frontend doesn't need to know which table the row
    /// came from.
    pub identifiers: Vec<EntityIdentifier>,
    /// Number of OTHER active entities this entity is linked to via
    /// `entity_links`. Self-loops are excluded.
    pub linked_entity_count: i64,
    /// Number of active evidence items linked to this entity.
    pub linked_evidence_count: i64,
}

/// Common shape across `person_identifiers` and `business_identifiers`
/// for the inspector's identifier list.
#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct EntityIdentifier {
    pub identifier_id: i64,
    pub kind: String,
    pub value: String,
    pub platform: Option<String>,
    pub notes: Option<String>,
    pub discovered_via_tool: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvidenceInspectorView {
    pub evidence: Evidence,
    /// Active entity_links touching this evidence (either source or target).
    pub linked_entity_count: i64,
    /// Number of hash_verification rows for this evidence.
    pub hash_verification_count: i64,
    /// Most recent custody event by `custody_datetime` DESC, if any.
    /// Tells the investigator "where is this evidence right now?"
    /// without expanding the full chain.
    pub latest_custody: Option<CustodyEventSummary>,
}

#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct CustodyEventSummary {
    pub action: String,
    pub from_party: String,
    pub to_party: String,
    pub custody_datetime: String,
    pub location: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IdentifierInspectorView {
    /// Identifier kind (email/phone/domain/etc.) from the underlying
    /// table. Serialized as `identifier_kind` to avoid colliding with
    /// the parent `InspectorPayload` enum's `#[serde(tag = "kind")]`
    /// discriminator — without the rename, serde would shadow this
    /// field with the literal string `"identifier"` over the wire.
    #[serde(rename = "identifier_kind")]
    pub kind: String,
    pub value: String,
    pub platform: Option<String>,
    pub notes: Option<String>,
    pub discovered_via_tool: Option<String>,
    /// All entities (across person + business tables) sharing this
    /// identifier's dedup key. Length ≥1 always (at least the row that
    /// was clicked). Length ≥2 means this is a SHARED identifier — the
    /// high-signal case for investigators.
    pub owners: Vec<IdentifierOwner>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IdentifierOwner {
    pub entity_id: i64,
    pub display_name: String,
    /// Always `"person"` or `"business"`.
    pub entity_type: String,
}

// ─── Public entry point ──────────────────────────────────────────────────────

/// Resolve a canvas namespaced node id to a populated inspector payload.
/// Returns `InspectorPayload::NotFound` if the prefix is unrecognized,
/// the suffix doesn't parse as the expected type, or the underlying row
/// has been soft-deleted (or never existed for this case).
pub async fn build_inspector(
    pool: &SqlitePool,
    case_id: &str,
    node_id: &str,
) -> Result<InspectorPayload, AppError> {
    if let Some(rest) = node_id.strip_prefix("entity:") {
        let Ok(entity_id) = rest.parse::<i64>() else {
            return Ok(InspectorPayload::NotFound);
        };
        return load_entity(pool, case_id, entity_id).await;
    }
    if let Some(rest) = node_id.strip_prefix("evidence:") {
        return load_evidence(pool, case_id, rest).await;
    }
    if let Some(rest) = node_id.strip_prefix("identifier:") {
        let Ok(identifier_id) = rest.parse::<i64>() else {
            return Ok(InspectorPayload::NotFound);
        };
        return load_identifier(pool, case_id, identifier_id).await;
    }
    Ok(InspectorPayload::NotFound)
}

// ─── Entity loader ───────────────────────────────────────────────────────────

async fn load_entity(
    pool: &SqlitePool,
    case_id: &str,
    entity_id: i64,
) -> Result<InspectorPayload, AppError> {
    #[derive(sqlx::FromRow)]
    struct Row {
        entity_id: i64,
        entity_type: String,
        display_name: String,
        subtype: Option<String>,
        photo_path: Option<String>,
        email: Option<String>,
        phone: Option<String>,
        username: Option<String>,
        employer: Option<String>,
        dob: Option<String>,
        notes: Option<String>,
    }

    let row: Option<Row> = sqlx::query_as::<_, Row>(
        r#"SELECT entity_id, entity_type, display_name, subtype,
                  photo_path, email, phone, username, employer, dob, notes
           FROM entities
           WHERE case_id = ? AND entity_id = ? AND is_deleted = 0"#,
    )
    .bind(case_id)
    .bind(entity_id)
    .fetch_optional(pool)
    .await?;

    let Some(row) = row else {
        return Ok(InspectorPayload::NotFound);
    };

    // Identifiers — query the table matching entity_type. The validation
    // at insert time guarantees only person identifiers point to person
    // entities and only business identifiers to business entities.
    let identifiers: Vec<EntityIdentifier> = match row.entity_type.as_str() {
        "person" => sqlx::query_as::<_, EntityIdentifier>(
            r#"SELECT identifier_id, kind, value, platform, notes, discovered_via_tool
               FROM person_identifiers
               WHERE entity_id = ? AND is_deleted = 0
               ORDER BY identifier_id ASC"#,
        )
        .bind(entity_id)
        .fetch_all(pool)
        .await?,
        "business" => sqlx::query_as::<_, EntityIdentifier>(
            r#"SELECT identifier_id, kind, value, platform, notes, discovered_via_tool
               FROM business_identifiers
               WHERE entity_id = ? AND is_deleted = 0
               ORDER BY identifier_id ASC"#,
        )
        .bind(entity_id)
        .fetch_all(pool)
        .await?,
        _ => Vec::new(),
    };

    // Counts — entity_links are namespaced by source_type/source_id,
    // target_type/target_id (strings). For an entity, we count rows
    // where it's either source or target.
    let entity_id_str = entity_id.to_string();

    let linked_entity_count: i64 = sqlx::query_scalar(
        r#"SELECT COUNT(*) FROM entity_links
           WHERE case_id = ? AND is_deleted = 0
             AND (
               (source_type = 'entity' AND source_id = ?
                  AND target_type = 'entity' AND target_id != ?)
               OR
               (target_type = 'entity' AND target_id = ?
                  AND source_type = 'entity' AND source_id != ?)
             )"#,
    )
    .bind(case_id)
    .bind(&entity_id_str)
    .bind(&entity_id_str)
    .bind(&entity_id_str)
    .bind(&entity_id_str)
    .fetch_one(pool)
    .await?;

    let linked_evidence_count: i64 = sqlx::query_scalar(
        r#"SELECT COUNT(*) FROM entity_links
           WHERE case_id = ? AND is_deleted = 0
             AND (
               (source_type = 'entity' AND source_id = ? AND target_type = 'evidence')
               OR
               (target_type = 'entity' AND target_id = ? AND source_type = 'evidence')
             )"#,
    )
    .bind(case_id)
    .bind(&entity_id_str)
    .bind(&entity_id_str)
    .fetch_one(pool)
    .await?;

    Ok(InspectorPayload::Entity(EntityInspectorView {
        entity_id: row.entity_id,
        entity_type: row.entity_type,
        display_name: row.display_name,
        subtype: row.subtype,
        photo_path: row.photo_path,
        email: row.email,
        phone: row.phone,
        username: row.username,
        employer: row.employer,
        dob: row.dob,
        notes: row.notes,
        identifiers,
        linked_entity_count,
        linked_evidence_count,
    }))
}

// ─── Evidence loader ─────────────────────────────────────────────────────────

async fn load_evidence(
    pool: &SqlitePool,
    case_id: &str,
    evidence_id: &str,
) -> Result<InspectorPayload, AppError> {
    let evidence: Option<Evidence> = sqlx::query_as::<_, Evidence>(
        r#"SELECT evidence_id, case_id, description, collected_by,
                  collection_datetime, location, status, evidence_type,
                  make_model, serial_number, storage_location
           FROM evidence
           WHERE case_id = ? AND evidence_id = ?"#,
    )
    .bind(case_id)
    .bind(evidence_id)
    .fetch_optional(pool)
    .await?;

    let Some(evidence) = evidence else {
        return Ok(InspectorPayload::NotFound);
    };

    let linked_entity_count: i64 = sqlx::query_scalar(
        r#"SELECT COUNT(*) FROM entity_links
           WHERE case_id = ? AND is_deleted = 0
             AND (
               (source_type = 'evidence' AND source_id = ? AND target_type = 'entity')
               OR
               (target_type = 'evidence' AND target_id = ? AND source_type = 'entity')
             )"#,
    )
    .bind(case_id)
    .bind(evidence_id)
    .bind(evidence_id)
    .fetch_one(pool)
    .await?;

    let hash_verification_count: i64 = sqlx::query_scalar(
        r#"SELECT COUNT(*) FROM hash_verification WHERE evidence_id = ?"#,
    )
    .bind(evidence_id)
    .fetch_one(pool)
    .await?;

    let latest_custody: Option<CustodyEventSummary> = sqlx::query_as::<_, CustodyEventSummary>(
        r#"SELECT action, from_party, to_party, custody_datetime, location
           FROM chain_of_custody
           WHERE evidence_id = ?
           ORDER BY custody_datetime DESC
           LIMIT 1"#,
    )
    .bind(evidence_id)
    .fetch_optional(pool)
    .await?;

    Ok(InspectorPayload::Evidence(EvidenceInspectorView {
        evidence,
        linked_entity_count,
        hash_verification_count,
        latest_custody,
    }))
}

// ─── Identifier loader ───────────────────────────────────────────────────────

async fn load_identifier(
    pool: &SqlitePool,
    case_id: &str,
    identifier_id: i64,
) -> Result<InspectorPayload, AppError> {
    // Step 1: locate the canonical row by identifier_id in either table.
    // The graph's canonical id format is `identifier:<lowest identifier_id
    // for this dedup key>` — could come from either table. We try person
    // first; failing that, business. If neither hits, the node was stale
    // (soft-deleted after the graph was rendered) → NotFound.
    #[derive(sqlx::FromRow)]
    struct CanonicalRow {
        kind: String,
        value: String,
        platform: Option<String>,
        notes: Option<String>,
        discovered_via_tool: Option<String>,
    }

    // CRITICAL: include case_id in the lookup. An identifier_id is
    // table-local, but the same identifier_id could exist in another
    // case's data. Filter via the parent entity's case_id.
    let person_row: Option<CanonicalRow> = sqlx::query_as::<_, CanonicalRow>(
        r#"SELECT pi.kind, pi.value, pi.platform, pi.notes, pi.discovered_via_tool
           FROM person_identifiers pi
           JOIN entities e ON pi.entity_id = e.entity_id
           WHERE pi.identifier_id = ?
             AND pi.is_deleted = 0
             AND e.case_id = ?
             AND e.is_deleted = 0"#,
    )
    .bind(identifier_id)
    .bind(case_id)
    .fetch_optional(pool)
    .await?;

    let canonical = if let Some(p) = person_row {
        p
    } else {
        let business_row: Option<CanonicalRow> = sqlx::query_as::<_, CanonicalRow>(
            r#"SELECT bi.kind, bi.value, bi.platform, bi.notes, bi.discovered_via_tool
               FROM business_identifiers bi
               JOIN entities e ON bi.entity_id = e.entity_id
               WHERE bi.identifier_id = ?
                 AND bi.is_deleted = 0
                 AND e.case_id = ?
                 AND e.is_deleted = 0"#,
        )
        .bind(identifier_id)
        .bind(case_id)
        .fetch_optional(pool)
        .await?;

        let Some(b) = business_row else {
            return Ok(InspectorPayload::NotFound);
        };
        b
    };

    // Step 2: find ALL owners across both tables sharing the dedup key.
    // We use SQL's LOWER + TRIM to mirror the Rust `normalize_ident`
    // applied at graph-build time. Empty platform on either side
    // (NULL or whitespace-only) normalizes to '' for consistent join.
    let value_norm = canonical.value.trim().to_lowercase();
    let platform_norm = canonical
        .platform
        .as_deref()
        .map(|p| p.trim().to_lowercase())
        .unwrap_or_default();

    #[derive(sqlx::FromRow)]
    struct OwnerRow {
        entity_id: i64,
        display_name: String,
        entity_type: String,
    }

    let owner_rows: Vec<OwnerRow> = sqlx::query_as::<_, OwnerRow>(
        r#"
        SELECT e.entity_id, e.display_name, e.entity_type
        FROM person_identifiers pi
        JOIN entities e ON pi.entity_id = e.entity_id
        WHERE pi.kind = ?
          AND LOWER(TRIM(pi.value)) = ?
          AND COALESCE(LOWER(TRIM(pi.platform)), '') = ?
          AND pi.is_deleted = 0
          AND e.is_deleted = 0
          AND e.case_id = ?
        UNION
        SELECT e.entity_id, e.display_name, e.entity_type
        FROM business_identifiers bi
        JOIN entities e ON bi.entity_id = e.entity_id
        WHERE bi.kind = ?
          AND LOWER(TRIM(bi.value)) = ?
          AND COALESCE(LOWER(TRIM(bi.platform)), '') = ?
          AND bi.is_deleted = 0
          AND e.is_deleted = 0
          AND e.case_id = ?
        ORDER BY display_name ASC
        "#,
    )
    .bind(&canonical.kind)
    .bind(&value_norm)
    .bind(&platform_norm)
    .bind(case_id)
    .bind(&canonical.kind)
    .bind(&value_norm)
    .bind(&platform_norm)
    .bind(case_id)
    .fetch_all(pool)
    .await?;

    let owners: Vec<IdentifierOwner> = owner_rows
        .into_iter()
        .map(|r| IdentifierOwner {
            entity_id: r.entity_id,
            display_name: r.display_name,
            entity_type: r.entity_type,
        })
        .collect();

    Ok(InspectorPayload::Identifier(IdentifierInspectorView {
        kind: canonical.kind,
        value: canonical.value,
        platform: canonical.platform,
        notes: canonical.notes,
        discovered_via_tool: canonical.discovered_via_tool,
        owners,
    }))
}
