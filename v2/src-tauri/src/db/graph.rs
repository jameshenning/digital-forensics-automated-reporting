/// Graph and crime-line aggregate queries — Phase 4.
///
/// Two aggregate read-only functions that power the link analysis page:
///
/// - `build_graph`      — assembles a Cytoscape.js-friendly node+edge payload
///                        for a case, with optional entity-type filter and
///                        include_evidence toggle.
/// - `build_crime_line` — unions case_events + evidence + chain_of_custody +
///                        hash_verification + tool_usage + analysis_notes into
///                        a vis-timeline-compatible items+groups payload.
///
/// Mirrors v1's `get_case_graph` and `get_case_timeline` from `app/database.py`.
/// v2 difference: graph nodes use Cytoscape.js `id` format, not vis-network's
/// integer IDs.  Everything else matches v1 row-for-row on the same DB.
use chrono::NaiveDateTime;
use serde::{Deserialize, Serialize};
use sqlx::SqlitePool;

use crate::error::AppError;

// ─── Graph types ──────────────────────────────────────────────────────────────

/// A single node in the Cytoscape graph.
///
/// `id` is namespaced: `"entity:<entity_id>"` or `"evidence:<evidence_id>"`
/// so they never collide across tables.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GraphNode {
    /// Namespaced id: `"entity:<id>"` or `"evidence:<id>"`.
    pub id: String,
    pub label: String,
    /// `"entity"` or `"evidence"`.
    pub kind: String,
    /// entity_type if kind == "entity", else None.
    pub entity_type: Option<String>,
    /// subtype if kind == "entity" and entity has one.
    pub subtype: Option<String>,
}

/// A single edge in the Cytoscape graph.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GraphEdge {
    /// `"link:<link_id>"`.
    pub id: String,
    /// Matches a `GraphNode.id`.
    pub source: String,
    /// Matches a `GraphNode.id`.
    pub target: String,
    pub label: Option<String>,
    pub directional: bool,
    pub weight: f64,
}

/// Full graph payload — returned by `case_graph` command.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GraphPayload {
    pub nodes: Vec<GraphNode>,
    pub edges: Vec<GraphEdge>,
}

/// Filter parameters for `build_graph`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GraphFilter {
    /// If `Some`, only entity nodes with a matching entity_type are included.
    /// `None` → include all entity types.
    pub entity_types: Option<Vec<String>>,
    /// If `false`, no evidence nodes are included.  Default: `true`.
    pub include_evidence: bool,
}

// ─── Timeline types ───────────────────────────────────────────────────────────

/// A single item on the crime-line timeline.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TimelineItem {
    /// Namespaced id, e.g. `"event:42"` or `"auto:evidence:EV-001"`.
    pub id: String,
    /// Matches a `TimelineGroup.id`.
    pub group: String,
    /// Display text shown in the timeline widget.
    pub content: String,
    pub start: NaiveDateTime,
    pub end: Option<NaiveDateTime>,
    pub category: Option<String>,
    /// `"investigator"` (authored) or `"auto"` (system-derived).
    pub source_type: String,
    /// The source table name.
    pub source_table: String,
}

/// A lane/group definition for the vis-timeline widget.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TimelineGroup {
    pub id: String,
    pub content: String,
}

/// Full timeline payload — returned by `case_crime_line` command.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TimelinePayload {
    pub items: Vec<TimelineItem>,
    pub groups: Vec<TimelineGroup>,
}

/// Date-range filter for `build_crime_line`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TimelineFilter {
    /// Inclusive lower bound. `None` → no lower bound.
    pub start: Option<NaiveDateTime>,
    /// Inclusive upper bound. `None` → no upper bound.
    pub end: Option<NaiveDateTime>,
}

// ─── Internal row types (sqlx::FromRow, not exported) ───────────────────────

#[derive(sqlx::FromRow)]
struct EntityRow {
    entity_id: i64,
    entity_type: String,
    display_name: String,
    subtype: Option<String>,
}

#[derive(sqlx::FromRow)]
struct EvidenceRow {
    evidence_id: String,
}

#[derive(sqlx::FromRow)]
struct LinkRow {
    link_id: i64,
    source_type: String,
    source_id: String,
    target_type: String,
    target_id: String,
    link_label: Option<String>,
    directional: i64,
    weight: f64,
}

// ─── Graph assembly ───────────────────────────────────────────────────────────

/// Build a Cytoscape.js-friendly graph payload for a case.
///
/// Steps:
/// 1. Load entities for the case (soft-delete filtered, entity_type filtered if set).
/// 2. If `filter.include_evidence`, load evidence and emit evidence nodes.
/// 3. Load active links; emit an edge only if both endpoints are in the node set.
pub async fn build_graph(
    pool: &SqlitePool,
    case_id: &str,
    filter: &GraphFilter,
) -> Result<GraphPayload, AppError> {
    // 1. Load entities
    let entity_rows: Vec<EntityRow> = if let Some(ref types) = filter.entity_types {
        if types.is_empty() {
            Vec::new()
        } else {
            // SQLite doesn't support array binding; build a parameterised IN clause.
            let placeholders = types.iter().map(|_| "?").collect::<Vec<_>>().join(", ");
            let sql = format!(
                r#"SELECT entity_id, entity_type, display_name, subtype
                   FROM entities
                   WHERE case_id = ? AND is_deleted = 0 AND entity_type IN ({placeholders})
                   ORDER BY entity_type ASC, display_name ASC"#
            );
            let mut q = sqlx::query_as::<_, EntityRow>(&sql).bind(case_id);
            for t in types {
                q = q.bind(t);
            }
            q.fetch_all(pool).await?
        }
    } else {
        sqlx::query_as::<_, EntityRow>(
            r#"SELECT entity_id, entity_type, display_name, subtype
               FROM entities
               WHERE case_id = ? AND is_deleted = 0
               ORDER BY entity_type ASC, display_name ASC"#,
        )
        .bind(case_id)
        .fetch_all(pool)
        .await?
    };

    // Build the node set and the id→present lookup in one pass.
    let mut nodes: Vec<GraphNode> = Vec::with_capacity(entity_rows.len());
    let mut node_ids: std::collections::HashSet<String> =
        std::collections::HashSet::with_capacity(entity_rows.len());

    for e in &entity_rows {
        let id = format!("entity:{}", e.entity_id);
        nodes.push(GraphNode {
            id: id.clone(),
            label: e.display_name.clone(),
            kind: "entity".into(),
            entity_type: Some(e.entity_type.clone()),
            subtype: e.subtype.clone(),
        });
        node_ids.insert(id);
    }

    // 2. Evidence nodes (if requested)
    if filter.include_evidence {
        let ev_rows: Vec<EvidenceRow> = sqlx::query_as::<_, EvidenceRow>(
            r#"SELECT evidence_id
               FROM evidence
               WHERE case_id = ?
               ORDER BY collection_datetime ASC"#,
        )
        .bind(case_id)
        .fetch_all(pool)
        .await?;

        for ev in &ev_rows {
            let id = format!("evidence:{}", ev.evidence_id);
            nodes.push(GraphNode {
                id: id.clone(),
                label: ev.evidence_id.clone(),
                kind: "evidence".into(),
                entity_type: None,
                subtype: None,
            });
            node_ids.insert(id);
        }
    }

    // 3. Load active links and emit edges only if both endpoints are in the node set.
    let link_rows: Vec<LinkRow> = sqlx::query_as::<_, LinkRow>(
        r#"SELECT link_id, source_type, source_id, target_type, target_id,
                  link_label, directional, weight
           FROM entity_links
           WHERE case_id = ? AND is_deleted = 0"#,
    )
    .bind(case_id)
    .fetch_all(pool)
    .await?;

    let mut edges: Vec<GraphEdge> = Vec::with_capacity(link_rows.len());
    for lk in &link_rows {
        let source_node = format!("{}:{}", lk.source_type, lk.source_id);
        let target_node = format!("{}:{}", lk.target_type, lk.target_id);
        if node_ids.contains(&source_node) && node_ids.contains(&target_node) {
            edges.push(GraphEdge {
                id: format!("link:{}", lk.link_id),
                source: source_node,
                target: target_node,
                label: lk.link_label.clone(),
                directional: lk.directional != 0,
                weight: lk.weight,
            });
        }
    }

    Ok(GraphPayload { nodes, edges })
}

// ─── Crime-line assembly ──────────────────────────────────────────────────────

/// Build a vis-timeline-compatible crime-line payload for a case.
///
/// Unions 6 sources: case_events, evidence, chain_of_custody,
/// hash_verification, tool_usage, analysis_notes. Applies date-range
/// filter if provided.  Items are sorted by start ASC.
///
/// Mirrors v1's `get_case_timeline` exactly, adapted for Rust types.
pub async fn build_crime_line(
    pool: &SqlitePool,
    case_id: &str,
    filter: &TimelineFilter,
) -> Result<TimelinePayload, AppError> {
    let mut items: Vec<TimelineItem> = Vec::new();

    let in_range = |dt: NaiveDateTime| -> bool {
        if let Some(start) = filter.start {
            if dt < start {
                return false;
            }
        }
        if let Some(end) = filter.end {
            if dt > end {
                return false;
            }
        }
        true
    };

    // 1. Investigator events (case_events, soft-delete filtered)
    {
        #[derive(sqlx::FromRow)]
        struct EvRow {
            event_id: i64,
            title: String,
            event_datetime: NaiveDateTime,
            event_end_datetime: Option<NaiveDateTime>,
            category: Option<String>,
        }

        let rows: Vec<EvRow> = sqlx::query_as::<_, EvRow>(
            r#"SELECT event_id, title, event_datetime, event_end_datetime, category
               FROM case_events
               WHERE case_id = ? AND is_deleted = 0"#,
        )
        .bind(case_id)
        .fetch_all(pool)
        .await?;

        for r in rows {
            if in_range(r.event_datetime) {
                items.push(TimelineItem {
                    id: format!("event:{}", r.event_id),
                    group: "events".into(),
                    content: r.title,
                    start: r.event_datetime,
                    end: r.event_end_datetime,
                    category: r.category,
                    source_type: "investigator".into(),
                    source_table: "case_events".into(),
                });
            }
        }
    }

    // 2. Evidence collection timestamps
    {
        #[derive(sqlx::FromRow)]
        struct EvRow {
            evidence_id: String,
            description: String,
            collection_datetime: NaiveDateTime,
        }

        let rows: Vec<EvRow> = sqlx::query_as::<_, EvRow>(
            r#"SELECT evidence_id, description, collection_datetime
               FROM evidence
               WHERE case_id = ?"#,
        )
        .bind(case_id)
        .fetch_all(pool)
        .await?;

        for r in rows {
            if in_range(r.collection_datetime) {
                items.push(TimelineItem {
                    id: format!("auto:evidence:{}", r.evidence_id),
                    group: "evidence".into(),
                    content: format!("Collected: {}", r.description),
                    start: r.collection_datetime,
                    end: None,
                    category: None,
                    source_type: "auto".into(),
                    source_table: "evidence".into(),
                });
            }
        }
    }

    // 3. Chain of custody transfers
    {
        #[derive(sqlx::FromRow)]
        struct CocRow {
            custody_id: i64,
            action: String,
            from_party: String,
            to_party: String,
            custody_datetime: NaiveDateTime,
        }

        let rows: Vec<CocRow> = sqlx::query_as::<_, CocRow>(
            r#"SELECT c.custody_id, c.action, c.from_party, c.to_party, c.custody_datetime
               FROM chain_of_custody c
               JOIN evidence e ON c.evidence_id = e.evidence_id
               WHERE e.case_id = ?"#,
        )
        .bind(case_id)
        .fetch_all(pool)
        .await?;

        for r in rows {
            if in_range(r.custody_datetime) {
                items.push(TimelineItem {
                    id: format!("auto:custody:{}", r.custody_id),
                    group: "custody".into(),
                    content: format!("{}: {} → {}", r.action, r.from_party, r.to_party),
                    start: r.custody_datetime,
                    end: None,
                    category: None,
                    source_type: "auto".into(),
                    source_table: "chain_of_custody".into(),
                });
            }
        }
    }

    // 4. Hash verifications
    {
        #[derive(sqlx::FromRow)]
        struct HashRow {
            hash_id: i64,
            algorithm: String,
            verified_by: String,
            verification_datetime: NaiveDateTime,
        }

        let rows: Vec<HashRow> = sqlx::query_as::<_, HashRow>(
            r#"SELECT h.hash_id, h.algorithm, h.verified_by, h.verification_datetime
               FROM hash_verification h
               JOIN evidence e ON h.evidence_id = e.evidence_id
               WHERE e.case_id = ?"#,
        )
        .bind(case_id)
        .fetch_all(pool)
        .await?;

        for r in rows {
            if in_range(r.verification_datetime) {
                items.push(TimelineItem {
                    id: format!("auto:hash:{}", r.hash_id),
                    group: "hashes".into(),
                    content: format!("{} verified by {}", r.algorithm, r.verified_by),
                    start: r.verification_datetime,
                    end: None,
                    category: None,
                    source_type: "auto".into(),
                    source_table: "hash_verification".into(),
                });
            }
        }
    }

    // 5. Tool usage
    {
        #[derive(sqlx::FromRow)]
        struct ToolRow {
            tool_id: i64,
            tool_name: String,
            version: Option<String>,
            purpose: String,
            execution_datetime: NaiveDateTime,
        }

        let rows: Vec<ToolRow> = sqlx::query_as::<_, ToolRow>(
            r#"SELECT tool_id, tool_name, version, purpose, execution_datetime
               FROM tool_usage
               WHERE case_id = ?"#,
        )
        .bind(case_id)
        .fetch_all(pool)
        .await?;

        for r in rows {
            if in_range(r.execution_datetime) {
                let version_or_empty = r.version.as_deref().unwrap_or("");
                items.push(TimelineItem {
                    id: format!("auto:tool:{}", r.tool_id),
                    group: "tools".into(),
                    content: format!("{} ({}): {}", r.tool_name, version_or_empty, r.purpose),
                    start: r.execution_datetime,
                    end: None,
                    category: None,
                    source_type: "auto".into(),
                    source_table: "tool_usage".into(),
                });
            }
        }
    }

    // 6. Analysis notes
    {
        #[derive(sqlx::FromRow)]
        struct NoteRow {
            note_id: i64,
            category: String,
            finding: String,
            created_at: NaiveDateTime,
        }

        let rows: Vec<NoteRow> = sqlx::query_as::<_, NoteRow>(
            r#"SELECT note_id, category, finding, created_at
               FROM analysis_notes
               WHERE case_id = ?"#,
        )
        .bind(case_id)
        .fetch_all(pool)
        .await?;

        for r in rows {
            if in_range(r.created_at) {
                // Truncate finding to 100 chars for the content field
                let finding_truncated: String = r.finding.chars().take(100).collect();
                items.push(TimelineItem {
                    id: format!("auto:analysis:{}", r.note_id),
                    group: "analysis".into(),
                    content: format!("[{}] {}", r.category, finding_truncated),
                    start: r.created_at,
                    end: None,
                    category: Some(r.category),
                    source_type: "auto".into(),
                    source_table: "analysis_notes".into(),
                });
            }
        }
    }

    // Sort all items by start ASC
    items.sort_by_key(|item| item.start);

    // Hardcoded stable groups (order matches v1's group list)
    let groups = vec![
        TimelineGroup {
            id: "events".into(),
            content: "Investigator events".into(),
        },
        TimelineGroup {
            id: "evidence".into(),
            content: "Evidence collection".into(),
        },
        TimelineGroup {
            id: "custody".into(),
            content: "Chain of custody".into(),
        },
        TimelineGroup {
            id: "hashes".into(),
            content: "Hash verifications".into(),
        },
        TimelineGroup {
            id: "tools".into(),
            content: "Tool usage".into(),
        },
        TimelineGroup {
            id: "analysis".into(),
            content: "Analysis notes".into(),
        },
    ];

    Ok(TimelinePayload { items, groups })
}
