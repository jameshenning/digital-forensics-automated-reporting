/// Grafana data-source queries — read-only aggregations for dashboard panels.
///
/// All endpoints under `/api/v1/grafana/*` consume these structs directly.
/// They are intentionally flat (no nested objects) so Grafana's JSON API
/// plugin can map them to data frames without complex transformations.
use serde::{Deserialize, Serialize};
use sqlx::SqlitePool;

use crate::db::graph::{self, GraphFilter};
use crate::error::AppError;

// ---------------------------------------------------------------------------
// Node Graph types (Grafana Node Graph panel)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GrafanaNode {
    pub id: String,
    pub title: String,
    pub subtitle: String,
    pub main_stat: i64,
    pub color: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GrafanaEdge {
    pub id: String,
    pub source: String,
    pub target: String,
    pub main_stat: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NodeGraphPayload {
    pub nodes: Vec<GrafanaNode>,
    pub edges: Vec<GrafanaEdge>,
}

// ---------------------------------------------------------------------------
// Stat panel types
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct EntityTypeStat {
    pub entity_type: String,
    pub count: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct EvidenceTypeStat {
    pub evidence_type: String,
    pub count: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct LinkLabelStat {
    pub link_label: String,
    pub count: i64,
}

// ---------------------------------------------------------------------------
// Timeline types
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct TimelineEvent {
    /// Unix timestamp in milliseconds.
    pub time: i64,
    pub title: String,
    pub category: String,
}

// ---------------------------------------------------------------------------
// Node Graph
// ---------------------------------------------------------------------------

/// Build node/edge payloads for Grafana's Node Graph panel.
/// Reuses the existing `graph::build_graph()` and maps to Grafana field names.
pub async fn node_graph_for_case(
    pool: &SqlitePool,
    case_id: &str,
) -> Result<NodeGraphPayload, AppError> {
    let graph = graph::build_graph(
        pool,
        case_id,
        &GraphFilter {
            entity_types: None,
            include_evidence: true,
            include_identifiers: true,
            only_shared_identifiers: false,
        },
    )
    .await?;

    let nodes: Vec<GrafanaNode> = graph
        .nodes
        .into_iter()
        .map(|n| GrafanaNode {
            id: n.id,
            title: n.label,
            subtitle: n.entity_type.unwrap_or_default(),
            main_stat: 1,
            color: node_color(&n.kind, n.subtype.as_deref()),
        })
        .collect();

    let edges: Vec<GrafanaEdge> = graph
        .edges
        .into_iter()
        .map(|e| GrafanaEdge {
            id: e.id,
            source: e.source,
            target: e.target,
            main_stat: e.label.unwrap_or_default(),
        })
        .collect();

    Ok(NodeGraphPayload { nodes, edges })
}

fn node_color(kind: &str, subtype: Option<&str>) -> String {
    match kind {
        "entity" => match subtype {
            Some("suspect") => "red".into(),
            Some("victim") => "blue".into(),
            Some("witness") => "green".into(),
            Some("investigator") => "purple".into(),
            Some("business") => "orange".into(),
            _ => "gray".into(),
        },
        "evidence" => "cyan".into(),
        "identifier" => "yellow".into(),
        _ => "gray".into(),
    }
}

// ---------------------------------------------------------------------------
// Statistics
// ---------------------------------------------------------------------------

pub async fn entity_type_stats(
    pool: &SqlitePool,
    case_id: &str,
) -> Result<Vec<EntityTypeStat>, AppError> {
    let rows: Vec<EntityTypeStat> = sqlx::query_as(
        r#"
        SELECT entity_type, COUNT(*) AS count
        FROM entities
        WHERE case_id = ? AND is_deleted = 0
        GROUP BY entity_type
        ORDER BY count DESC
        "#,
    )
    .bind(case_id)
    .fetch_all(pool)
    .await?;
    Ok(rows)
}

pub async fn evidence_type_stats(
    pool: &SqlitePool,
    case_id: &str,
) -> Result<Vec<EvidenceTypeStat>, AppError> {
    let rows: Vec<EvidenceTypeStat> = sqlx::query_as(
        r#"
        SELECT COALESCE(evidence_type, 'Unknown') AS evidence_type, COUNT(*) AS count
        FROM evidence
        WHERE case_id = ?
        GROUP BY evidence_type
        ORDER BY count DESC
        "#,
    )
    .bind(case_id)
    .fetch_all(pool)
    .await?;
    Ok(rows)
}

pub async fn link_label_stats(
    pool: &SqlitePool,
    case_id: &str,
) -> Result<Vec<LinkLabelStat>, AppError> {
    let rows: Vec<LinkLabelStat> = sqlx::query_as(
        r#"
        SELECT link_label, COUNT(*) AS count
        FROM entity_links
        WHERE case_id = ? AND is_deleted = 0
        GROUP BY link_label
        ORDER BY count DESC
        "#,
    )
    .bind(case_id)
    .fetch_all(pool)
    .await?;
    Ok(rows)
}

// ---------------------------------------------------------------------------
// Timeline
// ---------------------------------------------------------------------------

pub async fn timeline_events(
    pool: &SqlitePool,
    case_id: &str,
) -> Result<Vec<TimelineEvent>, AppError> {
    let rows: Vec<(String, String, String)> = sqlx::query_as(
        r#"
        SELECT
            strftime('%s', event_datetime) * 1000 AS time,
            title,
            category
        FROM case_events
        WHERE case_id = ? AND is_deleted = 0
        ORDER BY event_datetime ASC
        "#,
    )
    .bind(case_id)
    .fetch_all(pool)
    .await?;

    Ok(rows
        .into_iter()
        .map(|(time_str, title, category)| TimelineEvent {
            time: time_str.parse().unwrap_or(0),
            title,
            category,
        })
        .collect())
}
