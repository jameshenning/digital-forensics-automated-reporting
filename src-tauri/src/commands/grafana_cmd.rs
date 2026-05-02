/// Grafana lifecycle Tauri commands.
///
/// Commands:
///   - `grafana_get_settings`  — read current Grafana config from AppConfig
///   - `grafana_set_settings`  — enable/disable, regenerate service token
///   - `grafana_start`         — write provisioning files, run `docker compose up -d grafana`
///   - `grafana_stop`          — run `docker compose stop grafana`
///   - `grafana_status`        — check if Grafana container is running
use std::sync::Arc;

use serde::{Deserialize, Serialize};
use tauri::State;

use crate::{
    auth::session::require_session,
    config,
    db::grafana,
    error::AppError,
    state::AppState,
};

// ---------------------------------------------------------------------------
// Data types
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize)]
pub struct GrafanaSettings {
    pub enabled: bool,
    pub running: bool,
    pub url: String,
    pub docker_available: bool,
}

#[derive(Debug, Clone, Deserialize)]
pub struct GrafanaSetInput {
    pub enabled: bool,
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn generate_grafana_token() -> String {
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
    use rand::Rng;
    let mut rng = rand::thread_rng();
    let bytes: Vec<u8> = (0..32).map(|_| rng.gen()).collect();
    format!("grafana_{}", URL_SAFE_NO_PAD.encode(&bytes))
}

/// Return the directory where docker-compose.yml lives (project root).
fn project_root() -> std::path::PathBuf {
    // In dev: cargo runs from src-tauri/, so walk up to the project root.
    // In production: the executable may be nested, so walk up looking for
    // docker-compose.yml.
    let mut dir = std::env::current_dir().unwrap_or_else(|_| std::path::PathBuf::from("."));
    loop {
        if dir.join("docker-compose.yml").exists() || dir.join("package.json").exists() {
            return dir;
        }
        if !dir.pop() {
            // Fallback to current_dir if we can't find the project root
            return std::env::current_dir().unwrap_or_else(|_| std::path::PathBuf::from("."));
        }
    }
}

/// Write the Grafana datasource provisioning file with the current service token.
fn write_datasource_provisioning(token: &str) -> Result<(), AppError> {
    let root = project_root();
    let prov_dir = root.join("grafana").join("provisioning").join("datasources");
    std::fs::create_dir_all(&prov_dir)
        .map_err(|e| AppError::Io(format!("grafana provisioning dir: {e}")))?;

    let yaml = format!(
        r#"apiVersion: 1

datasources:
  - name: DFARS
    type: marcusolsson-json-datasource
    access: proxy
    url: http://host.docker.internal:5099/api/v1/grafana
    jsonData:
      httpHeaderName1: Authorization
    secureJsonData:
      httpHeaderValue1: Bearer {token}
"#
    );

    std::fs::write(prov_dir.join("dfars.yml"), yaml)
        .map_err(|e| AppError::Io(format!("grafana datasource prov: {e}")))?;
    Ok(())
}

/// Check whether the Grafana Docker container is running AND Grafana's
/// HTTP server is actually responding to requests.
async fn is_grafana_running() -> bool {
    // First: is the container even up?
    let docker_ok = match tokio::process::Command::new("docker")
        .args(["ps", "-q", "-f", "name=dfars-grafana"])
        .output()
        .await
    {
        Ok(o) => !o.stdout.is_empty(),
        Err(_) => return false,
    };

    if !docker_ok {
        return false;
    }

    // Second: is Grafana's web server ready inside the container?
    // Give it a short timeout so we don't block the UI.
    match tokio::time::timeout(
        std::time::Duration::from_secs(2),
        reqwest::get("http://localhost:3099/api/health"),
    )
    .await
    {
        Ok(Ok(resp)) => resp.status().is_success(),
        _ => false,
    }
}

/// Check whether Docker (desktop) is installed and the daemon is reachable.
async fn is_docker_available() -> bool {
    match tokio::process::Command::new("docker")
        .args(["version", "--format", "{{.Server.Version}}"])
        .output()
        .await
    {
        Ok(o) => o.status.success(),
        Err(_) => false,
    }
}

// ---------------------------------------------------------------------------
// Commands
// ---------------------------------------------------------------------------

#[tauri::command(rename_all = "snake_case")]
pub async fn grafana_get_settings(
    token: String,
    state: State<'_, Arc<AppState>>,
) -> Result<GrafanaSettings, AppError> {
    let _session = require_session(&state, &token)?;
    let cfg = config::load(&state.config_path).unwrap_or_else(|_| state.config.clone());
    let running = is_grafana_running().await;
    let docker_available = is_docker_available().await;
    Ok(GrafanaSettings {
        enabled: cfg.grafana_enabled,
        running,
        url: "http://localhost:3099".into(),
        docker_available,
    })
}

#[tauri::command(rename_all = "snake_case")]
pub async fn grafana_set_settings(
    token: String,
    input: GrafanaSetInput,
    state: State<'_, Arc<AppState>>,
) -> Result<GrafanaSettings, AppError> {
    let _session = require_session(&state, &token)?;

    let mut cfg = config::load(&state.config_path).unwrap_or_else(|_| state.config.clone());
    let previously_enabled = cfg.grafana_enabled;
    cfg.grafana_enabled = input.enabled;

    // Generate a service token the first time Grafana is enabled.
    if input.enabled && cfg.grafana_service_token.is_none() {
        cfg.grafana_service_token = Some(generate_grafana_token());
    }

    config::save(&state.config_path, &cfg)?;

    // Only write provisioning files when transitioning from disabled → enabled.
    // This prevents Vite file-watcher reload loops in dev mode.
    if input.enabled && !previously_enabled {
        if let Some(t) = &cfg.grafana_service_token {
            write_datasource_provisioning(t)?;
        }
    }

    let running = is_grafana_running().await;
    let docker_available = is_docker_available().await;
    Ok(GrafanaSettings {
        enabled: cfg.grafana_enabled,
        running,
        url: "http://localhost:3099".into(),
        docker_available,
    })
}

#[tauri::command(rename_all = "snake_case")]
pub async fn grafana_status(
    token: String,
    state: State<'_, Arc<AppState>>,
) -> Result<GrafanaSettings, AppError> {
    let _session = require_session(&state, &token)?;
    let cfg = config::load(&state.config_path).unwrap_or_else(|_| state.config.clone());
    let running = is_grafana_running().await;
    let docker_available = is_docker_available().await;
    Ok(GrafanaSettings {
        enabled: cfg.grafana_enabled,
        running,
        url: "http://localhost:3099".into(),
        docker_available,
    })
}

#[tauri::command(rename_all = "snake_case")]
pub async fn grafana_start(
    token: String,
    state: State<'_, Arc<AppState>>,
) -> Result<(), AppError> {
    let _session = require_session(&state, &token)?;

    let cfg = config::load(&state.config_path).unwrap_or_else(|_| state.config.clone());
    if !cfg.grafana_enabled {
        return Err(AppError::ValidationError {
            field: "grafana".into(),
            message: "Grafana is not enabled in settings.".into(),
        });
    }

    // Ensure provisioning file is up-to-date.
    if let Some(t) = &cfg.grafana_service_token {
        write_datasource_provisioning(t)?;
    }

    let root = project_root();
    let compose_file = root.join("docker-compose.yml");

    if !compose_file.exists() {
        return Err(AppError::Io(format!(
            "docker-compose.yml not found at {}",
            compose_file.display()
        )));
    }

    let output = tokio::process::Command::new("docker")
        .args([
            "compose",
            "-f",
            &compose_file.to_string_lossy(),
            "up",
            "-d",
            "--no-deps",
            "grafana",
        ])
        .current_dir(&root)
        .output()
        .await
        .map_err(|e| AppError::Io(format!("docker compose up failed: {e}")))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(AppError::Io(format!(
            "docker compose up failed: {stderr}"
        )));
    }

    Ok(())
}

#[tauri::command(rename_all = "snake_case")]
pub async fn grafana_stop(
    token: String,
    state: State<'_, Arc<AppState>>,
) -> Result<(), AppError> {
    let _session = require_session(&state, &token)?;

    let root = project_root();
    let compose_file = root.join("docker-compose.yml");

    let output = tokio::process::Command::new("docker")
        .args([
            "compose",
            "-f",
            &compose_file.to_string_lossy(),
            "stop",
            "grafana",
        ])
        .current_dir(&root)
        .output()
        .await
        .map_err(|e| AppError::Io(format!("docker compose stop failed: {e}")))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(AppError::Io(format!(
            "docker compose stop failed: {stderr}"
        )));
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Native dashboard commands — session-authenticated, no Docker required
// ---------------------------------------------------------------------------

#[tauri::command(rename_all = "snake_case")]
pub async fn case_dashboard_entity_stats(
    token: String,
    case_id: String,
    state: State<'_, Arc<AppState>>,
) -> Result<Vec<grafana::EntityTypeStat>, AppError> {
    let _session = require_session(&state, &token)?;
    grafana::entity_type_stats(&state.db.forensics, &case_id).await
}

#[tauri::command(rename_all = "snake_case")]
pub async fn case_dashboard_evidence_stats(
    token: String,
    case_id: String,
    state: State<'_, Arc<AppState>>,
) -> Result<Vec<grafana::EvidenceTypeStat>, AppError> {
    let _session = require_session(&state, &token)?;
    grafana::evidence_type_stats(&state.db.forensics, &case_id).await
}

#[tauri::command(rename_all = "snake_case")]
pub async fn case_dashboard_link_stats(
    token: String,
    case_id: String,
    state: State<'_, Arc<AppState>>,
) -> Result<Vec<grafana::LinkLabelStat>, AppError> {
    let _session = require_session(&state, &token)?;
    grafana::link_label_stats(&state.db.forensics, &case_id).await
}

#[tauri::command(rename_all = "snake_case")]
pub async fn case_dashboard_timeline(
    token: String,
    case_id: String,
    state: State<'_, Arc<AppState>>,
) -> Result<Vec<grafana::TimelineEvent>, AppError> {
    let _session = require_session(&state, &token)?;
    grafana::timeline_events(&state.db.forensics, &case_id).await
}

#[tauri::command(rename_all = "snake_case")]
pub async fn case_dashboard_graph(
    token: String,
    case_id: String,
    state: State<'_, Arc<AppState>>,
) -> Result<grafana::NodeGraphPayload, AppError> {
    let _session = require_session(&state, &token)?;
    grafana::node_graph_for_case(&state.db.forensics, &case_id).await
}

