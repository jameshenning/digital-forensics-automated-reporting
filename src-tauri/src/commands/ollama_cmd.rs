/// Local LLM (Ollama) Tauri commands.
///
/// Completely independent from Agent Zero. These commands talk directly to a
/// local Ollama instance (typically running in Docker at localhost:11434).
/// No API key is required. No data leaves the host machine.
use std::sync::Arc;

use serde::Serialize;
use tauri::State;
use tracing::{error, info};

use crate::audit;
use crate::auth::session::require_session;
use crate::config::{self, AppConfig};
use crate::error::AppError;
use crate::ollama::OllamaClient;
use crate::state::AppState;

// ─── Return types ─────────────────────────────────────────────────────────────

#[derive(Debug, Serialize)]
pub struct OllamaHealthResult {
    pub reachable: bool,
    pub model_loaded: bool,
    pub url: String,
    pub model: String,
}

// ─── Commands ─────────────────────────────────────────────────────────────────

/// Enhance a narrative text using the local Ollama LLM.
#[tauri::command(rename_all = "snake_case")]
pub async fn ollama_enhance(
    token: String,
    text: String,
    state: State<'_, Arc<AppState>>,
) -> Result<String, AppError> {
    let session = require_session(&state, &token)?;

    if text.is_empty() {
        return Err(AppError::ValidationError {
            field: "text".into(),
            message: "text must not be empty".into(),
        });
    }

    let cfg = fresh_config(&state);
    let url = cfg.ollama_url.as_deref();
    let model = cfg.ollama_model.as_deref();

    if url.is_none() && model.is_none() {
        // Fall back to defaults silently — Ollama is meant to be zero-config.
    }

    let client = OllamaClient::new(url, model, cfg.allow_custom_agent_zero_url)?;
    let result = client.enhance(&text).await;

    match &result {
        Ok(_) => info!(
            username = %session.username,
            action = audit::OLLAMA_ENHANCE_CALLED,
            "ollama_enhance succeeded"
        ),
        Err(e) => error!(
            username = %session.username,
            error = ?e,
            "ollama_enhance failed"
        ),
    }

    result
}

/// Health-check the Ollama server and verify the configured model is loaded.
#[tauri::command(rename_all = "snake_case")]
pub async fn ollama_health(
    token: String,
    state: State<'_, Arc<AppState>>,
) -> Result<OllamaHealthResult, AppError> {
    require_session(&state, &token)?;

    let cfg = fresh_config(&state);
    let url = cfg.ollama_url.as_deref().unwrap_or("http://localhost:11434");
    let model = cfg.ollama_model.as_deref().unwrap_or("mistral");

    let client = OllamaClient::new(Some(url), Some(model), cfg.allow_custom_agent_zero_url)?;

    let reachable = client.is_available().await.unwrap_or(false);
    let model_loaded = if reachable {
        client.model_loaded().await.unwrap_or(false)
    } else {
        false
    };

    Ok(OllamaHealthResult {
        reachable,
        model_loaded,
        url: url.to_owned(),
        model: model.to_owned(),
    })
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

fn fresh_config(state: &AppState) -> AppConfig {
    config::load(&state.config_path).unwrap_or_else(|_| state.config.clone())
}
