/// Integration settings Tauri commands — Phase 5.
///
/// Manages Agent Zero and SMTP configuration via `config.rs`.
///
/// Security constraints:
///   - Returned `AgentZeroSettings` NEVER includes the plaintext API key.
///     Only `api_key_set: bool` is returned to the frontend.
///   - Returned `SmtpSettings` NEVER includes the plaintext password.
///     Only `password_set: bool` is returned.
///   - Changing `agent_zero_url` triggers URL validation — invalid URLs
///     return `AppError::AgentZeroUrlRejected`.
///   - `shown_ai_summarize_consent` is set by `settings_acknowledge_ai_consent`
///     (MUST-DO 8).
use std::sync::Arc;

use serde::{Deserialize, Serialize};
use tauri::State;
use tracing::info;

use crate::agent_zero::AgentZeroClient;
use crate::audit;
use crate::auth::session::require_session;
use crate::config::{self, AppConfig};
use crate::error::AppError;
use crate::mailer::{self, SmtpConfig};
use crate::state::AppState;

// ─── Return types (never include plaintext secrets) ───────────────────────────

#[derive(Debug, Serialize)]
pub struct AgentZeroSettings {
    pub url: Option<String>,
    pub api_key_set: bool,
    pub allow_custom_url: bool,
    /// Serialized as "port" to match the TS AgentZeroSettings interface.
    #[serde(rename = "port")]
    pub axum_port: u16,
    pub bind_host: String,
    pub allow_network_bind: bool,
    /// Derived field: true when both url and api_key are set.
    pub is_configured: bool,
    /// Mirror of config.shown_ai_summarize_consent — used by AI consent dialog.
    pub shown_ai_summarize_consent: bool,
    /// Mirror of config.tor_enabled. When true, ai_osint_person tells Agent
    /// Zero to run the dark-web tool set alongside clearnet OSINT and uses
    /// the 1800s deep-search timeout tier.
    pub tor_enabled: bool,
}

/// Result shape for `settings_test_agent_zero`. Mirrors the TS
/// `AgentZeroTestResult` interface in `src/lib/bindings.ts`.  Previously the
/// Rust handler returned `()` which serialized as `null` on the IPC boundary
/// and crashed the frontend with "Cannot read properties of null (reading
/// 'plugin_version')" when the test succeeded.
#[derive(Debug, Serialize)]
pub struct AgentZeroTestResult {
    pub ok: bool,
    pub plugin_version: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct AgentZeroInput {
    pub url: Option<String>,
    /// Plaintext API key — encrypted before storage.
    pub api_key: Option<String>,
    pub allow_custom_url: Option<bool>,
    pub axum_port: Option<u16>,
    pub bind_host: Option<String>,
    pub allow_network_bind: Option<bool>,
    /// Opt-in for dark-web OSINT. Requires a Tor-capable Agent Zero
    /// container; failures surface as `AppError::TorUnavailable`.
    pub tor_enabled: Option<bool>,
}

#[derive(Debug, Serialize)]
pub struct SmtpSettings {
    pub host: Option<String>,
    pub port: Option<u16>,
    pub username: Option<String>,
    pub password_set: bool,
    pub from: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct SmtpInput {
    pub host: Option<String>,
    pub port: Option<u16>,
    pub username: Option<String>,
    /// Plaintext password — encrypted before storage.
    pub password: Option<String>,
    pub from: Option<String>,
}

// ─── Agent Zero settings ──────────────────────────────────────────────────────

#[tauri::command(rename_all = "snake_case")]
pub async fn settings_get_agent_zero(
    token: String,
    state: State<'_, Arc<AppState>>,
) -> Result<AgentZeroSettings, AppError> {
    require_session(&state, &token)?;
    let cfg = &state.config;
    let api_key_set = cfg.agent_zero_api_key_encrypted.is_some();
    let is_configured = cfg.agent_zero_url.is_some() && api_key_set;
    Ok(AgentZeroSettings {
        url: cfg.agent_zero_url.clone(),
        api_key_set,
        allow_custom_url: cfg.allow_custom_agent_zero_url,
        axum_port: cfg.axum_port,
        bind_host: cfg.bind_host.clone(),
        allow_network_bind: cfg.allow_network_bind,
        is_configured,
        shown_ai_summarize_consent: cfg.shown_ai_summarize_consent,
        tor_enabled: cfg.tor_enabled,
    })
}

#[tauri::command(rename_all = "snake_case")]
pub async fn settings_set_agent_zero(
    token: String,
    input: AgentZeroInput,
    state: State<'_, Arc<AppState>>,
) -> Result<(), AppError> {
    let session = require_session(&state, &token)?;

    // Clone the current config and apply mutations.
    let mut cfg = state.config.clone();

    if let Some(url) = &input.url {
        // Validate URL before persisting — MUST-DO 6.
        let allow_custom = input.allow_custom_url.unwrap_or(cfg.allow_custom_agent_zero_url);
        crate::agent_zero::validate_url_public(url, allow_custom)?;
        cfg.agent_zero_url = Some(url.clone());
    }

    if let Some(key) = input.api_key {
        if !key.is_empty() {
            let encrypted = state.crypto.encrypt(key.as_bytes());
            cfg.agent_zero_api_key_encrypted = Some(encrypted);
        }
    }

    if let Some(v) = input.allow_custom_url {
        cfg.allow_custom_agent_zero_url = v;
    }
    if let Some(p) = input.axum_port {
        cfg.axum_port = p;
    }
    if let Some(h) = input.bind_host {
        if h != "127.0.0.1" && h != "0.0.0.0" {
            return Err(AppError::ValidationError {
                field: "bind_host".into(),
                message: "bind_host must be '127.0.0.1' or '0.0.0.0'".into(),
            });
        }
        cfg.bind_host = h;
    }
    if let Some(v) = input.allow_network_bind {
        cfg.allow_network_bind = v;
    }
    if let Some(v) = input.tor_enabled {
        cfg.tor_enabled = v;
    }

    // Persist config.
    let config_path = state.config_path.clone();
    config::save(&config_path, &cfg)?;

    // Rebuild the Agent Zero client with the new settings.
    rebuild_agent_zero_client(&state, &cfg).await?;

    info!(username = %session.username, "Agent Zero settings updated");
    audit::log_auth(
        &format!("user:{}", session.username),
        audit::SETTINGS_CHANGED,
        "Agent Zero settings updated",
    );

    Ok(())
}

#[tauri::command(rename_all = "snake_case")]
pub async fn settings_test_agent_zero(
    token: String,
    state: State<'_, Arc<AppState>>,
) -> Result<AgentZeroTestResult, AppError> {
    require_session(&state, &token)?;

    let az = state.agent_zero.client.read().await;
    let client = az.as_ref().ok_or(AppError::AgentZeroNotConfigured)?;

    // Send a trivial enhance request as a connectivity test. Reaching the
    // plugin + passing the X-API-KEY check is the "ok" signal — whether the
    // upstream LLM responds with text or errors on credits is not relevant
    // for a connectivity test.
    client.enhance("test").await?;
    Ok(AgentZeroTestResult {
        ok: true,
        plugin_version: None,
    })
}

// ─── SMTP settings ────────────────────────────────────────────────────────────

#[tauri::command(rename_all = "snake_case")]
pub async fn settings_get_smtp(
    token: String,
    state: State<'_, Arc<AppState>>,
) -> Result<SmtpSettings, AppError> {
    require_session(&state, &token)?;
    let cfg = &state.config;
    Ok(SmtpSettings {
        host: cfg.smtp_host.clone(),
        port: cfg.smtp_port,
        username: cfg.smtp_username.clone(),
        password_set: cfg.smtp_password_encrypted.is_some(),
        from: cfg.smtp_from.clone(),
    })
}

#[tauri::command(rename_all = "snake_case")]
pub async fn settings_set_smtp(
    token: String,
    input: SmtpInput,
    state: State<'_, Arc<AppState>>,
) -> Result<(), AppError> {
    let session = require_session(&state, &token)?;

    let mut cfg = state.config.clone();

    if let Some(host) = input.host { cfg.smtp_host = Some(host); }
    if let Some(port) = input.port { cfg.smtp_port = Some(port); }
    if let Some(uname) = input.username { cfg.smtp_username = Some(uname); }
    if let Some(pw) = input.password {
        if !pw.is_empty() {
            let encrypted = state.crypto.encrypt(pw.as_bytes());
            cfg.smtp_password_encrypted = Some(encrypted);
        }
    }
    if let Some(from) = input.from { cfg.smtp_from = Some(from); }

    let config_path = state.config_path.clone();
    config::save(&config_path, &cfg)?;

    info!(username = %session.username, "SMTP settings updated");
    audit::log_auth(
        &format!("user:{}", session.username),
        audit::SETTINGS_CHANGED,
        "SMTP settings updated",
    );

    Ok(())
}

#[tauri::command(rename_all = "snake_case")]
pub async fn settings_test_smtp(
    token: String,
    to_address: String,
    state: State<'_, Arc<AppState>>,
) -> Result<(), AppError> {
    require_session(&state, &token)?;

    let smtp_cfg = build_smtp_config(&state)?;
    mailer::send_email(
        &smtp_cfg,
        &to_address,
        "DFARS SMTP Test",
        "This is a test email from DFARS Desktop v2.",
    )
    .await
}

// ─── Consent (MUST-DO 8) ─────────────────────────────────────────────────────

/// Acknowledge the AI summarize consent banner.
///
/// SEC-4 MUST-DO 8: sets `shown_ai_summarize_consent = true` in `config.json`.
/// After this, `ai_summarize_case` will proceed without returning
/// `AppError::AiSummarizeConsentRequired`.
#[tauri::command(rename_all = "snake_case")]
pub async fn settings_acknowledge_ai_consent(
    token: String,
    state: State<'_, Arc<AppState>>,
) -> Result<(), AppError> {
    let session = require_session(&state, &token)?;

    let mut cfg = state.config.clone();
    cfg.shown_ai_summarize_consent = true;
    let config_path = state.config_path.clone();
    config::save(&config_path, &cfg)?;

    info!(username = %session.username, "AI summarize consent acknowledged");
    audit::log_auth(
        &format!("user:{}", session.username),
        audit::SETTINGS_CHANGED,
        "ai_summarize_case consent acknowledged",
    );

    Ok(())
}

/// Acknowledge the separate OSINT consent banner.
///
/// Sets `shown_ai_osint_consent = true` in config.json AND flips the
/// runtime atomic on `AppState` so subsequent `ai_osint_person` calls can
/// proceed without restarting the app. Distinct from the AI summarize
/// consent because OSINT sends PII to external sources and is a
/// meaningfully different decision to make.
#[tauri::command(rename_all = "snake_case")]
pub async fn settings_acknowledge_osint_consent(
    token: String,
    state: State<'_, Arc<AppState>>,
) -> Result<(), AppError> {
    let session = require_session(&state, &token)?;

    let mut cfg = state.config.clone();
    cfg.shown_ai_osint_consent = true;
    let config_path = state.config_path.clone();
    config::save(&config_path, &cfg)?;

    // Flip the runtime atomic so the current process sees the change.
    state.set_osint_consent_granted(true);

    info!(username = %session.username, "OSINT consent acknowledged");
    audit::log_auth(
        &format!("user:{}", session.username),
        audit::OSINT_CONSENT_ACKNOWLEDGED,
        "ai_osint_person consent acknowledged",
    );

    Ok(())
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

fn build_smtp_config(state: &AppState) -> Result<SmtpConfig, AppError> {
    let cfg = &state.config;
    let host = cfg.smtp_host.clone().ok_or_else(|| AppError::ValidationError {
        field: "smtp_host".into(),
        message: "SMTP host not configured".into(),
    })?;
    let port = cfg.smtp_port.unwrap_or(587);
    let username = cfg.smtp_username.clone().unwrap_or_default();
    let password = if let Some(enc) = &cfg.smtp_password_encrypted {
        let bytes = state.crypto.decrypt(enc)?;
        String::from_utf8(bytes)
            .map_err(|_| AppError::Crypto("SMTP password is not valid UTF-8".into()))?
    } else {
        String::new()
    };
    let from = cfg.smtp_from.clone().unwrap_or_else(|| username.clone());
    Ok(SmtpConfig { host, port, username, password, from })
}

async fn rebuild_agent_zero_client(
    state: &AppState,
    cfg: &AppConfig,
) -> Result<(), AppError> {
    let mut lock = state.agent_zero.client.write().await;
    if let (Some(url), Some(enc_key)) = (
        cfg.agent_zero_url.as_deref(),
        cfg.agent_zero_api_key_encrypted.as_deref(),
    ) {
        match state.crypto.decrypt(enc_key) {
            Ok(key_bytes) => match String::from_utf8(key_bytes) {
                Ok(key) => match AgentZeroClient::new(url, key, cfg.allow_custom_agent_zero_url) {
                    Ok(client) => {
                        *lock = Some(client);
                        return Ok(());
                    }
                    Err(e) => return Err(e),
                },
                Err(_) => {
                    return Err(AppError::Crypto("API key is not valid UTF-8".into()));
                }
            },
            Err(e) => return Err(e),
        }
    }
    // No URL or key configured — clear the client.
    *lock = None;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_helpers::build_test_state;

    #[tokio::test]
    async fn settings_get_agent_zero_empty_token() {
        let (state, _pool) = build_test_state().await;
        let result = require_session(&state, "");
        assert!(matches!(result, Err(AppError::Unauthorized)));
    }

    #[tokio::test]
    async fn settings_set_agent_zero_empty_token() {
        let (state, _pool) = build_test_state().await;
        let result = require_session(&state, "");
        assert!(matches!(result, Err(AppError::Unauthorized)));
    }
}
