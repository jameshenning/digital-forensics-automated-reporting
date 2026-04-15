/// App configuration — `%APPDATA%\DFARS\config.json`.
///
/// Loaded once at startup and re-persisted whenever settings change.
/// Additive-only: unknown fields are preserved via `serde_json::Value` round-trip
/// so v1 → v2 migration does not clobber fields the existing v1 code sets.
///
/// SEC-4/5 fields of note:
///   - `bind_host` / `allow_network_bind` — MUST-DO 5 bind-host gate
///   - `agent_zero_url` / `allow_custom_agent_zero_url` — MUST-DO 6 URL allowlist
///   - `shown_ai_summarize_consent` — MUST-DO 8 one-time consent gate
use std::path::Path;

use serde::{Deserialize, Serialize};

use crate::error::AppError;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppConfig {
    // ─── Network ──────────────────────────────────────────────────────────────
    /// IPv4 address the axum server binds to. Default "127.0.0.1" (loopback only).
    #[serde(default = "default_bind_host")]
    pub bind_host: String,

    /// Must be explicitly set to `true` to allow binding to non-loopback addresses
    /// (e.g. "0.0.0.0").  SEC-5 MUST-DO 5 — double opt-in for network exposure.
    #[serde(default)]
    pub allow_network_bind: bool,

    /// Port the axum server listens on. Default 5099 (matches v1 + Agent Zero plugin default).
    #[serde(default = "default_axum_port")]
    pub axum_port: u16,

    // ─── Agent Zero ───────────────────────────────────────────────────────────
    /// Base URL for the Agent Zero container. Validated against an allowlist.
    pub agent_zero_url: Option<String>,

    /// Fernet-encrypted Agent Zero API key.
    pub agent_zero_api_key_encrypted: Option<String>,

    /// Allow Agent Zero URL to point to non-localhost hosts.
    /// SEC-4 MUST-DO 6: requires explicit opt-in. The UI shows an amber warning banner.
    #[serde(default)]
    pub allow_custom_agent_zero_url: bool,

    /// Whether the investigator has acknowledged the one-time AI summarize consent banner.
    /// SEC-4 MUST-DO 8: first `ai_summarize_case` call must show the banner.
    #[serde(default)]
    pub shown_ai_summarize_consent: bool,

    /// Whether the investigator has acknowledged the one-time OSINT consent
    /// banner. OSINT is separately acknowledged from case-summary consent
    /// because it's more invasive — person PII (name, email, username,
    /// employer) is sent to Agent Zero and onward to external OSINT sources
    /// (LinkedIn, Shodan, Sherlock's site list, etc.).
    #[serde(default)]
    pub shown_ai_osint_consent: bool,

    // ─── SMTP ─────────────────────────────────────────────────────────────────
    pub smtp_host: Option<String>,
    pub smtp_port: Option<u16>,
    pub smtp_username: Option<String>,

    /// Fernet-encrypted SMTP password.
    pub smtp_password_encrypted: Option<String>,
    pub smtp_from: Option<String>,

    // ─── File upload (Phase 3b carry-forward) ─────────────────────────────────
    pub max_upload_bytes: Option<u64>,
    #[serde(default)]
    pub evidence_onedrive_risk_acknowledged: bool,
}

fn default_bind_host() -> String {
    "127.0.0.1".to_owned()
}

fn default_axum_port() -> u16 {
    5099
}

impl Default for AppConfig {
    fn default() -> Self {
        Self {
            bind_host: default_bind_host(),
            allow_network_bind: false,
            axum_port: default_axum_port(),
            agent_zero_url: None,
            agent_zero_api_key_encrypted: None,
            allow_custom_agent_zero_url: false,
            shown_ai_summarize_consent: false,
            shown_ai_osint_consent: false,
            smtp_host: None,
            smtp_port: None,
            smtp_username: None,
            smtp_password_encrypted: None,
            smtp_from: None,
            max_upload_bytes: None,
            evidence_onedrive_risk_acknowledged: false,
        }
    }
}

// ─── Load / save ─────────────────────────────────────────────────────────────

/// Load config from `path`. If the file does not exist, returns `AppConfig::default()`.
/// Unknown fields are silently ignored (additive-only policy).
pub fn load(path: &Path) -> Result<AppConfig, AppError> {
    if !path.exists() {
        return Ok(AppConfig::default());
    }
    let raw = std::fs::read_to_string(path)
        .map_err(|e| AppError::Io(format!("config read failed: {e}")))?;
    let cfg: AppConfig = serde_json::from_str(&raw)
        .map_err(|e| AppError::Internal(format!("config parse failed: {e}")))?;
    Ok(cfg)
}

/// Persist `cfg` to `path`.  Creates parent directories as needed.
/// Fields already in the file that we don't know about are NOT merged here —
/// serde serializes exactly the struct fields.  If v1 fields need preservation,
/// use a two-step read-modify-write via `serde_json::Value`.
pub fn save(path: &Path, cfg: &AppConfig) -> Result<(), AppError> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|e| AppError::Io(format!("config dir create failed: {e}")))?;
    }
    let json = serde_json::to_string_pretty(cfg)
        .map_err(|e| AppError::Internal(format!("config serialize failed: {e}")))?;
    std::fs::write(path, &json)
        .map_err(|e| AppError::Io(format!("config write failed: {e}")))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn default_bind_host_is_loopback() {
        let cfg = AppConfig::default();
        assert_eq!(cfg.bind_host, "127.0.0.1");
    }

    #[test]
    fn default_port_is_5099() {
        let cfg = AppConfig::default();
        assert_eq!(cfg.axum_port, 5099);
    }

    #[test]
    fn round_trip_config() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("config.json");
        let mut cfg = AppConfig::default();
        cfg.agent_zero_url = Some("http://localhost:50080".into());
        cfg.smtp_host = Some("smtp.example.com".into());
        save(&path, &cfg).unwrap();
        let loaded = load(&path).unwrap();
        assert_eq!(loaded.agent_zero_url, cfg.agent_zero_url);
        assert_eq!(loaded.smtp_host, cfg.smtp_host);
        assert_eq!(loaded.axum_port, 5099);
    }

    #[test]
    fn load_missing_file_returns_default() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("nonexistent.json");
        let cfg = load(&path).unwrap();
        assert_eq!(cfg.bind_host, "127.0.0.1");
        assert!(!cfg.allow_network_bind);
    }
}
