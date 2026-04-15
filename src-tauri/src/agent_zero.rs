/// Agent Zero outbound HTTP client — SEC-4 MUST-DOs 6, 7, and related SHOULD-DOs.
///
/// This module owns:
///   - `AgentZeroClient` — a thin wrapper around `reqwest::Client` that enforces
///     the URL allowlist (MUST-DO 6), per-endpoint timeouts, and response-body
///     limits (MUST-DO 7).
///   - `AgentZeroState`  — an `Arc<RwLock<Option<AgentZeroClient>>>` shared into
///     `AppState` so commands can call Agent Zero without re-constructing the client.
///
/// ## URL allowlist (MUST-DO 6)
///
/// Without validation, a tampered `config.json` (malware write, social engineering)
/// would silently POST the entire case record — investigator names, custody chains,
/// SHA-256 hashes, analysis notes — to an attacker-controlled server.
///
/// Accepted without the custom-URL flag:
///   - `http://localhost`            (any port, any path)
///   - `http://127.0.0.1`           (any port, any path)
///   - `http://host.docker.internal` (any port, any path)
///
/// Plain HTTP for Docker loopback is intentional: traffic never leaves the host
/// machine's loopback/virtual-ethernet stack. The URL allowlist — not TLS — is
/// the primary exfiltration control (see sec-4-5-network-review.md §2.2).
///
/// ## Per-endpoint timeouts + body limits (MUST-DO 7)
///
/// | Endpoint              | Total timeout | Response body limit |
/// |---|---|---|
/// | dfars_enhance         | 30 s          | 16 KiB              |
/// | dfars_classify        | 30 s          | 8 KiB               |
/// | dfars_summarize       | 120 s         | 64 KiB              |
/// | dfars_analyze_evidence| 180 s         | 128 KiB             |
/// | dfars_forensic_analyze| 300 s         | 256 KiB             |
///
/// Connect timeout is 10 s across all endpoints (catches "AZ container down" fast).
///
/// ## Token isolation
///
/// Decrypted API key is stored in `zeroize::Zeroizing<String>` — wiped on drop.
/// NEVER logged.
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use reqwest::Url;
use serde::{Deserialize, Serialize};
use tokio::sync::RwLock;
use tracing::{info, warn};
use zeroize::Zeroizing;

use crate::audit;
use crate::config::AppConfig;
use crate::crypto::CryptoState;
use crate::error::AppError;

// ─── Per-endpoint constants ───────────────────────────────────────────────────

const TIMEOUT_ENHANCE:         Duration = Duration::from_secs(30);
const TIMEOUT_CLASSIFY:        Duration = Duration::from_secs(30);
const TIMEOUT_SUMMARIZE:       Duration = Duration::from_secs(120);
#[allow(dead_code)]
const TIMEOUT_ANALYZE_EVIDENCE:Duration = Duration::from_secs(180);
const TIMEOUT_FORENSIC_ANALYZE:Duration = Duration::from_secs(300);
/// OSINT tier — Agent Zero may run SpiderFoot, Sherlock, theHarvester, and other
/// Kali OSINT tools, which collectively can take up to 15 minutes. This is the
/// longest-running endpoint we accept.
const TIMEOUT_OSINT:           Duration = Duration::from_secs(900);
const TIMEOUT_CONNECT:         Duration = Duration::from_secs(10);

const LIMIT_ENHANCE:           usize = 16 * 1024;
const LIMIT_CLASSIFY:          usize = 8 * 1024;
const LIMIT_SUMMARIZE:         usize = 64 * 1024;
#[allow(dead_code)]
const LIMIT_ANALYZE_EVIDENCE:  usize = 128 * 1024;
const LIMIT_FORENSIC_ANALYZE:  usize = 256 * 1024;
/// OSINT results can be large (per-tool summaries + dozens of runs). 512 KiB
/// is generous but bounded.
const LIMIT_OSINT:             usize = 512 * 1024;

// ─── Allowlist hosts ─────────────────────────────────────────────────────────

const ALLOWED_HOSTS: &[&str] = &["localhost", "127.0.0.1", "host.docker.internal"];

// ─── Public data types ────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClassificationResult {
    pub category: String,
    pub subcategory: Option<String>,
    pub confidence: f64,
    pub reasoning: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CasePayload {
    pub case_id: String,
    pub case_name: String,
    pub investigator: Option<String>,
    pub agency: Option<String>,
    pub classification: Option<String>,
    pub description: Option<String>,
    pub status: Option<String>,
    pub evidence: Vec<serde_json::Value>,
    pub custody: Vec<serde_json::Value>,
    pub hashes: Vec<serde_json::Value>,
    pub tools: Vec<serde_json::Value>,
    pub analysis: Vec<serde_json::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CaseSummary {
    pub executive_summary: String,
    pub key_findings: Vec<String>,
    pub conclusion: Option<String>,
    pub generated_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ForensicAnalysisResult {
    pub evidence_id: String,
    pub report_markdown: String,
    pub tools_used: Vec<String>,
    pub platforms_used: Vec<String>,
    pub status: String,
    pub error_message: Option<String>,
}

// ─── OSINT (Persons feature) ─────────────────────────────────────────────────

/// One OSINT-relevant identifier attached to a person. Mirrors a row from the
/// `person_identifiers` table (migration 0004) minus the audit/ownership
/// columns. Agent Zero's orchestration uses the full array to dispatch tools
/// across every known handle/email/phone/url in parallel instead of the
/// single-value legacy fields.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct OsintPersonIdentifier {
    /// One of: email | username | handle | phone | url
    pub kind: String,
    pub value: String,
    /// Free-form platform tag (twitter, reddit, github, gmail, …). Optional.
    pub platform: Option<String>,
}

/// Known fields about a person that Agent Zero can use as OSINT input.
/// Every legacy field is optional — Agent Zero decides which tools to run
/// based on which inputs are present.
///
/// `identifiers` (migration 0004) is the multi-valued replacement: a single
/// person typically has many emails, handles, and URLs across platforms.
/// The legacy single-value `email`/`phone`/`username` columns stay populated
/// for backward compatibility with existing Agent Zero containers that only
/// speak the v1 payload shape — they are filled from the first identifier of
/// each applicable kind when the entity row itself doesn't have them.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OsintPersonPayload {
    pub name: String,
    pub email: Option<String>,
    pub phone: Option<String>,
    pub username: Option<String>,
    pub employer: Option<String>,
    pub dob: Option<String>,
    pub notes: Option<String>,
    /// Multi-valued OSINT identifiers from the person_identifiers table,
    /// already deduplicated by (kind, lowercased value) before send.
    #[serde(default)]
    pub identifiers: Vec<OsintPersonIdentifier>,
}

/// Request body for `dfars_osint_person`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OsintPersonRequest {
    pub case_id: String,
    pub person: OsintPersonPayload,
    /// Minimum tool set Agent Zero MUST run if the required inputs are present.
    pub tools_requested: Vec<String>,
    /// If true, Agent Zero has discretion to run additional Kali OSINT tools
    /// beyond `tools_requested` when it judges them useful.
    pub discretion_allowed: bool,
}

/// One row per tool Agent Zero actually executed.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OsintToolRun {
    pub tool_name: String,
    pub version: Option<String>,
    pub command_executed: Option<String>,
    pub execution_datetime: Option<String>,
    pub findings_summary: String,
    pub raw_output_truncated: Option<String>,
    pub output_file_stored_at: Option<String>,
    pub success: bool,
    pub error_message: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OsintPersonResponse {
    /// "success" | "partial" | "failed"
    pub status: String,
    pub runs: Vec<OsintToolRun>,
    pub notes: Option<String>,
}

// ─── Client ──────────────────────────────────────────────────────────────────

pub struct AgentZeroClient {
    client: reqwest::Client,
    base_url: Url,
    /// Decrypted key — wiped from heap on drop (SHOULD-DO 3).
    /// NEVER logged, NEVER included in audit entries.
    api_key: Zeroizing<String>,
}

impl AgentZeroClient {
    /// Construct a new client, validating the URL against the allowlist.
    ///
    /// `allow_custom_url = true` bypasses the allowlist but writes a WARN audit
    /// entry so the investigator has a paper trail.
    pub fn new(url: &str, api_key: String, allow_custom_url: bool) -> Result<Self, AppError> {
        let base_url = validate_agent_zero_url(url, allow_custom_url)?;

        let client = reqwest::Client::builder()
            .connect_timeout(TIMEOUT_CONNECT)
            .use_rustls_tls()
            .build()
            .map_err(|e| AppError::Internal(format!("reqwest build failed: {e}")))?;

        Ok(Self {
            client,
            base_url,
            api_key: Zeroizing::new(api_key),
        })
    }

    pub fn is_configured(&self) -> bool {
        !self.api_key.is_empty() && !self.base_url.as_str().is_empty()
    }

    // ─── Outbound calls ───────────────────────────────────────────────────────

    /// `dfars_enhance` — narrative rewrite. Sends only the typed text (low risk).
    pub async fn enhance(&self, text: &str) -> Result<String, AppError> {
        info!(action = audit::AI_ENHANCE_CALLED, fields_sent = "text");
        let body = serde_json::json!({ "text": text });
        let resp = self
            .post("dfars_enhance", &body, TIMEOUT_ENHANCE)
            .await?;
        let bytes = bounded_body(resp, LIMIT_ENHANCE).await?;
        let val: serde_json::Value = serde_json::from_slice(&bytes)
            .map_err(|e| AppError::Internal(format!("enhance parse failed: {e}")))?;
        Ok(val["enhanced_text"]
            .as_str()
            .unwrap_or_default()
            .to_owned())
    }

    /// `dfars_classify` — categorisation. Sends only the typed text (low risk).
    pub async fn classify(&self, text: &str) -> Result<ClassificationResult, AppError> {
        info!(action = audit::AI_CLASSIFY_CALLED, fields_sent = "text");
        let body = serde_json::json!({ "text": text });
        let resp = self
            .post("dfars_classify", &body, TIMEOUT_CLASSIFY)
            .await?;
        let bytes = bounded_body(resp, LIMIT_CLASSIFY).await?;
        serde_json::from_slice(&bytes)
            .map_err(|e| AppError::Internal(format!("classify parse failed: {e}")))
    }

    /// `dfars_summarize` — full case payload. HIGH DATA SENSITIVITY.
    ///
    /// Sends: case metadata, investigator name, agency, evidence descriptions,
    /// custody chains, hashes, tools, analysis notes.
    /// SEC-4 MUST-DO 8: caller MUST have checked `config.shown_ai_summarize_consent`.
    pub async fn summarize_case(&self, case_payload: &CasePayload) -> Result<CaseSummary, AppError> {
        info!(
            action = audit::AI_SUMMARIZE_CALLED,
            case_id = %case_payload.case_id,
            fields_sent = "case_id,case_name,investigator,agency,classification,description,status,evidence,custody,hashes,tools,analysis"
        );
        let body = serde_json::json!({ "case": case_payload });
        let resp = self
            .post("dfars_summarize", &body, TIMEOUT_SUMMARIZE)
            .await?;
        let bytes = bounded_body(resp, LIMIT_SUMMARIZE).await?;
        serde_json::from_slice(&bytes)
            .map_err(|e| AppError::Internal(format!("summarize parse failed: {e}")))
    }

    /// `dfars_forensic_analyze` — AI-enhanced analysis. Sends evidence record + API token
    /// so the AZ plugin can call back to DFARS's axum file-download endpoint.
    ///
    /// The `dfars_token` pass-through is intentional: Agent Zero needs it to
    /// authenticate to the axum file-download endpoint. See spec §8 OQ-SEC4-3.
    pub async fn forensic_analyze(
        &self,
        evidence_id: &str,
        narrative: &str,
        dfars_token: &str,
    ) -> Result<ForensicAnalysisResult, AppError> {
        info!(
            action = audit::FORENSIC_ANALYZE_CALLED,
            evidence_id = %evidence_id,
            fields_sent = "evidence_id,narrative,dfars_api_token"
        );
        // NOTE: dfars_token is intentionally included here (plugin callback auth).
        // It is NOT logged above because audit entries must not contain token values.
        let body = serde_json::json!({
            "evidence_id": evidence_id,
            "narrative": narrative,
            "dfars_api_token": dfars_token,
        });
        let resp = self
            .post("dfars_forensic_analyze", &body, TIMEOUT_FORENSIC_ANALYZE)
            .await?;
        let bytes = bounded_body(resp, LIMIT_FORENSIC_ANALYZE).await?;
        serde_json::from_slice(&bytes)
            .map_err(|e| AppError::Internal(format!("forensic_analyze parse failed: {e}")))
    }

    /// `dfars_osint_person` — Agent Zero OSINT orchestration. Sends a
    /// person payload (name + optional known fields) and a minimum tool set;
    /// Agent Zero decides which additional Kali OSINT tools to run and
    /// returns structured results.
    ///
    /// HIGH DATA SENSITIVITY — PII (name / email / phone / username /
    /// employer) is sent to Agent Zero which may forward it to external
    /// OSINT data sources (LinkedIn, Shodan, public DNS, Sherlock's site
    /// list, etc.). Caller MUST have checked `config.shown_ai_osint_consent`
    /// before invoking.
    ///
    /// 900s timeout tier. Response body capped at 512 KiB.
    pub async fn osint_person(
        &self,
        req: &OsintPersonRequest,
    ) -> Result<OsintPersonResponse, AppError> {
        info!(
            action = audit::AI_OSINT_PERSON_CALLED,
            case_id = %req.case_id,
            tools_requested_count = req.tools_requested.len(),
            identifiers_count = req.person.identifiers.len(),
            discretion_allowed = req.discretion_allowed,
            fields_sent = "person(name,email,phone,username,employer,dob,notes,identifiers[]), tools_requested, discretion_allowed"
        );
        let body = serde_json::to_value(req)
            .map_err(|e| AppError::Internal(format!("osint_person serialize failed: {e}")))?;
        let resp = self
            .post("dfars_osint_person", &body, TIMEOUT_OSINT)
            .await?;
        let bytes = bounded_body(resp, LIMIT_OSINT).await?;
        serde_json::from_slice(&bytes)
            .map_err(|e| AppError::Internal(format!("osint_person parse failed: {e}")))
    }

    // ─── Internal helpers ─────────────────────────────────────────────────────

    async fn post(
        &self,
        endpoint: &str,
        body: &serde_json::Value,
        timeout: Duration,
    ) -> Result<reqwest::Response, AppError> {
        let url = self
            .base_url
            .join(&format!("/api/plugins/_dfars_integration/{endpoint}"))
            .map_err(|e| AppError::Internal(format!("URL join failed: {e}")))?;

        let resp = self
            .client
            .post(url)
            .header("X-API-KEY", self.api_key.as_str())
            .json(body)
            .timeout(timeout)
            .send()
            .await
            .map_err(|e| {
                if e.is_timeout() {
                    AppError::AgentZeroTimeout {
                        endpoint: endpoint.to_owned(),
                        seconds: timeout.as_secs(),
                    }
                } else if e.is_connect() {
                    AppError::AgentZeroTimeout {
                        endpoint: endpoint.to_owned(),
                        seconds: TIMEOUT_CONNECT.as_secs(),
                    }
                } else {
                    AppError::Internal(format!("Agent Zero request failed: {e}"))
                }
            })?;

        if !resp.status().is_success() {
            let status = resp.status().as_u16();
            let msg = resp.text().await.unwrap_or_default();
            // Truncate message to prevent log spam
            let msg_truncated = msg.chars().take(200).collect::<String>();
            return Err(AppError::AgentZeroServerError {
                status,
                message: msg_truncated,
            });
        }

        Ok(resp)
    }
}

// ─── Bounded body reader (MUST-DO 7) ─────────────────────────────────────────

/// Stream the response body and reject it if it exceeds `max_bytes`.
///
/// reqwest reads response bodies without a cap by default — a malicious or
/// buggy Agent Zero response of unbounded size would OOM the process.
/// This helper enforces a hard per-endpoint limit.
pub async fn bounded_body(
    resp: reqwest::Response,
    max_bytes: usize,
) -> Result<Bytes, AppError> {
    use futures_util::StreamExt as _;

    let mut accumulated = bytes::BytesMut::new();
    let mut stream = resp.bytes_stream();

    while let Some(chunk) = stream.next().await {
        let chunk = chunk.map_err(|e| AppError::Internal(format!("body stream error: {e}")))?;
        accumulated.extend_from_slice(&chunk);
        if accumulated.len() > max_bytes {
            return Err(AppError::PayloadTooLarge { limit: max_bytes });
        }
    }

    Ok(accumulated.freeze())
}

// ─── URL validation (MUST-DO 6) ──────────────────────────────────────────────

/// Public wrapper for URL validation — used by `settings_set_agent_zero`.
pub fn validate_url_public(url: &str, allow_custom: bool) -> Result<(), AppError> {
    validate_agent_zero_url(url, allow_custom).map(|_| ())
}

fn validate_agent_zero_url(url: &str, allow_custom: bool) -> Result<Url, AppError> {
    let parsed = Url::parse(url).map_err(|_| AppError::AgentZeroUrlRejected {
        url: url.to_owned(),
    })?;

    // Must be http or https scheme.
    if parsed.scheme() != "http" && parsed.scheme() != "https" {
        return Err(AppError::AgentZeroUrlRejected {
            url: url.to_owned(),
        });
    }

    let host = parsed.host_str().unwrap_or("");
    let on_allowlist = ALLOWED_HOSTS.contains(&host) && parsed.scheme() == "http";

    if on_allowlist {
        return Ok(parsed);
    }

    // Not on the allowlist — check the custom-URL override.
    if allow_custom {
        warn!(
            "Agent Zero URL points to non-standard host '{}' — custom URL override is active. \
             Ensure the target is trusted before sending case data.",
            host
        );
        audit::log_auth(
            "SYSTEM",
            audit::AGENT_ZERO_CUSTOM_URL_ACTIVE,
            &format!("Agent Zero custom URL active: {}", url),
        );
        return Ok(parsed);
    }

    Err(AppError::AgentZeroUrlRejected {
        url: url.to_owned(),
    })
}

// ─── Shared state ─────────────────────────────────────────────────────────────

/// Holds the lazily-initialized Agent Zero client.
///
/// Wrapped in `Arc<RwLock<Option<...>>>` so:
///   - Multiple commands can call Agent Zero concurrently (reads are cheap).
///   - Settings updates can swap the client under a write lock.
///   - `is_configured()` is a cheap read with no Argon2 / crypto involved.
pub struct AgentZeroState {
    pub client: Arc<RwLock<Option<AgentZeroClient>>>,
}

impl AgentZeroState {
    pub fn new() -> Self {
        Self {
            client: Arc::new(RwLock::new(None)),
        }
    }

    /// Build from app config + crypto. Returns `Ok(Self)` even if Agent Zero is
    /// not configured — callers check `is_configured()` before dispatching.
    pub async fn from_config(cfg: &AppConfig, crypto: &CryptoState) -> Result<Self, AppError> {
        let state = Self::new();

        if let (Some(url), Some(encrypted_key)) = (
            cfg.agent_zero_url.as_deref(),
            cfg.agent_zero_api_key_encrypted.as_deref(),
        ) {
            match crypto.decrypt(encrypted_key) {
                Ok(key_bytes) => {
                    match String::from_utf8(key_bytes) {
                        Ok(key) => {
                            match AgentZeroClient::new(url, key, cfg.allow_custom_agent_zero_url) {
                                Ok(client) => {
                                    *state.client.write().await = Some(client);
                                    info!("Agent Zero client initialized");
                                }
                                Err(e) => {
                                    warn!("Agent Zero URL rejected at startup: {e}");
                                }
                            }
                        }
                        Err(_) => {
                            warn!("Agent Zero API key is not valid UTF-8 after decryption");
                        }
                    }
                }
                Err(e) => {
                    warn!("Agent Zero API key decryption failed at startup: {e}");
                }
            }
        }

        Ok(state)
    }

    /// `true` if the client is initialized and the key is non-empty.
    pub async fn is_configured(&self) -> bool {
        self.client
            .read()
            .await
            .as_ref()
            .map(|c| c.is_configured())
            .unwrap_or(false)
    }
}

impl Default for AgentZeroState {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn allowlist_localhost_ok() {
        assert!(validate_agent_zero_url("http://localhost:50080", false).is_ok());
    }

    #[test]
    fn allowlist_loopback_ok() {
        assert!(validate_agent_zero_url("http://127.0.0.1:50080", false).is_ok());
    }

    #[test]
    fn allowlist_docker_internal_ok() {
        assert!(validate_agent_zero_url("http://host.docker.internal:50080", false).is_ok());
    }

    #[test]
    fn reject_external_url() {
        let e = validate_agent_zero_url("https://evil.example.com", false).unwrap_err();
        assert!(matches!(e, AppError::AgentZeroUrlRejected { .. }));
    }

    #[test]
    fn reject_ftp_scheme() {
        let e = validate_agent_zero_url("ftp://localhost", false).unwrap_err();
        assert!(matches!(e, AppError::AgentZeroUrlRejected { .. }));
    }

    #[test]
    fn custom_url_with_flag_ok() {
        // https:// to non-localhost is allowed when allow_custom = true
        assert!(validate_agent_zero_url("https://my-az.internal", true).is_ok());
    }

    #[test]
    fn custom_url_without_flag_rejected() {
        let e = validate_agent_zero_url("https://my-az.internal", false).unwrap_err();
        assert!(matches!(e, AppError::AgentZeroUrlRejected { .. }));
    }

    #[test]
    fn invalid_url_rejected() {
        let e = validate_agent_zero_url("not-a-url", false).unwrap_err();
        assert!(matches!(e, AppError::AgentZeroUrlRejected { .. }));
    }

    #[tokio::test]
    async fn bounded_body_rejects_oversize() {
        // Build a fake response body larger than the limit.
        let large = vec![b'x'; 9 * 1024]; // 9 KiB
        let resp = reqwest::Response::from(
            http::Response::builder()
                .status(200)
                .body(large)
                .unwrap(),
        );
        let err = bounded_body(resp, 8 * 1024).await.unwrap_err();
        assert!(matches!(err, AppError::PayloadTooLarge { .. }));
    }

    #[tokio::test]
    async fn bounded_body_accepts_small() {
        let small = vec![b'x'; 100];
        let resp = reqwest::Response::from(
            http::Response::builder()
                .status(200)
                .body(small)
                .unwrap(),
        );
        let bytes = bounded_body(resp, 8 * 1024).await.unwrap();
        assert_eq!(bytes.len(), 100);
    }
}
