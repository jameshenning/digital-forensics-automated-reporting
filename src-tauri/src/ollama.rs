/// Local LLM client — Ollama integration.
///
/// Completely separate from Agent Zero. Talks directly to the Ollama REST API
/// at `http://localhost:11434` (or a user-configured loopback URL).
///
/// Security: URL is validated against the same allowlist as Agent Zero
/// (localhost, 127.0.0.1, host.docker.internal) unless `allow_custom_url` is
/// explicitly enabled. No API key is required for local Ollama.
use std::time::Duration;

use bytes::Bytes;
use reqwest::Url;
use serde::{Deserialize, Serialize};
use tracing::{info, warn};

use crate::audit;
use crate::error::AppError;

// ─── Constants ────────────────────────────────────────────────────────────────

const TIMEOUT_GENERATE: Duration = Duration::from_secs(60);
const TIMEOUT_CONNECT: Duration = Duration::from_secs(10);
const LIMIT_GENERATE: usize = 32 * 1024; // 32 KiB

const ALLOWED_HOSTS: &[&str] = &["localhost", "127.0.0.1", "host.docker.internal"];

const DEFAULT_OLLAMA_URL: &str = "http://localhost:11434";
const DEFAULT_MODEL: &str = "mistral";

// ─── System prompt for forensic narrative enhancement ─────────────────────────

const SYSTEM_PROMPT: &str = r#"You are a senior digital forensic investigator and technical report writer.
Your task is to expand the investigator's brief draft notes into a detailed,
professional forensic narrative suitable for inclusion in a formal DFARS
(Defense Federal Acquisition Regulation Supplement) compliance report.

Guidelines:
1. Expand the content significantly — turn bullet points or terse sentences
   into fully developed paragraphs with proper structure.
2. Use precise forensic terminology and maintain an objective, factual tone.
3. Add logical structure: context, methodology, observations, and implications
   where appropriate.
4. Do NOT invent facts, evidence, or conclusions not present in the draft.
5. Do NOT add speculative language; ground everything in the provided content.
6. If the draft mentions tools, techniques, or procedures, elaborate on their
   purpose and how they were applied.
7. Write in the third person passive voice where appropriate for formal reports.
8. Preserve all specific names, dates, identifiers, and technical details exactly.

Respond ONLY with the enhanced narrative text. No markdown formatting,
no preamble, no postscript."#;

// ─── Client ───────────────────────────────────────────────────────────────────

pub struct OllamaClient {
    client: reqwest::Client,
    base_url: Url,
    model: String,
}

impl OllamaClient {
    /// Construct a new client from an optional URL and model.
    /// Falls back to localhost defaults when not configured.
    pub fn new(url: Option<&str>, model: Option<&str>, allow_custom_url: bool) -> Result<Self, AppError> {
        let url = url.unwrap_or(DEFAULT_OLLAMA_URL);
        let base_url = validate_ollama_url(url, allow_custom_url)?;
        let model = model.unwrap_or(DEFAULT_MODEL).to_owned();

        let client = reqwest::Client::builder()
            .connect_timeout(TIMEOUT_CONNECT)
            .build()
            .map_err(|e| AppError::Internal(format!("ollama reqwest build failed: {e}")))?;

        Ok(Self {
            client,
            base_url,
            model,
        })
    }

    /// Enhance a narrative text string using the local LLM.
    pub async fn enhance(&self, text: &str) -> Result<String, AppError> {
        info!(action = audit::OLLAMA_ENHANCE_CALLED, model = %self.model, fields_sent = "text");

        let body = GenerateRequest {
            model: self.model.clone(),
            system: Some(SYSTEM_PROMPT.to_owned()),
            prompt: text.to_owned(),
            stream: false,
            options: Some(GenerateOptions {
                temperature: 0.3,
            }),
        };

        let url = self
            .base_url
            .join("/api/generate")
            .map_err(|e| AppError::Internal(format!("ollama URL join failed: {e}")))?;

        let resp = self
            .client
            .post(url)
            .json(&body)
            .timeout(TIMEOUT_GENERATE)
            .send()
            .await
            .map_err(|e| {
                if e.is_timeout() || e.is_connect() {
                    AppError::OllamaUnavailable {
                        url: self.base_url.to_string(),
                    }
                } else {
                    AppError::Internal(format!("ollama request failed: {e}"))
                }
            })?;

        if !resp.status().is_success() {
            let status = resp.status().as_u16();
            let msg = resp.text().await.unwrap_or_default();
            let msg_truncated = msg.chars().take(200).collect::<String>();
            return Err(AppError::OllamaServerError {
                status,
                message: msg_truncated,
            });
        }

        let bytes = bounded_body(resp, LIMIT_GENERATE).await?;
        let val: GenerateResponse = serde_json::from_slice(&bytes)
            .map_err(|e| AppError::Internal(format!("ollama response parse failed: {e}")))?;

        Ok(val.response)
    }

    /// Lightweight health check — verifies Ollama is reachable and lists models.
    pub async fn is_available(&self) -> Result<bool, AppError> {
        let url = self
            .base_url
            .join("/api/tags")
            .map_err(|e| AppError::Internal(format!("ollama URL join failed: {e}")))?;

        let resp = self
            .client
            .get(url)
            .timeout(TIMEOUT_CONNECT)
            .send()
            .await;

        match resp {
            Ok(r) => Ok(r.status().is_success()),
            Err(_) => Ok(false),
        }
    }

    /// Check if the configured model is present in the Ollama model list.
    pub async fn model_loaded(&self) -> Result<bool, AppError> {
        let url = self
            .base_url
            .join("/api/tags")
            .map_err(|e| AppError::Internal(format!("ollama URL join failed: {e}")))?;

        let resp = self
            .client
            .get(url)
            .timeout(TIMEOUT_CONNECT)
            .send()
            .await
            .map_err(|_e| AppError::OllamaUnavailable {
                url: self.base_url.to_string(),
            })?;

        if !resp.status().is_success() {
            return Ok(false);
        }

        let bytes = bounded_body(resp, 64 * 1024).await?;
        let val: ModelListResponse = serde_json::from_slice(&bytes)
            .map_err(|e| AppError::Internal(format!("ollama model list parse failed: {e}")))?;

        let model_name = self.model.clone();
        Ok(val.models.iter().any(|m| m.name == model_name || m.name.starts_with(&format!("{}/", model_name))))
    }
}

// ─── Request / Response types ─────────────────────────────────────────────────

#[derive(Debug, Serialize)]
struct GenerateRequest {
    model: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    system: Option<String>,
    prompt: String,
    stream: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    options: Option<GenerateOptions>,
}

#[derive(Debug, Serialize)]
struct GenerateOptions {
    temperature: f32,
}

#[derive(Debug, Deserialize)]
struct GenerateResponse {
    response: String,
}

#[derive(Debug, Deserialize)]
struct ModelListResponse {
    models: Vec<ModelInfo>,
}

#[derive(Debug, Deserialize)]
struct ModelInfo {
    name: String,
}

// ─── Bounded body reader ──────────────────────────────────────────────────────

async fn bounded_body(resp: reqwest::Response, max_bytes: usize) -> Result<Bytes, AppError> {
    use futures_util::StreamExt as _;

    let mut accumulated = bytes::BytesMut::new();
    let mut stream = resp.bytes_stream();

    while let Some(chunk) = stream.next().await {
        let chunk = chunk.map_err(|e| AppError::Internal(format!("ollama body stream error: {e}")))?;
        accumulated.extend_from_slice(&chunk);
        if accumulated.len() > max_bytes {
            return Err(AppError::PayloadTooLarge { limit: max_bytes });
        }
    }

    Ok(accumulated.freeze())
}

// ─── URL validation ───────────────────────────────────────────────────────────

/// Public wrapper for URL validation — used by settings commands.
pub fn validate_url_public(url: &str, allow_custom: bool) -> Result<(), AppError> {
    validate_ollama_url(url, allow_custom).map(|_| ())
}

fn validate_ollama_url(url: &str, allow_custom: bool) -> Result<Url, AppError> {
    let parsed = Url::parse(url).map_err(|_| AppError::AgentZeroUrlRejected {
        url: url.to_owned(),
    })?;

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

    if allow_custom {
        warn!(
            "Ollama URL points to non-standard host '{}' — custom URL override is active.",
            host
        );
        audit::log_auth(
            "SYSTEM",
            audit::OLLAMA_CUSTOM_URL_ACTIVE,
            &format!("Ollama custom URL active: {}", url),
        );
        return Ok(parsed);
    }

    Err(AppError::AgentZeroUrlRejected {
        url: url.to_owned(),
    })
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn allowlist_localhost_ok() {
        assert!(validate_ollama_url("http://localhost:11434", false).is_ok());
    }

    #[test]
    fn allowlist_loopback_ok() {
        assert!(validate_ollama_url("http://127.0.0.1:11434", false).is_ok());
    }

    #[test]
    fn allowlist_docker_internal_ok() {
        assert!(validate_ollama_url("http://host.docker.internal:11434", false).is_ok());
    }

    #[test]
    fn reject_external_url() {
        let e = validate_ollama_url("https://evil.example.com", false).unwrap_err();
        assert!(matches!(e, AppError::AgentZeroUrlRejected { .. }));
    }

    #[test]
    fn reject_https_localhost() {
        // HTTPS on localhost is rejected because the allowlist requires plain http.
        let e = validate_ollama_url("https://localhost:11434", false).unwrap_err();
        assert!(matches!(e, AppError::AgentZeroUrlRejected { .. }));
    }

    #[test]
    fn custom_url_override_works() {
        assert!(validate_ollama_url("http://192.168.1.50:11434", true).is_ok());
    }
}
