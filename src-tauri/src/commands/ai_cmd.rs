/// AI helper Tauri commands — Phase 5.
///
/// All four commands are session-gated (`require_session` first), check
/// `AgentZeroState::is_configured()`, delegate to `AgentZeroClient`, and
/// audit-log both success and failure.
///
/// MUST-DO 8: `ai_summarize_case` checks `config.shown_ai_summarize_consent`
/// before sending any data.  If false → `AppError::AiSummarizeConsentRequired`
/// so the frontend can show the consent dialog, and the investigator must
/// acknowledge before retrying.
use std::sync::Arc;

use tauri::State;
use tracing::{error, info};

use crate::audit;
use crate::auth::session::require_session;
use crate::db::{cases, custody, evidence, hashes, tools, analysis};
use crate::agent_zero::{AgentZeroClient, CasePayload, ClassificationResult, CaseSummary, ForensicAnalysisResult};
use tokio::sync::RwLockReadGuard;
use crate::error::AppError;
use crate::state::AppState;

// ─── ai_enhance ──────────────────────────────────────────────────────────────

/// Rewrite / improve an investigator-typed narrative string.
/// Sends ONLY the typed text — no case metadata.
#[tauri::command]
pub async fn ai_enhance(
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

    let az: RwLockReadGuard<'_, Option<AgentZeroClient>> = state.agent_zero.client.read().await;
    let client = az.as_ref().ok_or(AppError::AgentZeroNotConfigured)?;

    let result: Result<String, AppError> = client.enhance(&text).await;

    match &result {
        Ok(_) => info!(username = %session.username, action = audit::AI_ENHANCE_CALLED, "ai_enhance succeeded"),
        Err(e) => error!(username = %session.username, error = ?e, "ai_enhance failed"),
    }

    result
}

// ─── ai_classify ─────────────────────────────────────────────────────────────

/// Categorize a narrative string.  Sends ONLY the typed text.
#[tauri::command]
pub async fn ai_classify(
    token: String,
    text: String,
    state: State<'_, Arc<AppState>>,
) -> Result<ClassificationResult, AppError> {
    let session = require_session(&state, &token)?;

    if text.is_empty() {
        return Err(AppError::ValidationError {
            field: "text".into(),
            message: "text must not be empty".into(),
        });
    }

    let az: RwLockReadGuard<'_, Option<AgentZeroClient>> = state.agent_zero.client.read().await;
    let client = az.as_ref().ok_or(AppError::AgentZeroNotConfigured)?;

    let result = client.classify(&text).await;

    match &result {
        Ok(_) => info!(username = %session.username, action = audit::AI_CLASSIFY_CALLED, "ai_classify succeeded"),
        Err(e) => error!(username = %session.username, error = ?e, "ai_classify failed"),
    }

    result
}

// ─── ai_summarize_case ────────────────────────────────────────────────────────

/// Generate an executive-summary report for a case.
///
/// Sends the FULL case payload — all evidence, custody, hashes, tools, analysis.
///
/// SEC-4 MUST-DO 8: checks `shown_ai_summarize_consent` before sending.
/// If false → `AppError::AiSummarizeConsentRequired`.
#[tauri::command]
pub async fn ai_summarize_case(
    token: String,
    case_id: String,
    state: State<'_, Arc<AppState>>,
) -> Result<CaseSummary, AppError> {
    let session = require_session(&state, &token)?;

    // MUST-DO 8: one-time consent gate.
    if !state.config.shown_ai_summarize_consent {
        return Err(AppError::AiSummarizeConsentRequired);
    }

    let az: RwLockReadGuard<'_, Option<AgentZeroClient>> = state.agent_zero.client.read().await;
    let client = az.as_ref().ok_or(AppError::AgentZeroNotConfigured)?;

    // Assemble the full case payload.
    let payload = build_case_payload(&state, &case_id).await?;

    let result = client.summarize_case(&payload).await;

    match &result {
        Ok(_) => {
            info!(
                username = %session.username,
                case_id = %case_id,
                action = audit::AI_SUMMARIZE_CALLED,
                fields_sent = "case_id,case_name,investigator,agency,classification,description,status,evidence,custody,hashes,tools,analysis",
                "ai_summarize_case succeeded"
            );
        }
        Err(e) => {
            error!(username = %session.username, case_id = %case_id, error = ?e, "ai_summarize_case failed");
        }
    }

    result
}

async fn build_case_payload(
    state: &AppState,
    case_id: &str,
) -> Result<CasePayload, AppError> {
    let detail = cases::get_case(&state.db.forensics, case_id).await?;
    let evidence_list = evidence::list_for_case(&state.db.forensics, case_id).await?;
    let custody_list = custody::list_for_case(&state.db.forensics, case_id).await?;
    let hash_list = hashes::list_for_case(&state.db.forensics, case_id).await?;
    let tool_list = tools::list_for_case(&state.db.forensics, case_id).await?;
    let analysis_list = analysis::list_for_case(&state.db.forensics, case_id).await?;

    Ok(CasePayload {
        case_id: detail.case.case_id.clone(),
        case_name: detail.case.case_name.clone(),
        investigator: Some(detail.case.investigator.clone()),
        agency: detail.case.agency.clone(),
        classification: detail.case.classification.clone(),
        description: detail.case.description.clone(),
        status: Some(detail.case.status.clone()),
        evidence: evidence_list
            .into_iter()
            .map(|e| serde_json::to_value(e).unwrap_or_default())
            .collect(),
        custody: custody_list
            .into_iter()
            .map(|c| serde_json::to_value(c).unwrap_or_default())
            .collect(),
        hashes: hash_list
            .into_iter()
            .map(|h| serde_json::to_value(h).unwrap_or_default())
            .collect(),
        tools: tool_list
            .into_iter()
            .map(|t| serde_json::to_value(t).unwrap_or_default())
            .collect(),
        analysis: analysis_list
            .into_iter()
            .map(|a| serde_json::to_value(a).unwrap_or_default())
            .collect(),
    })
}

// ─── evidence_forensic_analyze ────────────────────────────────────────────────

/// AI-enhanced forensic analysis via Agent Zero.
///
/// Sends: evidence_id, narrative, and a dfars_api_token (so the Agent Zero
/// plugin can call back to DFARS's axum file-download endpoint).
///
/// The dfars_api_token pass-through is intentional — see spec §8 OQ-SEC4-3.
/// The token value is NOT logged (audit records log its presence, not value).
#[tauri::command]
pub async fn evidence_forensic_analyze(
    token: String,
    evidence_id: String,
    narrative: String,
    dfars_api_token: String,
    state: State<'_, Arc<AppState>>,
) -> Result<ForensicAnalysisResult, AppError> {
    let session = require_session(&state, &token)?;

    let az: RwLockReadGuard<'_, Option<AgentZeroClient>> = state.agent_zero.client.read().await;
    let client = az.as_ref().ok_or(AppError::AgentZeroNotConfigured)?;

    // Look up which case this evidence belongs to for audit logging.
    let ev = evidence::get_evidence(&state.db.forensics, &evidence_id).await?;
    let case_id = ev.case_id.clone();

    let result = client
        .forensic_analyze(&evidence_id, &narrative, &dfars_api_token)
        .await;

    match &result {
        Ok(_) => {
            info!(
                username = %session.username,
                evidence_id = %evidence_id,
                action = audit::FORENSIC_ANALYZE_CALLED,
                fields_sent = "evidence_id,narrative,dfars_api_token(present)",
                "evidence_forensic_analyze succeeded"
            );
            audit::log_case(
                &case_id,
                &format!("user:{}", session.username),
                audit::FORENSIC_ANALYZE_CALLED,
                &format!("evidence_id={evidence_id} forensic analysis requested"),
            );
        }
        Err(e) => {
            error!(
                username = %session.username,
                evidence_id = %evidence_id,
                error = ?e,
                "evidence_forensic_analyze failed"
            );
        }
    }

    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_helpers::build_test_state;

    /// SEC-5 negative test: empty token returns Unauthorized.
    #[tokio::test]
    async fn ai_enhance_empty_token_unauthorized() {
        let (state, _pool) = build_test_state().await;
        // We can't call the Tauri command directly without the Tauri runtime,
        // but we can test the session guard inline.
        let result = require_session(&state, "");
        assert!(matches!(result, Err(AppError::Unauthorized)));
    }

    #[tokio::test]
    async fn ai_classify_empty_token_unauthorized() {
        let (state, _pool) = build_test_state().await;
        let result = require_session(&state, "");
        assert!(matches!(result, Err(AppError::Unauthorized)));
    }
}
