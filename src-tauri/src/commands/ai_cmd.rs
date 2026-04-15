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
use crate::db::{cases, custody, entities, evidence, hashes, tools, analysis};
use crate::agent_zero::{
    AgentZeroClient, CasePayload, CaseSummary, ClassificationResult,
    ForensicAnalysisResult, OsintPersonPayload, OsintPersonRequest, OsintPersonResponse,
};
use crate::db::tools::ToolInput;
use tokio::sync::RwLockReadGuard;
use crate::error::AppError;
use crate::state::AppState;

// ─── ai_enhance ──────────────────────────────────────────────────────────────

/// Rewrite / improve an investigator-typed narrative string.
/// Sends ONLY the typed text — no case metadata.
#[tauri::command(rename_all = "snake_case")]
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
#[tauri::command(rename_all = "snake_case")]
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
#[tauri::command(rename_all = "snake_case")]
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
#[tauri::command(rename_all = "snake_case")]
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

// ─── ai_osint_person (Persons feature) ───────────────────────────────────────

/// Result summary returned to the frontend after an OSINT orchestration run.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct OsintRunSummary {
    pub status: String,
    pub tools_run: usize,
    pub tool_usage_rows_inserted: usize,
    pub notes: Option<String>,
}

/// The minimum tool set Agent Zero MUST run if the relevant inputs are
/// present. Agent Zero has discretion to add more via `discretion_allowed`.
const DEFAULT_OSINT_TOOLS: &[&str] =
    &["sherlock", "holehe", "theharvester", "spiderfoot"];

/// Orchestrate an OSINT run for a person entity.
///
/// Flow:
/// 1. Validate session
/// 2. Fetch the entity, verify entity_type = "person"
/// 3. Check `shown_ai_osint_consent` (separate from the AI summarize consent)
/// 4. Build OsintPersonRequest from the person's known fields
/// 5. POST to Agent Zero `dfars_osint_person` (900s timeout, 512 KiB cap)
/// 6. For every successful run returned, insert a `tool_usage` row via
///    `db::tools::add_tool()` so it appears in the Tools tab narrative view
///    and the Markdown forensic report
/// 7. Append findings into the entity's `metadata_json.osint_findings[]`
///    array via a direct UPDATE (we do not re-validate the whole entity)
/// 8. Audit-log AI_OSINT_PERSON_CALLED with the tool count
/// 9. Return a summary to the frontend
///
/// HIGH DATA SENSITIVITY — caller must ensure the user has acknowledged the
/// separate OSINT consent banner before calling. PII leaves the machine by
/// design.
#[tauri::command(rename_all = "snake_case")]
pub async fn ai_osint_person(
    token: String,
    entity_id: i64,
    state: State<'_, Arc<AppState>>,
) -> Result<OsintRunSummary, AppError> {
    let session = require_session(&state, &token)?;

    // Separate consent gate — runtime flag reflects in-session acknowledgment.
    if !state.osint_consent_granted() {
        return Err(AppError::AiOsintConsentRequired);
    }

    // Fetch the entity and validate it's a person.
    let entity = entities::get_entity(&state.db.forensics, entity_id).await?;
    if entity.is_deleted != 0 {
        return Err(AppError::EntityNotFound { entity_id });
    }
    if entity.entity_type != "person" {
        return Err(AppError::EntityNotAPerson {
            entity_id,
            entity_type: entity.entity_type.clone(),
        });
    }

    // Build the OSINT request payload from the person's known fields.
    let payload = OsintPersonPayload {
        name: entity.display_name.clone(),
        email: entity.email.clone(),
        phone: entity.phone.clone(),
        username: entity.username.clone(),
        employer: entity.employer.clone(),
        dob: entity.dob.clone(),
        notes: entity.notes.clone(),
    };
    let request = OsintPersonRequest {
        case_id: entity.case_id.clone(),
        person: payload,
        tools_requested: DEFAULT_OSINT_TOOLS.iter().map(|s| s.to_string()).collect(),
        discretion_allowed: true,
    };

    // Call Agent Zero.
    let az: RwLockReadGuard<'_, Option<AgentZeroClient>> = state.agent_zero.client.read().await;
    let client = az.as_ref().ok_or(AppError::AgentZeroNotConfigured)?;
    let response: OsintPersonResponse = client.osint_person(&request).await?;

    // Drop the read guard before we take async actions that might re-enter
    // state.agent_zero (avoids lock contention).
    drop(az);

    // Insert a tool_usage row for every successful run.
    let mut inserted = 0usize;
    for run in &response.runs {
        if !run.success {
            continue;
        }
        // Parse the execution_datetime from the Agent Zero response if present.
        // Format expected: RFC 3339 or YYYY-MM-DDTHH:MM:SS. If parsing fails,
        // fall back to None so the DB layer uses Utc::now().
        let parsed_dt = run.execution_datetime.as_ref().and_then(|s| {
            chrono::NaiveDateTime::parse_from_str(s, "%Y-%m-%dT%H:%M:%S")
                .ok()
                .or_else(|| {
                    // Try RFC 3339 with Z suffix
                    chrono::DateTime::parse_from_rfc3339(s)
                        .ok()
                        .map(|dt| dt.naive_utc())
                })
        });

        let tool_input = ToolInput {
            evidence_id: None, // OSINT runs are person-scoped, not evidence-scoped
            tool_name: run.tool_name.clone(),
            version: run.version.clone(),
            purpose: format!(
                "OSINT via Agent Zero for person '{}' — {}",
                entity.display_name, run.findings_summary
            ),
            command_used: run.command_executed.clone(),
            input_file: Some(format!(
                "Person entity_id={} ({})",
                entity.entity_id, entity.display_name
            )),
            output_file: run.output_file_stored_at.clone(),
            execution_datetime: parsed_dt,
            operator: format!("Agent Zero ({})", run.tool_name),
            // Reproduction fields — Agent Zero OSINT runs are not directly
            // reproducible by another examiner (target may have changed),
            // so we leave them None and let the KB warning flag the gap.
            input_sha256: None,
            output_sha256: None,
            environment_notes: Some(format!(
                "Run inside Agent Zero container; tool {} executed automatically as part of dfars_osint_person orchestration",
                run.tool_name
            )),
            reproduction_notes: run.raw_output_truncated.clone(),
        };

        if let Err(e) = tools::add_tool(&state.db.forensics, &entity.case_id, &tool_input).await {
            error!(
                username = %session.username,
                entity_id = entity_id,
                tool_name = %run.tool_name,
                error = ?e,
                "failed to insert tool_usage row for OSINT run"
            );
            continue;
        }
        inserted += 1;
    }

    // Append findings to the entity's metadata_json.
    //
    // We parse whatever is there, add/replace the `osint_findings` array,
    // and UPDATE via a direct query (not update_entity — we don't want to
    // re-validate the full entity here).
    let existing_metadata: serde_json::Value = entity
        .metadata_json
        .as_deref()
        .and_then(|s| serde_json::from_str(s).ok())
        .unwrap_or_else(|| serde_json::json!({}));

    let new_findings: Vec<serde_json::Value> = response
        .runs
        .iter()
        .filter(|r| r.success)
        .map(|r| {
            serde_json::json!({
                "tool_name": r.tool_name,
                "findings_summary": r.findings_summary,
                "execution_datetime": r.execution_datetime,
            })
        })
        .collect();

    let mut metadata_obj = match existing_metadata {
        serde_json::Value::Object(m) => m,
        _ => serde_json::Map::new(),
    };
    metadata_obj.insert(
        "osint_findings".to_string(),
        serde_json::Value::Array(new_findings),
    );
    let new_metadata_json = serde_json::Value::Object(metadata_obj).to_string();

    sqlx::query(
        "UPDATE entities SET metadata_json = ?, updated_at = CURRENT_TIMESTAMP WHERE entity_id = ?",
    )
    .bind(&new_metadata_json)
    .bind(entity_id)
    .execute(&state.db.forensics)
    .await
    .map_err(AppError::from)?;

    // Audit + structured log.
    info!(
        username = %session.username,
        entity_id = entity_id,
        case_id = %entity.case_id,
        action = audit::AI_OSINT_PERSON_CALLED,
        tools_run = response.runs.len(),
        tool_usage_rows_inserted = inserted,
        status = %response.status,
        "ai_osint_person succeeded"
    );
    audit::log_case(
        &entity.case_id,
        &format!("user:{}", session.username),
        audit::AI_OSINT_PERSON_CALLED,
        &format!(
            "entity_id={} person='{}' tools_run={} rows_inserted={} status={}",
            entity_id,
            entity.display_name,
            response.runs.len(),
            inserted,
            response.status
        ),
    );

    Ok(OsintRunSummary {
        status: response.status,
        tools_run: response.runs.len(),
        tool_usage_rows_inserted: inserted,
        notes: response.notes,
    })
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
