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
use tracing::{error, info, warn};

use crate::audit;
use crate::auth::session::require_session;
use crate::db::{cases, custody, entities, evidence, hashes, tools, analysis, person_identifiers};
use crate::db::entities::Entity;
use crate::db::person_identifiers::PersonIdentifier;
use crate::agent_zero::{
    AgentZeroClient, CasePayload, CaseSummary, ClassificationResult,
    ForensicAnalysisResult, OsintPersonIdentifier, OsintPersonPayload, OsintPersonRequest,
    OsintPersonResponse,
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
    /// Number of deduplicated identifiers submitted to Agent Zero for this
    /// batch. Counts entries in the `identifiers` array after dedup.
    pub identifiers_submitted: usize,
    pub tools_run: usize,
    pub tool_usage_rows_inserted: usize,
    pub notes: Option<String>,
}

/// The minimum tool set Agent Zero MUST run if the relevant inputs are
/// present. Agent Zero has discretion to add more via `discretion_allowed`.
const DEFAULT_OSINT_TOOLS: &[&str] =
    &["sherlock", "holehe", "theharvester", "spiderfoot"];

/// Safety cap on the number of identifiers forwarded to Agent Zero in a
/// single batch. Agent Zero orchestration may fan out one tool thread per
/// identifier, so an uncapped 200+ batch can thrash the container and
/// burn rate limits on external services (holehe, Sherlock site list).
/// Anything above this gets truncated after dedup and a `warn!` is emitted.
const MAX_IDENTIFIERS_PER_RUN: usize = 50;

/// Result of `build_osint_payload`. Carries the payload and the
/// pre-cap deduped count so the caller can tell truncation apart from a
/// merely-large-input-that-deduped-down-to-OK. Avoids the footgun where
/// `raw_list.len() > cap` fires when dedup would've brought it under.
///
/// Public (not `pub(crate)`) because integration tests in phase4 exercise
/// the full Pass 1 → Pass 2 chain against a real DB pool.
pub struct BuildPayloadResult {
    pub payload: OsintPersonPayload,
    /// Number of distinct identifiers after dedup, BEFORE the cap was applied.
    /// If this is greater than `MAX_IDENTIFIERS_PER_RUN`, truncation happened.
    pub deduped_count: usize,
}

/// Build an OSINT request payload from a person entity and its full list
/// of active identifiers (migration 0004). Pure function — no I/O, no
/// state — so it can be unit-tested independently.
///
/// Dedup semantics: two identifiers are considered duplicates when their
/// `(kind, trim(lowercase(value)), trim(lowercase(platform)))` tuples match.
/// Platform is part of the key because the same address registered on two
/// providers is genuinely two pieces of OSINT signal — `holehe` against
/// gmail vs protonmail returns different account-existence facts, and
/// Sherlock site-list dispatch is platform-scoped. Collapsing cross-platform
/// entries would silently lose investigator-entered intelligence.
///
/// Dedup gap (deferred to a later pass): only exact-after-trim-and-lowercase
/// matches are merged. Phone-number format variants (`+15555551234` vs
/// `555-555-1234`) and URL trailing-slash variants are NOT normalized and
/// will pass through as distinct entries. E.164 / URL normalization is a
/// Pass-3 concern once the forensic workflow has real duplicates in the wild.
///
/// Legacy compatibility: the single-value `email`/`phone`/`username` fields
/// on `OsintPersonPayload` keep their v1 semantics — prefer the value from
/// `entity.*` if present (investigator-curated primary), otherwise fall back
/// to the first matching identifier so older Agent Zero containers that only
/// read the legacy shape still work.
///
/// Returns the payload + a `deduped_count` that represents the number of
/// distinct identifiers BEFORE the `MAX_IDENTIFIERS_PER_RUN` cap was applied.
/// `payload.identifiers.len()` is the POST-cap count. When they differ,
/// truncation happened.
pub fn build_osint_payload(
    entity: &Entity,
    identifiers: &[PersonIdentifier],
) -> BuildPayloadResult {
    use std::collections::HashSet;

    // Dedup pass — preserves first-seen order so the legacy fallback below
    // is deterministic. Key = (kind, lowercased+trimmed value, lowercased+
    // trimmed platform-or-None). See function docstring.
    let mut seen: HashSet<(String, String, Option<String>)> = HashSet::new();
    let mut deduped: Vec<OsintPersonIdentifier> = Vec::with_capacity(identifiers.len());
    for id in identifiers {
        // Only include active rows — defensive, list_for_entity already filters.
        if id.is_deleted != 0 {
            continue;
        }
        let plat_key = id
            .platform
            .as_deref()
            .map(|p| p.trim().to_lowercase())
            .filter(|p| !p.is_empty());
        let key = (id.kind.clone(), id.value.trim().to_lowercase(), plat_key);
        if !seen.insert(key) {
            continue;
        }
        deduped.push(OsintPersonIdentifier {
            kind: id.kind.clone(),
            value: id.value.trim().to_string(),
            platform: id.platform.clone(),
        });
    }

    // Capture the post-dedup, pre-cap count so callers can correctly detect
    // truncation (vs. "large raw input that deduped below the cap").
    let deduped_count = deduped.len();

    // Safety cap — see MAX_IDENTIFIERS_PER_RUN. First-seen wins when truncating.
    if deduped.len() > MAX_IDENTIFIERS_PER_RUN {
        deduped.truncate(MAX_IDENTIFIERS_PER_RUN);
    }

    // Legacy single-value fallback: pick the first identifier of the kind
    // if the entity column itself is None.
    let first_of = |kind: &str| -> Option<String> {
        deduped
            .iter()
            .find(|i| i.kind == kind)
            .map(|i| i.value.clone())
    };
    let email = entity.email.clone().or_else(|| first_of("email"));
    let phone = entity.phone.clone().or_else(|| first_of("phone"));
    let username = entity
        .username
        .clone()
        .or_else(|| first_of("username"))
        .or_else(|| first_of("handle"));

    let payload = OsintPersonPayload {
        name: entity.display_name.clone(),
        email,
        phone,
        username,
        employer: entity.employer.clone(),
        dob: entity.dob.clone(),
        notes: entity.notes.clone(),
        identifiers: deduped,
    };

    BuildPayloadResult {
        payload,
        deduped_count,
    }
}

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

    // Fetch the full multi-valued identifier list for this person (migration
    // 0004). Active rows only — list_for_entity already filters is_deleted=1.
    let identifiers =
        person_identifiers::list_for_entity(&state.db.forensics, entity_id).await?;

    // Build the OSINT request payload from the person's known fields + the
    // deduped identifier batch. Dedup lives inside `build_osint_payload` so
    // the pure-function layer is the single source of truth for the merge.
    // The helper returns both the payload and the post-dedup PRE-cap count
    // so we can correctly detect truncation (a raw list of 60 that dedups
    // to 45 is NOT truncated even though 60 > cap).
    let BuildPayloadResult {
        payload,
        deduped_count,
    } = build_osint_payload(&entity, &identifiers);
    let identifiers_submitted = payload.identifiers.len();

    // Truncation is exactly "deduped count exceeded the cap".
    let truncated = deduped_count > MAX_IDENTIFIERS_PER_RUN;
    if truncated {
        tracing::warn!(
            username = %session.username,
            entity_id = entity_id,
            deduped_count,
            submitted = identifiers_submitted,
            cap = MAX_IDENTIFIERS_PER_RUN,
            "OSINT batch truncated — too many distinct identifiers for a single run"
        );
    }

    // Zero-identifier runs are intentionally allowed (Agent Zero can still
    // run spiderfoot on the display_name alone), but we flag them loudly so
    // the investigator understands the submission is name-only.
    let name_only_run =
        identifiers_submitted == 0 && entity.email.is_none() && entity.phone.is_none()
            && entity.username.is_none();
    if name_only_run {
        tracing::warn!(
            username = %session.username,
            entity_id = entity_id,
            "OSINT run has no identifiers and no legacy curated fields — name-only submission"
        );
    }

    // Read `tor_enabled` from live config. When true, the Agent Zero
    // container plugin additionally runs dark-web tools (SpiderFoot with
    // sfp_ahmia/sfp_torch/sfp_darkdump, onionsearch, darkdump2) and uses
    // the deep-search timeout tier. Defaults to false on the config side
    // so clearnet-only containers continue to work unchanged.
    let tor_enabled = state.config.tor_enabled;

    let request = OsintPersonRequest {
        case_id: entity.case_id.clone(),
        person: payload,
        tools_requested: DEFAULT_OSINT_TOOLS.iter().map(|s| s.to_string()).collect(),
        discretion_allowed: true,
        tor_enabled,
    };

    // Call Agent Zero.
    let az: RwLockReadGuard<'_, Option<AgentZeroClient>> = state.agent_zero.client.read().await;
    let client = az.as_ref().ok_or(AppError::AgentZeroNotConfigured)?;
    let response: OsintPersonResponse = client.osint_person(&request).await?;

    // Drop the read guard before we take async actions that might re-enter
    // state.agent_zero (avoids lock contention).
    drop(az);

    // Tor preflight failure on the container side is reported as a
    // sentinel status rather than an HTTP error, because the rest of the
    // response shape is unchanged. Map it to a specific AppError so the
    // investigator sees "Tor daemon is not reachable" in the toast
    // instead of a generic failure. No tool_usage rows are inserted and
    // no metadata_json update runs — the failure is early-exit.
    //
    // Any OTHER unrecognized status string is also treated as an error:
    // the plugin contract is `success | partial | failed | tor_unavailable`,
    // so a string we don't know about means either the plugin is a
    // newer/older version than we expect or the response is malformed.
    // Silently accepting it would render a misleading "success" in the
    // UI with zero rows. Fail loudly instead. (Finalization code-review
    // agent finding — was a fall-through gap.)
    match response.status.as_str() {
        "tor_unavailable" => {
            warn!(
                username = %session.username,
                entity_id = entity_id,
                upstream_notes = ?response.notes,
                "Agent Zero reported tor_unavailable — user has tor_enabled but \
                 the container daemon is not reachable"
            );
            return Err(AppError::TorUnavailable);
        }
        "success" | "partial" | "failed" => {
            // expected status values — fall through to normal processing
        }
        other => {
            error!(
                username = %session.username,
                entity_id = entity_id,
                unknown_status = %other,
                upstream_notes = ?response.notes,
                runs_count = response.runs.len(),
                "Agent Zero returned an unrecognized status string — refusing to \
                 insert any tool_usage rows until the plugin contract is understood"
            );
            return Err(AppError::Internal(format!(
                "Agent Zero returned unrecognized status '{other}'. Verify the \
                 _dfars_integration plugin version matches this build of DFARS Desktop."
            )));
        }
    }

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

    // Replace `osint_findings` in the entity's metadata_json with the current
    // run's results.
    //
    // "Replace" (not "append") is deliberate: the UI surfaces the LATEST run
    // inline on the PersonCard. Historical runs are never lost — every tool
    // invocation has already been recorded as a `tool_usage` row above, which
    // drives the case's Tools tab and the Markdown forensic report. If a
    // future phase needs a per-run history on the PersonCard itself, we'll
    // switch this to an append + add a run_timestamp discriminator, but the
    // tool_usage rows are the source of truth either way.
    //
    // Atomicity: this uses SQLite's built-in `json_set` in a single UPDATE
    // rather than the classic read-modify-write cycle. A read-modify-write
    // would race against a concurrent OSINT run on the same entity (reader A
    // fetches metadata → writer B commits → reader A writes, clobbering B's
    // findings). `json_set(COALESCE(metadata_json,'{}'), '$.osint_findings', ?)`
    // runs server-side in SQLite and preserves every other key in the object.
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
    let new_findings_json = serde_json::Value::Array(new_findings).to_string();

    sqlx::query(
        r#"
        UPDATE entities
        SET metadata_json = json_set(
                COALESCE(metadata_json, '{}'),
                '$.osint_findings',
                json(?)
            ),
            updated_at = CURRENT_TIMESTAMP
        WHERE entity_id = ?
        "#,
    )
    .bind(&new_findings_json)
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
        identifiers_submitted = identifiers_submitted,
        tools_run = response.runs.len(),
        tool_usage_rows_inserted = inserted,
        status = %response.status,
        "ai_osint_person succeeded"
    );
    // Audit trail: count-only. `display_name` is intentionally NOT
    // interpolated — the person is uniquely identified by entity_id, and
    // embedding raw names here would create a PII surface in audit exports.
    audit::log_case(
        &entity.case_id,
        &format!("user:{}", session.username),
        audit::AI_OSINT_PERSON_CALLED,
        &format!(
            "entity_id={} identifiers_submitted={} tools_run={} rows_inserted={} status={}",
            entity_id,
            identifiers_submitted,
            response.runs.len(),
            inserted,
            response.status
        ),
    );

    // Augment the upstream `notes` with local context so the frontend can
    // render a single unambiguous status line. Preserves whatever Agent Zero
    // returned and prefixes our own observations when relevant.
    let mut note_fragments: Vec<String> = Vec::new();
    if name_only_run {
        note_fragments
            .push("No identifiers recorded — name-only submission.".to_string());
    }
    if truncated {
        note_fragments.push(format!(
            "Batch truncated: {deduped_count} distinct identifiers, {identifiers_submitted} submitted (cap {MAX_IDENTIFIERS_PER_RUN})."
        ));
    }
    if tor_enabled {
        note_fragments.push("Dark-web pass: active.".to_string());
    }
    if let Some(upstream) = response.notes.as_deref() {
        if !upstream.is_empty() {
            note_fragments.push(upstream.to_string());
        }
    }
    let notes = if note_fragments.is_empty() {
        None
    } else {
        Some(note_fragments.join(" "))
    };

    Ok(OsintRunSummary {
        status: response.status,
        identifiers_submitted,
        tools_run: response.runs.len(),
        tool_usage_rows_inserted: inserted,
        notes,
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

    // ─── build_osint_payload (Pass 2 pure-function helper) ───────────────────

    /// Test helper: call `build_osint_payload` and return just the payload.
    /// Most tests only care about the payload shape; the `deduped_count`
    /// field is covered by dedicated tests.
    fn payload_from(entity: &Entity, ids: &[PersonIdentifier]) -> OsintPersonPayload {
        build_osint_payload(entity, ids).payload
    }

    // Intentionally exhaustive — adding an Entity field must force a test
    // review here so nobody can silently widen the OSINT payload surface.
    // Do NOT rewrite as `..Default::default()`.
    fn make_entity(overrides: impl FnOnce(&mut Entity)) -> Entity {
        let mut e = Entity {
            entity_id: 1,
            case_id: "CASE-001".into(),
            entity_type: "person".into(),
            display_name: "Alice".into(),
            subtype: Some("poi".into()),
            organizational_rank: None,
            parent_entity_id: None,
            notes: None,
            metadata_json: None,
            is_deleted: 0,
            created_at: "2026-04-15 00:00:00".into(),
            updated_at: "2026-04-15 00:00:00".into(),
            photo_path: None,
            email: None,
            phone: None,
            username: None,
            employer: None,
            dob: None,
        };
        overrides(&mut e);
        e
    }

    fn mk_ident(id: i64, kind: &str, value: &str, platform: Option<&str>) -> PersonIdentifier {
        PersonIdentifier {
            identifier_id: id,
            entity_id: 1,
            kind: kind.into(),
            value: value.into(),
            platform: platform.map(|s| s.into()),
            notes: None,
            is_deleted: 0,
            created_at: "2026-04-15 00:00:00".into(),
            updated_at: "2026-04-15 00:00:00".into(),
        }
    }

    #[test]
    fn build_osint_payload_empty_identifiers_preserves_entity_fields() {
        let entity = make_entity(|e| {
            e.email = Some("alice@example.com".into());
            e.phone = Some("+15555551234".into());
            e.username = Some("alice_u".into());
        });
        let payload = payload_from(&entity, &[]);
        assert_eq!(payload.email.as_deref(), Some("alice@example.com"));
        assert_eq!(payload.phone.as_deref(), Some("+15555551234"));
        assert_eq!(payload.username.as_deref(), Some("alice_u"));
        assert!(payload.identifiers.is_empty());
    }

    #[test]
    fn build_osint_payload_populates_legacy_fields_from_identifiers_when_entity_empty() {
        let entity = make_entity(|_| {});
        let ids = vec![
            mk_ident(1, "email", "first@example.com", Some("gmail")),
            mk_ident(2, "phone", "+15555550002", None),
            mk_ident(3, "handle", "@first", Some("twitter")),
        ];
        let payload = payload_from(&entity, &ids);
        // Legacy fallback picks first-of-kind.
        assert_eq!(payload.email.as_deref(), Some("first@example.com"));
        assert_eq!(payload.phone.as_deref(), Some("+15555550002"));
        // username has no direct identifier match; falls back to first handle.
        assert_eq!(payload.username.as_deref(), Some("@first"));
        assert_eq!(payload.identifiers.len(), 3);
    }

    #[test]
    fn build_osint_payload_prefers_entity_curated_over_identifier_for_legacy_fields() {
        let entity = make_entity(|e| {
            e.email = Some("primary@example.com".into());
        });
        let ids = vec![
            mk_ident(1, "email", "other@example.com", None),
        ];
        let payload = payload_from(&entity, &ids);
        // Entity's curated email wins.
        assert_eq!(payload.email.as_deref(), Some("primary@example.com"));
        // But the identifier still appears in the multi-valued array.
        assert_eq!(payload.identifiers.len(), 1);
        assert_eq!(payload.identifiers[0].value, "other@example.com");
    }

    #[test]
    fn build_osint_payload_dedupes_same_platform_case_insensitive_with_trim() {
        // All three rows share (kind=email, lowered value, lowered platform=gmail)
        // so they collapse to one. First-seen wins.
        let entity = make_entity(|_| {});
        let ids = vec![
            mk_ident(1, "email", "Alice@Example.com", Some("gmail")),
            mk_ident(2, "email", "alice@example.com", Some("Gmail")),
            mk_ident(3, "email", "  ALICE@EXAMPLE.COM  ", Some("  GMAIL  ")),
            mk_ident(4, "email", "other@example.com", None),
        ];
        let payload = payload_from(&entity, &ids);
        assert_eq!(
            payload.identifiers.len(),
            2,
            "three case/whitespace-variants on the same platform must collapse"
        );
        assert_eq!(payload.identifiers[0].value, "Alice@Example.com");
        assert_eq!(payload.identifiers[0].platform.as_deref(), Some("gmail"));
        assert_eq!(payload.identifiers[1].value, "other@example.com");
    }

    #[test]
    fn build_osint_payload_keeps_same_value_across_different_platforms() {
        // Same email registered on two different providers is genuine OSINT
        // signal — holehe against gmail returns a different fact than holehe
        // against protonmail. Both must survive dedup.
        let entity = make_entity(|_| {});
        let ids = vec![
            mk_ident(1, "email", "alice@example.com", Some("gmail")),
            mk_ident(2, "email", "alice@example.com", Some("protonmail")),
            mk_ident(3, "email", "alice@example.com", None), // no platform — distinct bucket
        ];
        let payload = payload_from(&entity, &ids);
        assert_eq!(payload.identifiers.len(), 3);
        let platforms: Vec<Option<&str>> = payload
            .identifiers
            .iter()
            .map(|i| i.platform.as_deref())
            .collect();
        assert_eq!(platforms, vec![Some("gmail"), Some("protonmail"), None]);
    }

    #[test]
    fn build_osint_payload_truncates_over_cap_and_reports_deduped_count() {
        // (MAX + 10) distinct identifiers — deduped_count must equal MAX + 10
        // (everything was already distinct), but payload.identifiers gets
        // truncated to MAX.
        let entity = make_entity(|_| {});
        let ids: Vec<PersonIdentifier> = (0..(MAX_IDENTIFIERS_PER_RUN + 10))
            .map(|i| mk_ident(i as i64, "email", &format!("a{i}@example.com"), None))
            .collect();
        let result = build_osint_payload(&entity, &ids);
        assert_eq!(result.payload.identifiers.len(), MAX_IDENTIFIERS_PER_RUN);
        assert_eq!(result.deduped_count, MAX_IDENTIFIERS_PER_RUN + 10);
        // First-seen wins on truncation — index 0..N must survive.
        assert_eq!(result.payload.identifiers[0].value, "a0@example.com");
        assert_eq!(
            result.payload.identifiers[MAX_IDENTIFIERS_PER_RUN - 1].value,
            format!("a{}@example.com", MAX_IDENTIFIERS_PER_RUN - 1)
        );
        // The caller uses (deduped_count > MAX) as the truncation signal.
        assert!(result.deduped_count > MAX_IDENTIFIERS_PER_RUN);
    }

    #[test]
    fn build_osint_payload_large_input_that_dedups_under_cap_is_not_truncated() {
        // QA finalization bug: (pre_dedup_count > MAX) was used as the
        // truncation signal, which fires false-positive when a big raw list
        // collapses below the cap after dedup. This test pins the fix:
        // deduped_count is the source of truth, NOT raw input length.
        let entity = make_entity(|_| {});
        let distinct = MAX_IDENTIFIERS_PER_RUN - 5; // well under the cap
        // Build `distinct` unique rows, then repeat each once to simulate a
        // dup-heavy raw list whose distinct count is still under the cap.
        let mut ids: Vec<PersonIdentifier> = Vec::new();
        for i in 0..distinct {
            let v = format!("b{i}@example.com");
            ids.push(mk_ident((i as i64) * 2, "email", &v, Some("gmail")));
            // exact duplicate of the row above (case-mangled to prove dedup fires)
            ids.push(mk_ident(
                (i as i64) * 2 + 1,
                "email",
                &v.to_uppercase(),
                Some("Gmail"),
            ));
        }
        // Raw list has 2 * (MAX - 5) rows — bigger than MAX for many common caps,
        // so the old bug would have mis-reported truncation. deduped_count
        // should match `distinct`, not the raw length.
        let result = build_osint_payload(&entity, &ids);
        assert_eq!(result.deduped_count, distinct);
        assert_eq!(result.payload.identifiers.len(), distinct);
        // Caller's truncation check: (deduped_count > MAX) MUST be false here.
        assert!(
            result.deduped_count <= MAX_IDENTIFIERS_PER_RUN,
            "a raw list that dedupes under the cap must NOT report truncation"
        );
    }

    #[test]
    fn build_osint_payload_empty_entity_empty_identifiers_no_panic() {
        // Belt-and-braces: both inputs empty. Must produce a valid payload
        // with all-None legacy fields and an empty identifiers Vec.
        let entity = make_entity(|_| {});
        let payload = payload_from(&entity, &[]);
        assert!(payload.email.is_none());
        assert!(payload.phone.is_none());
        assert!(payload.username.is_none());
        assert!(payload.identifiers.is_empty());
        assert_eq!(payload.name, "Alice");
    }

    #[test]
    fn build_osint_payload_whitespace_value_filtered_upstream_roundtrip() {
        // `validate_input` at the db layer already rejects whitespace-only
        // values, so they should never reach build_osint_payload in real
        // flows. This test documents the current (permissive) behavior when
        // such a row is passed in anyway — the trim makes it empty-string,
        // which survives as a distinct dedup-key bucket. If a stricter check
        // is wanted, assert a different behavior here first.
        let entity = make_entity(|_| {});
        let ids = vec![
            mk_ident(1, "email", "   ", None),
            mk_ident(2, "email", "  ", None),
        ];
        let payload = payload_from(&entity, &ids);
        // Both map to key (email, "", None); first-seen wins.
        assert_eq!(payload.identifiers.len(), 1);
        assert_eq!(payload.identifiers[0].value, "");
    }

    #[test]
    fn build_osint_payload_username_fallback_priority_pinned() {
        // QA recommended pinning the username fallback order so a future
        // change can't silently flip it. Priority:
        //   1. entity.username (curated primary)
        //   2. first identifier of kind="username"
        //   3. first identifier of kind="handle" (platform-scoped handles
        //      are LESS useful than a bare username for Sherlock-style
        //      cross-platform enumeration, so they rank below username)
        let entity = make_entity(|_| {});
        let ids = vec![
            mk_ident(1, "handle", "@alice_twitter", Some("twitter")),
            mk_ident(2, "username", "alice_u", None),
        ];
        let payload = payload_from(&entity, &ids);
        assert_eq!(
            payload.username.as_deref(),
            Some("alice_u"),
            "username kind must outrank handle kind in the legacy fallback"
        );
    }

    #[test]
    fn build_osint_payload_trims_value_on_output() {
        let entity = make_entity(|_| {});
        let ids = vec![mk_ident(1, "handle", "  @alice  ", None)];
        let payload = payload_from(&entity, &ids);
        assert_eq!(payload.identifiers[0].value, "@alice");
    }

    #[test]
    fn build_osint_payload_skips_soft_deleted_rows_defensively() {
        // list_for_entity already filters; this asserts build_osint_payload
        // is also robust if a caller somehow passes a soft-deleted row in.
        let entity = make_entity(|_| {});
        let mut deleted = mk_ident(1, "email", "ghost@example.com", None);
        deleted.is_deleted = 1;
        let ids = vec![deleted, mk_ident(2, "email", "live@example.com", None)];
        let payload = payload_from(&entity, &ids);
        assert_eq!(payload.identifiers.len(), 1);
        assert_eq!(payload.identifiers[0].value, "live@example.com");
    }

    #[test]
    fn build_osint_payload_different_kinds_same_value_not_deduped() {
        // (kind, value) is the dedup key — a phone "12345" and a url "12345"
        // are distinct even if they look the same.
        let entity = make_entity(|_| {});
        let ids = vec![
            mk_ident(1, "phone", "12345", None),
            mk_ident(2, "url", "12345", None),
        ];
        let payload = payload_from(&entity, &ids);
        assert_eq!(payload.identifiers.len(), 2);
    }

    #[test]
    fn build_osint_payload_preserves_first_seen_order_across_kinds() {
        let entity = make_entity(|_| {});
        let ids = vec![
            mk_ident(1, "url", "https://alice.example", None),
            mk_ident(2, "email", "a@a.com", None),
            mk_ident(3, "handle", "@a", None),
        ];
        let payload = payload_from(&entity, &ids);
        let kinds: Vec<&str> = payload.identifiers.iter().map(|i| i.kind.as_str()).collect();
        assert_eq!(kinds, vec!["url", "email", "handle"]);
    }
}
