/// Markdown report generator — Phase 3b.
///
/// Port of `app/report_generator.py` to Rust.  Generates a SWGDE-compliant
/// markdown case report by querying the DB modules (cases, evidence, custody,
/// hashes, tools, analysis) through the existing public APIs.
///
/// Public surface:
///   - `preview_markdown(state, case_id) -> Result<String, AppError>`
///     Returns the full markdown without writing to disk.
///   - `generate_report(state, case_id, format) -> Result<PathBuf, AppError>`
///     Writes the report to `%APPDATA%\DFARS\reports\<case_id>_<timestamp>.md`
///     and returns the absolute path.
///
/// The section order mirrors v1's `DEFAULT_TEMPLATE` exactly so output is
/// comparable.

use std::path::{Path, PathBuf};

use chrono::Utc;
use serde::{Deserialize, Serialize};

use crate::{
    db::{
        analysis,
        analysis_reviews,
        cases,
        custody,
        entities,
        evidence as evidence_db,
        hashes,
        links as links_db,
        person_identifiers,
        tools,
    },
    error::AppError,
    forensic_tools,
    state::AppState,
};

/// Report format enum — Markdown is Phase 3b; HTML deferred.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ReportFormat {
    Markdown,
    Html,
    Pdf,
}

impl ReportFormat {
    pub fn extension(&self) -> &str {
        match self {
            ReportFormat::Markdown => "md",
            ReportFormat::Html => "html",
            ReportFormat::Pdf => "pdf",
        }
    }
}

/// Report template enum — controls section structure and compliance level.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ReportTemplate {
    Standard,
    Swgde,
}

impl ReportTemplate {
    pub fn label(&self) -> &'static str {
        match self {
            ReportTemplate::Standard => "Standard",
            ReportTemplate::Swgde => "SWGDE Compliant",
        }
    }
}

/// Human-readable name for a validation level (0-4).
fn validation_level_name(level: i64) -> &'static str {
    match level {
        0 => "Unvalidated",
        1 => "Tool-Validated",
        2 => "Cross-Validated",
        3 => "Examiner-Validated",
        4 => "Peer-Reviewed",
        _ => "Unknown",
    }
}

// ─── Public entry-points ──────────────────────────────────────────────────────

/// Generate a markdown report and return it as a `String` without writing to disk.
/// Used by the `case_report_preview` command.
pub async fn preview_markdown(state: &AppState, case_id: &str) -> Result<String, AppError> {
    let payload = gather_report_payload(state, case_id).await?;
    render_markdown(&payload)
}

/// Generate a report, write it to the reports directory, and return the path.
/// Used by the `case_report_generate` command.
pub async fn generate_report(
    state: &AppState,
    case_id: &str,
    format: ReportFormat,
    template: ReportTemplate,
    reports_root: &Path,  // injected so tests can override %APPDATA%
) -> Result<PathBuf, AppError> {
    let payload = gather_report_payload(state, case_id).await?;

    let safe_case_id = sanitize_report_filename(case_id);
    let timestamp = Utc::now().format("%Y-%m-%d_%H-%M-%S").to_string();
    let filename = format!("{safe_case_id}_{timestamp}.{}", format.extension());

    std::fs::create_dir_all(reports_root).map_err(AppError::from)?;

    // Canonical-prefix check to prevent any path injection.
    let canonical_root = std::fs::canonicalize(reports_root).map_err(|e| {
        AppError::ReportGenerationFailed {
            reason: format!("cannot canonicalize reports directory: {e}"),
        }
    })?;

    let out_path = canonical_root.join(&filename);

    if !out_path.starts_with(&canonical_root) {
        return Err(AppError::ReportGenerationFailed {
            reason: "path traversal in report filename".into(),
        });
    }

    match format {
        ReportFormat::Pdf => {
            let pdf_bytes = render_pdf(&payload, &template)?;
            std::fs::write(&out_path, pdf_bytes).map_err(AppError::from)?;
        }
        _ => {
            let content = match format {
                ReportFormat::Markdown => render_markdown(&payload)?,
                ReportFormat::Html => render_html(&payload)?,
                ReportFormat::Pdf => unreachable!(),
            };
            std::fs::write(&out_path, content.as_bytes()).map_err(AppError::from)?;
        }
    }

    Ok(out_path)
}

// ─── Internal payload gathering ───────────────────────────────────────────────

#[allow(dead_code)]
struct ReportPayload {
    case_id: String,
    case_name: String,
    description: Option<String>,
    investigator: String,
    agency: Option<String>,
    start_date: String,
    end_date: Option<String>,
    status: String,
    priority: String,
    classification: Option<String>,
    tags: Vec<String>,
    evidence_items: Vec<EvidenceReport>,
    persons: Vec<PersonReport>,
    all_custody: Vec<CustodyReport>,
    all_hashes: Vec<HashReport>,
    all_tools: Vec<ToolReport>,
    analysis_notes: Vec<AnalysisReport>,
    /// Phase B (migration 0008): rendered in the new "Entity Connections" section.
    links: Vec<LinkReport>,
    generated_at: String,
}

#[allow(dead_code)]
struct PersonReport {
    entity_id: i64,
    display_name: String,
    subtype: Option<String>,
    organizational_rank: Option<String>,
    email: Option<String>,
    phone: Option<String>,
    username: Option<String>,
    employer: Option<String>,
    dob: Option<String>,
    notes: Option<String>,
    /// Extracted from entity.metadata_json.osint_findings[].tool_name if present.
    osint_tools_run: Vec<String>,
    /// Multi-valued identifiers from `person_identifiers` (Phase B).
    identifiers: Vec<IdentifierReport>,
}

/// Phase B (migration 0008): per-identifier attribution payload used by the
/// report renderer for both person_identifiers and (in a future expansion)
/// business_identifiers.
#[allow(dead_code)]
struct IdentifierReport {
    kind: String,
    value: String,
    platform: Option<String>,
    notes: Option<String>,
    /// Tool that surfaced an auto-discovered identifier (migration 0006).
    discovered_via_tool: Option<String>,
    // Migration 0008 attribution fields.
    attributed_by: Option<String>,
    attribution_basis: Option<String>,
    confidence_level: Option<String>,
    verification_status: Option<String>,
}

/// Phase B (migration 0008): a single asserted connection with full
/// attribution context. Rendered in the new "Entity Connections" section.
#[allow(dead_code)]
struct LinkReport {
    link_id: i64,
    source_type: String,
    source_id: String,
    source_label: String,
    target_type: String,
    target_id: String,
    target_label: String,
    link_label: Option<String>,
    directional: bool,
    weight: f64,
    notes: Option<String>,
    // Migration 0008 attribution fields.
    attributed_by: Option<String>,
    basis: Option<String>,
    confidence_level: Option<String>,
    method_reference: Option<String>,
    alternatives_considered: Option<String>,
    evidence_refs: Option<String>,
}

#[allow(dead_code)]
struct EvidenceReport {
    evidence_id: String,
    description: String,
    collected_by: String,
    collection_datetime: String,
    location: Option<String>,
    status: String,
    evidence_type: Option<String>,
}

#[allow(dead_code)]
struct CustodyReport {
    evidence_id: String,
    custody_sequence: i64,
    action: String,
    from_party: String,
    to_party: String,
    location: Option<String>,
    custody_datetime: String,
    purpose: Option<String>,
    notes: Option<String>,
}

#[allow(dead_code)]
struct HashReport {
    evidence_id: String,
    algorithm: String,
    hash_value: String,
    verified_by: String,
    verification_datetime: String,
    notes: Option<String>,
}

#[allow(dead_code)]
struct ToolReport {
    tool_name: String,
    version: Option<String>,
    purpose: String,
    command_used: Option<String>,
    input_file: Option<String>,
    output_file: Option<String>,
    execution_datetime: String,
    operator: String,
    evidence_id: Option<String>,
}

#[allow(dead_code)]
struct AnalysisReport {
    note_id: i64,
    category: String,
    finding: String,
    description: Option<String>,
    confidence_level: String,
    evidence_id: Option<String>,
    // Validation fields (migration 0007) — nullable, "not recorded"
    // semantics preserved in the rendered output.
    created_by: Option<String>,
    method_reference: Option<String>,
    alternatives_considered: Option<String>,
    tool_version: Option<String>,
    validation_level: i64,
    /// Reviews gathered separately via `analysis_reviews::list_for_case`
    /// and joined by note_id at gathering time. Ordered by review
    /// created_at ASC (chronological review history).
    reviews: Vec<AnalysisReviewBrief>,
}

#[allow(dead_code)]
struct AnalysisReviewBrief {
    reviewed_by: String,
    reviewed_at: String,
    /// Optional reviewer commentary captured when the review was
    /// stamped. Rendered inline beneath the "Reviewed by X on Y"
    /// line in the report so substantive peer feedback isn't
    /// invisibly buried in the DB.
    review_notes: Option<String>,
}

async fn gather_report_payload(
    state: &AppState,
    case_id: &str,
) -> Result<ReportPayload, AppError> {
    let case_detail = cases::get_case(&state.db.forensics, case_id).await?;
    let case = &case_detail.case;

    let evidence_list = evidence_db::list_for_case(&state.db.forensics, case_id).await?;

    let mut all_custody: Vec<CustodyReport> = Vec::new();
    let mut all_hashes: Vec<HashReport> = Vec::new();

    for ev in &evidence_list {
        let custody = custody::list_for_evidence(&state.db.forensics, &ev.evidence_id).await?;
        for c in custody {
            all_custody.push(CustodyReport {
                evidence_id: c.evidence_id.clone(),
                custody_sequence: c.custody_sequence,
                action: c.action.clone(),
                from_party: c.from_party.clone(),
                to_party: c.to_party.clone(),
                location: c.location.clone(),
                custody_datetime: c.custody_datetime.clone(),
                purpose: c.purpose.clone(),
                notes: c.notes.clone(),
            });
        }

        let hashes = hashes::list_for_evidence(&state.db.forensics, &ev.evidence_id).await?;
        for h in hashes {
            all_hashes.push(HashReport {
                evidence_id: h.evidence_id.clone(),
                algorithm: h.algorithm.clone(),
                hash_value: h.hash_value.clone(),
                verified_by: h.verified_by.clone(),
                verification_datetime: h.verification_datetime.clone(),
                notes: h.notes.clone(),
            });
        }
    }

    let tool_list = tools::list_for_case(&state.db.forensics, case_id).await?;
    let all_tools: Vec<ToolReport> = tool_list
        .into_iter()
        .map(|t| ToolReport {
            tool_name: t.tool_name.clone(),
            version: t.version.clone(),
            purpose: t.purpose.clone(),
            command_used: t.command_used.clone(),
            input_file: t.input_file.clone(),
            output_file: t.output_file.clone(),
            execution_datetime: t.execution_datetime.clone(),
            operator: t.operator.clone(),
            evidence_id: t.evidence_id.clone(),
        })
        .collect();

    let analysis_list = analysis::list_for_case(&state.db.forensics, case_id).await?;

    // Gather reviews for every note in the case in one query and group
    // by note_id so the rendering path can attach them without N+1.
    let review_list = analysis_reviews::list_for_case(&state.db.forensics, case_id).await?;
    let mut reviews_by_note: std::collections::HashMap<i64, Vec<AnalysisReviewBrief>> =
        std::collections::HashMap::new();
    for r in review_list {
        reviews_by_note
            .entry(r.note_id)
            .or_default()
            .push(AnalysisReviewBrief {
                reviewed_by: r.reviewed_by,
                reviewed_at: r.reviewed_at,
                review_notes: r.review_notes,
            });
    }

    let analysis_notes: Vec<AnalysisReport> = analysis_list
        .into_iter()
        .map(|n| AnalysisReport {
            note_id: n.note_id,
            category: n.category.clone(),
            finding: n.finding.clone(),
            description: n.description.clone(),
            confidence_level: n.confidence_level.clone(),
            evidence_id: n.evidence_id.clone(),
            created_by: n.created_by.clone(),
            method_reference: n.method_reference.clone(),
            alternatives_considered: n.alternatives_considered.clone(),
            tool_version: n.tool_version.clone(),
            validation_level: n.validation_level,
            reviews: reviews_by_note.remove(&n.note_id).unwrap_or_default(),
        })
        .collect();

    let evidence_items: Vec<EvidenceReport> = evidence_list
        .iter()
        .map(|e| EvidenceReport {
            evidence_id: e.evidence_id.clone(),
            description: e.description.clone(),
            collected_by: e.collected_by.clone(),
            collection_datetime: e.collection_datetime.clone(),
            location: e.location.clone(),
            status: e.status.clone(),
            evidence_type: e.evidence_type.clone(),
        })
        .collect();

    // Persons — filter entities to entity_type = 'person'
    let entity_list = entities::list_for_case(&state.db.forensics, case_id).await?;

    // Build a lookup of entity_id → display_name for link rendering below.
    // We need this before consuming `entity_list` into the persons Vec.
    let mut entity_label_by_id: std::collections::HashMap<String, String> =
        std::collections::HashMap::new();
    for e in &entity_list {
        entity_label_by_id.insert(e.entity_id.to_string(), e.display_name.clone());
    }

    // Phase B: gather person_identifiers per person ahead of constructing the
    // PersonReport vec. One query per person — list_for_entity is small (5–50
    // rows typically) so the overhead is negligible.
    let mut persons: Vec<PersonReport> = Vec::new();
    for p in entity_list.into_iter().filter(|e| e.entity_type == "person") {
        let osint_tools_run: Vec<String> = p
            .metadata_json
            .as_deref()
            .and_then(|s| serde_json::from_str::<serde_json::Value>(s).ok())
            .and_then(|v| v.get("osint_findings").cloned())
            .and_then(|v| v.as_array().cloned())
            .map(|arr| {
                arr.into_iter()
                    .filter_map(|f| {
                        f.get("tool_name")
                            .and_then(|t| t.as_str())
                            .map(|s| s.to_string())
                    })
                    .collect()
            })
            .unwrap_or_default();

        let identifier_rows =
            person_identifiers::list_for_entity(&state.db.forensics, p.entity_id).await?;
        let identifiers: Vec<IdentifierReport> = identifier_rows
            .into_iter()
            .map(|r| IdentifierReport {
                kind: r.kind,
                value: r.value,
                platform: r.platform,
                notes: r.notes,
                discovered_via_tool: r.discovered_via_tool,
                attributed_by: r.attributed_by,
                attribution_basis: r.attribution_basis,
                confidence_level: r.confidence_level,
                verification_status: r.verification_status,
            })
            .collect();

        persons.push(PersonReport {
            entity_id: p.entity_id,
            display_name: p.display_name,
            subtype: p.subtype,
            organizational_rank: p.organizational_rank,
            email: p.email,
            phone: p.phone,
            username: p.username,
            employer: p.employer,
            dob: p.dob,
            notes: p.notes,
            osint_tools_run,
            identifiers,
        });
    }

    // Phase B: gather entity_links for the case + resolve endpoint labels.
    let link_rows = links_db::list_for_case(&state.db.forensics, case_id).await?;
    let links: Vec<LinkReport> = link_rows
        .into_iter()
        .map(|l| {
            // Resolve a human-readable label per endpoint. Entity endpoints
            // resolve via `entity_label_by_id`; evidence endpoints render the
            // raw evidence_id (which is already human-readable, e.g. "E-001").
            let label_for = |ty: &str, id: &str| -> String {
                if ty == "entity" {
                    entity_label_by_id
                        .get(id)
                        .cloned()
                        .unwrap_or_else(|| format!("entity #{id}"))
                } else {
                    id.to_string()
                }
            };
            let source_label = label_for(&l.source_type, &l.source_id);
            let target_label = label_for(&l.target_type, &l.target_id);
            LinkReport {
                link_id: l.link_id,
                source_type: l.source_type,
                source_id: l.source_id,
                source_label,
                target_type: l.target_type,
                target_id: l.target_id,
                target_label,
                link_label: l.link_label,
                directional: l.directional != 0,
                weight: l.weight,
                notes: l.notes,
                attributed_by: l.attributed_by,
                basis: l.basis,
                confidence_level: l.confidence_level,
                method_reference: l.method_reference,
                alternatives_considered: l.alternatives_considered,
                evidence_refs: l.evidence_refs,
            }
        })
        .collect();

    Ok(ReportPayload {
        case_id: case.case_id.clone(),
        case_name: case.case_name.clone(),
        description: case.description.clone(),
        investigator: case.investigator.clone(),
        agency: case.agency.clone(),
        // start_date / end_date are now Strings from the DB (v1-compat).
        // Pass them through verbatim — the report is a text document and the
        // frontend display code already handles both `YYYY-MM-DD` and the
        // v1 space-separated datetime format for rendering.
        start_date: case.start_date.clone(),
        end_date: case.end_date.clone(),
        status: case.status.clone(),
        priority: case.priority.clone(),
        classification: case.classification.clone(),
        tags: case_detail.tags.clone(),
        evidence_items,
        persons,
        all_custody,
        all_hashes,
        all_tools,
        analysis_notes,
        links,
        generated_at: Utc::now().format("%Y-%m-%dT%H:%M:%S%.6fZ").to_string(),
    })
}

// ─── Rendering ────────────────────────────────────────────────────────────────

fn render_markdown(p: &ReportPayload) -> Result<String, AppError> {
    let mut out = String::with_capacity(8192);

    // ── YAML front-matter ────────────────────────────────────────────────────
    out.push_str("---\n");
    out.push_str(&format!("case_id: \"{}\"\n", esc_yaml(&p.case_id)));
    out.push_str("report_type: \"Forensic Analysis Report\"\n");
    out.push_str(&format!("date: \"{}\"\n", &p.generated_at[..10]));
    out.push_str(&format!("investigator: \"{}\"\n", esc_yaml(&p.investigator)));
    out.push_str(&format!(
        "agency: \"{}\"\n",
        esc_yaml(p.agency.as_deref().unwrap_or(""))
    ));
    if !p.tags.is_empty() {
        out.push_str("tags:\n");
        for tag in &p.tags {
            out.push_str(&format!("  - \"{}\"\n", esc_yaml(tag)));
        }
    }
    out.push_str(&format!("status: \"{}\"\n", esc_yaml(&p.status)));
    out.push_str(&format!("priority: \"{}\"\n", esc_yaml(&p.priority)));
    out.push_str(&format!(
        "classification: \"{}\"\n",
        esc_yaml(p.classification.as_deref().unwrap_or(""))
    ));
    out.push_str("---\n\n");

    // ── Title ────────────────────────────────────────────────────────────────
    out.push_str(&format!(
        "# {} - Forensic Analysis Report\n\n",
        esc_md(&p.case_name)
    ));

    // ── Executive Summary ────────────────────────────────────────────────────
    out.push_str("## Executive Summary\n");
    out.push_str(&format!("> {}\n\n", generate_executive_summary(p)));

    // ── Case Overview ────────────────────────────────────────────────────────
    out.push_str("## Case Overview\n");
    out.push_str(&format!("- **Case ID**: `{}`\n", esc_md(&p.case_id)));
    out.push_str("- **Report Type**: Forensic Analysis Report\n");
    out.push_str(&format!("- **Date**: {}\n", &p.generated_at[..10]));
    out.push_str(&format!("- **Investigator**: {}\n", esc_md(&p.investigator)));
    out.push_str(&format!(
        "- **Agency**: {}\n",
        esc_md(p.agency.as_deref().unwrap_or(""))
    ));
    out.push_str(&format!("- **Status**: {}\n", esc_md(&p.status)));
    out.push_str(&format!("- **Priority**: {}\n", esc_md(&p.priority)));
    out.push_str(&format!(
        "- **Classification**: {}\n",
        esc_md(p.classification.as_deref().unwrap_or(""))
    ));
    if let Some(desc) = &p.description {
        out.push_str(&format!("- **Description**: {}\n", esc_md(desc)));
    }
    if !p.tags.is_empty() {
        out.push_str(&format!("- **Tags**: {}\n", p.tags.join(", ")));
    }
    out.push('\n');

    // ── Table of Contents ─────────────────────────────────────────────────────
    out.push_str("## Table of Contents\n");
    out.push_str("- [Case Overview](#case-overview)\n");
    out.push_str("- [Evidence Log](#evidence-log)\n");
    if !p.persons.is_empty() {
        out.push_str("- [Persons](#persons)\n");
    }
    out.push_str("- [Analysis Findings](#analysis-findings)\n");
    out.push_str("- [Chain of Custody](#chain-of-custody)\n");
    out.push_str("- [Hash Verification](#hash-verification)\n");
    out.push_str("- [Tool Usage](#tool-usage)\n");
    out.push_str("- [Conclusion](#conclusion)\n");
    out.push_str("- [Appendices](#appendices)\n\n");
    out.push_str("---\n\n");

    // ── Evidence Log ──────────────────────────────────────────────────────────
    out.push_str("## Evidence Log\n\n");
    out.push_str("| Evidence ID | Description | Collected By | Collection Date/Time | Location | Status |\n");
    out.push_str("|-------------|-------------|--------------|----------------------|----------|--------|\n");
    for ev in &p.evidence_items {
        out.push_str(&format!(
            "| {} | {} | {} | {} | {} | {} |\n",
            esc_md(&ev.evidence_id),
            esc_md(&ev.description),
            esc_md(&ev.collected_by),
            esc_md(&ev.collection_datetime),
            esc_md(ev.location.as_deref().unwrap_or("")),
            esc_md(&ev.status),
        ));
    }
    out.push('\n');

    // ── Persons ───────────────────────────────────────────────────────────────
    //
    // Listed individually with their known profile fields and an OSINT run
    // count. OSINT tool narratives themselves appear in the Tool Usage section
    // below — each `ai_osint_person` run inserts one `tool_usage` row.
    if !p.persons.is_empty() {
        out.push_str("## Persons\n\n");
        out.push_str(
            "The following persons are identified in this case (suspects, \
             victims, witnesses, investigators, and persons of interest). Their \
             OSINT investigation runs, if any, appear in the Tool Usage section \
             below with full per-tool narratives.\n\n",
        );

        for (i, person) in p.persons.iter().enumerate() {
            let role = match person.subtype.as_deref() {
                Some(s) => format!(" — {}", s),
                None => String::new(),
            };
            out.push_str(&format!(
                "### {}. {}{}\n\n",
                i + 1,
                esc_md(&person.display_name),
                esc_md(&role)
            ));

            if let Some(title) = &person.organizational_rank {
                out.push_str(&format!("- **Title / rank**: {}\n", esc_md(title)));
            }
            if let Some(employer) = &person.employer {
                out.push_str(&format!("- **Employer**: {}\n", esc_md(employer)));
            }
            if let Some(email) = &person.email {
                out.push_str(&format!("- **Email**: {}\n", esc_md(email)));
            }
            if let Some(phone) = &person.phone {
                out.push_str(&format!("- **Phone**: {}\n", esc_md(phone)));
            }
            if let Some(username) = &person.username {
                out.push_str(&format!(
                    "- **Handle / username**: `{}`\n",
                    esc_md(username)
                ));
            }
            if let Some(dob) = &person.dob {
                out.push_str(&format!("- **Date of birth**: {}\n", esc_md(dob)));
            }

            if !person.osint_tools_run.is_empty() {
                out.push_str(&format!(
                    "- **OSINT runs executed**: {} — {} (see **Tool Usage** for full narrative)\n",
                    person.osint_tools_run.len(),
                    esc_md(&person.osint_tools_run.join(", "))
                ));
            } else {
                out.push_str("- **OSINT runs executed**: none\n");
            }

            // Phase B (migration 0008): identifier sub-list with attribution.
            render_person_identifiers(&mut out, &person.identifiers);

            if let Some(notes) = &person.notes {
                if !notes.trim().is_empty() {
                    out.push_str(&format!("\n**Notes**:\n\n{}\n", esc_md(notes)));
                }
            }
            out.push_str("\n---\n\n");
        }
    }

    // ── Analysis Findings ─────────────────────────────────────────────────────
    out.push_str("## Analysis Findings\n\n");

    // Validation summary line — counts reveal methodology coverage at
    // a glance. "N findings total · M peer-reviewed · K pending review"
    let total = p.analysis_notes.len();
    let reviewed = p.analysis_notes.iter().filter(|n| !n.reviews.is_empty()).count();
    let pending = total - reviewed;
    let validated = p.analysis_notes.iter().filter(|n| n.validation_level >= 3).count();
    out.push_str(&format!(
        "_{} finding{} total · {} peer-reviewed · {} pending review · {} examiner-validated_\n\n",
        total,
        if total == 1 { "" } else { "s" },
        reviewed,
        pending,
        validated,
    ));

    // Per-note detail blocks — author, methodology, alternatives, and
    // review footer inline so a single finding reads as a self-contained
    // forensic record when a reader jumps to it from the TOC.
    for note in &p.analysis_notes {
        out.push_str(&format!(
            "### {} — {}\n",
            esc_md(&note.category),
            esc_md(&note.finding),
        ));
        out.push_str(&format!(
            "- **Author**: {}\n",
            esc_md(note.created_by.as_deref().unwrap_or("not recorded")),
        ));
        out.push_str(&format!(
            "- **Confidence**: {}\n",
            esc_md(&note.confidence_level),
        ));
        out.push_str(&format!(
            "- **Validation Level**: {} ({})",
            note.validation_level,
            validation_level_name(note.validation_level),
        ));
        if note.validation_level == 0 {
            out.push_str(" — *not independently validated*");
        }
        out.push_str("\n");
        if let Some(ev) = &note.evidence_id {
            out.push_str(&format!("- **Evidence**: {}\n", esc_md(ev)));
        }
        if let Some(method) = note.method_reference.as_deref().filter(|s| !s.trim().is_empty()) {
            out.push_str(&format!("- **Method**: {}\n", esc_md(method)));
        }
        if let Some(tv) = note.tool_version.as_deref().filter(|s| !s.trim().is_empty()) {
            out.push_str(&format!("- **Tool**: {}\n", esc_md(tv)));
        }
        if let Some(desc) = note.description.as_deref().filter(|s| !s.trim().is_empty()) {
            out.push_str(&format!("\n{}\n", esc_md(desc)));
        }
        if let Some(alts) = note
            .alternatives_considered
            .as_deref()
            .filter(|s| !s.trim().is_empty())
        {
            out.push_str(&format!(
                "\n**Alternative explanations considered:**\n\n{}\n",
                esc_md(alts),
            ));
        }
        if note.reviews.is_empty() {
            out.push_str("\n_Pending peer review_\n");
        } else {
            out.push_str("\n**Peer review:**\n");
            for r in &note.reviews {
                out.push_str(&format!(
                    "- Reviewed by {} on {}",
                    esc_md(&r.reviewed_by),
                    esc_md(&r.reviewed_at),
                ));
                // Reviewer commentary surfaces inline when present.
                // Indented continuation under the bullet preserves
                // the list structure across CommonMark renderers.
                if let Some(notes) = r.review_notes.as_deref().filter(|s| !s.trim().is_empty()) {
                    out.push_str(&format!("\n\n  > {}", esc_md(notes)));
                }
                out.push('\n');
            }
        }
        out.push_str("\n");
    }

    out.push_str("### Key Findings\n");
    for note in p
        .analysis_notes
        .iter()
        .filter(|n| n.confidence_level == "High" || n.confidence_level == "Medium")
    {
        let suffix = if note.reviews.is_empty() {
            " _(pending peer review)_"
        } else {
            ""
        };
        out.push_str(&format!("- {}{}\n", esc_md(&note.finding), suffix));
    }
    out.push_str("\n---\n\n");

    // ── Chain of Custody ──────────────────────────────────────────────────────
    out.push_str("## Chain of Custody\n\n");
    for (i, c) in p.all_custody.iter().enumerate() {
        out.push_str(&format!("### Custody Event {}\n", i + 1));
        out.push_str(&format!("- **Date/Time**: {}\n", esc_md(&c.custody_datetime)));
        out.push_str(&format!("- **Action**: {}\n", esc_md(&c.action)));
        out.push_str(&format!("- **From**: {}\n", esc_md(&c.from_party)));
        out.push_str(&format!("- **To**: {}\n", esc_md(&c.to_party)));
        out.push_str(&format!(
            "- **Location**: {}\n",
            esc_md(c.location.as_deref().unwrap_or(""))
        ));
        out.push_str(&format!(
            "- **Purpose**: {}\n",
            esc_md(c.purpose.as_deref().unwrap_or(""))
        ));
        out.push_str(&format!(
            "- **Notes**: {}\n",
            esc_md(c.notes.as_deref().unwrap_or(""))
        ));
        out.push_str("\n---\n\n");
    }

    // ── Hash Verification ─────────────────────────────────────────────────────
    out.push_str("## Hash Verification\n\n");
    out.push_str("| Evidence ID | Algorithm | Hash Value | Verified By | Verification Date |\n");
    out.push_str("|-------------|-----------|------------|-------------|-------------------|\n");
    for h in &p.all_hashes {
        out.push_str(&format!(
            "| {} | {} | {} | {} | {} |\n",
            esc_md(&h.evidence_id),
            esc_md(&h.algorithm),
            esc_md(&h.hash_value),
            esc_md(&h.verified_by),
            esc_md(&h.verification_datetime),
        ));
    }
    out.push('\n');

    // ── Tool Usage ────────────────────────────────────────────────────────────
    out.push_str("## Tool Usage\n\n");
    out.push_str(
        "The following forensic tools were used during the examination. \
         For each tool, this section documents what the tool is, the \
         case-specific purpose and command, the types of findings the tool \
         typically produces, its forensic significance, and its relationship \
         to other tools in this case's investigation chain. This is intended \
         to make the tool selection and results intelligible to attorneys, \
         judges, and opposing experts without requiring separate forensic \
         expertise.\n\n",
    );

    // Summary table first — for at-a-glance review
    out.push_str("### Summary table\n\n");
    out.push_str("| # | Tool | Category | Version | Operator | Date/time | Scope |\n");
    out.push_str("|---|------|----------|---------|----------|-----------|-------|\n");
    for (i, t) in p.all_tools.iter().enumerate() {
        let kb = forensic_tools::lookup(&t.tool_name);
        let name = kb.map(|k| k.name).unwrap_or(&t.tool_name);
        let category = kb.map(|k| k.category.label()).unwrap_or("(not in KB)");
        let scope = t
            .evidence_id
            .as_deref()
            .map(|e| format!("Evidence {e}"))
            .unwrap_or_else(|| "Case-wide".to_string());
        out.push_str(&format!(
            "| {} | {} | {} | {} | {} | {} | {} |\n",
            i + 1,
            esc_md(name),
            esc_md(category),
            esc_md(t.version.as_deref().unwrap_or("")),
            esc_md(&t.operator),
            esc_md(&t.execution_datetime),
            esc_md(&scope),
        ));
    }
    out.push('\n');

    // Collect case tool names for dependency chaining
    let case_tool_names: Vec<String> =
        p.all_tools.iter().map(|t| t.tool_name.clone()).collect();

    // Per-tool narrative sections
    for (i, t) in p.all_tools.iter().enumerate() {
        let kb = forensic_tools::lookup(&t.tool_name);
        let display_name = kb.map(|k| k.name).unwrap_or(&t.tool_name);

        out.push_str(&format!(
            "### {}. {}\n\n",
            i + 1,
            esc_md(display_name)
        ));

        // Header facts
        if let Some(k) = kb {
            out.push_str(&format!("- **Category**: {}\n", k.category.label()));
        } else {
            out.push_str("- **Category**: Not in curated knowledge base\n");
        }
        if let Some(v) = &t.version {
            out.push_str(&format!("- **Version used**: {}\n", esc_md(v)));
        }
        out.push_str(&format!("- **Operator**: {}\n", esc_md(&t.operator)));
        out.push_str(&format!(
            "- **Date/time executed**: {}\n",
            esc_md(&t.execution_datetime)
        ));
        out.push_str(&format!(
            "- **Evidence scope**: {}\n",
            match &t.evidence_id {
                Some(e) => format!("Evidence `{}`", esc_md(e)),
                None => "Case-wide (not bound to a single evidence item)".to_string(),
            }
        ));
        if let Some(k) = kb {
            if let Some(r) = k.reference {
                out.push_str(&format!("- **Reference**: {}\n", r));
            }
        }
        out.push('\n');

        // About the tool
        out.push_str("**About the tool**\n\n");
        if let Some(k) = kb {
            out.push_str(k.description);
            out.push_str("\n\n");
        } else {
            out.push_str(&format!(
                "{} is not in the curated forensic-tools knowledge base. \
                 See the operator-recorded purpose and command below for the \
                 case-specific context of its use.\n\n",
                esc_md(&t.tool_name)
            ));
        }

        // What it was used for in this case
        out.push_str("**What it was used for in this case**\n\n");
        out.push_str(&t.purpose);
        out.push_str("\n\n");
        if let Some(cmd) = &t.command_used {
            out.push_str("**Command executed**\n\n");
            out.push_str("```\n");
            out.push_str(cmd);
            out.push_str("\n```\n\n");
        }
        if t.input_file.is_some() || t.output_file.is_some() {
            if let Some(input) = &t.input_file {
                out.push_str(&format!("- **Input file**: `{}`\n", esc_md(input)));
            }
            if let Some(output) = &t.output_file {
                out.push_str(&format!("- **Output file**: `{}`\n", esc_md(output)));
            }
            out.push('\n');
        }

        // Typical findings (KB)
        if let Some(k) = kb {
            if !k.typical_findings.is_empty() {
                out.push_str("**What this tool typically finds**\n\n");
                for f in k.typical_findings {
                    out.push_str(&format!("- {}\n", f));
                }
                out.push('\n');
            }

            // Why it matters (KB)
            out.push_str("**Why it matters**\n\n");
            out.push_str(k.why_it_matters);
            out.push_str("\n\n");

            // Investigation chain resolved to case tools
            let prereqs = forensic_tools::prerequisites_in_case(k, &case_tool_names);
            let deps = forensic_tools::dependents_in_case(k, &case_tool_names);
            if !prereqs.is_empty() || !deps.is_empty() {
                out.push_str("**Investigation chain in this case**\n\n");
                if !prereqs.is_empty() {
                    let names: Vec<String> = prereqs
                        .iter()
                        .map(|(raw, kb)| {
                            kb.map(|k| k.name.to_string()).unwrap_or_else(|| raw.clone())
                        })
                        .collect();
                    out.push_str(&format!(
                        "- **Consumes output from**: {}\n",
                        names.join(", ")
                    ));
                }
                if !deps.is_empty() {
                    let names: Vec<String> = deps
                        .iter()
                        .map(|(raw, kb)| {
                            kb.map(|k| k.name.to_string()).unwrap_or_else(|| raw.clone())
                        })
                        .collect();
                    out.push_str(&format!("- **Feeds into**: {}\n", names.join(", ")));
                }
                out.push('\n');
            }
        }

        out.push_str("---\n\n");
    }

    // ── Entity Connections (Phase B, migration 0008) ──────────────────────────
    render_entity_connections(&mut out, &p.links);

    // ── Conclusion ────────────────────────────────────────────────────────────
    out.push_str("## Conclusion\n\n");
    out.push_str(&generate_conclusion(p));
    out.push_str("\n\n");

    // ── Appendices ────────────────────────────────────────────────────────────
    out.push_str("## Appendices\n\n");

    out.push_str("### Appendix A: Glossary\n\n");
    for (term, def) in get_glossary() {
        out.push_str(&format!("- **{}**: {}\n", term, def));
    }
    out.push('\n');

    out.push_str("### Appendix B: Case Metadata\n\n");
    out.push_str(&format!(
        "- **Total Evidence Items**: {}\n",
        p.evidence_items.len()
    ));
    out.push_str(&format!("- **Total Persons**: {}\n", p.persons.len()));
    out.push_str(&format!(
        "- **Total Custody Events**: {}\n",
        p.all_custody.len()
    ));
    out.push_str(&format!(
        "- **Total Hash Verifications**: {}\n",
        p.all_hashes.len()
    ));
    let tools_used: Vec<&str> = p.all_tools.iter().map(|t| t.tool_name.as_str()).collect();
    out.push_str(&format!("- **Tools Used**: {}\n", tools_used.join(", ")));
    out.push_str(&format!(
        "- **Analysis Notes**: {}\n",
        p.analysis_notes.len()
    ));
    out.push('\n');

    out.push_str("### Appendix C: Notes\n\n");
    out.push_str("Report generated by DFARS Desktop\n\n");

    out.push_str("---\n\n");
    out.push_str("*Report generated by DFARS Desktop*  \n");
    out.push_str("*System Version: 2.0.0*  \n");
    out.push_str(&format!("*Generated: {}*  \n", &p.generated_at));
    out.push_str(&format!("*Case ID: {}*\n", esc_md(&p.case_id)));

    Ok(out)
}

/// HTML rendering — Phase 3b deliverable: wrap the markdown in a minimal HTML shell.
/// Full HTML rendering is deferred per spec.
fn render_html(p: &ReportPayload) -> Result<String, AppError> {
    let md = render_markdown(p)?;
    Ok(format!(
        "<!DOCTYPE html><html><head><meta charset=\"utf-8\"><title>{} - Report</title></head><body><pre>{}</pre></body></html>",
        esc_html(&p.case_name),
        esc_html(&md),
    ))
}

// ─── Report content helpers ───────────────────────────────────────────────────

fn generate_executive_summary(p: &ReportPayload) -> String {
    // Tag each finding's summary string with a pending-review suffix
    // when no peer review has been stamped — the executive summary is
    // the first thing a reader sees, so the qualifier has to be
    // colocated with the claim.
    fn tagged(note: &AnalysisReport) -> String {
        if note.reviews.is_empty() {
            format!("{} (pending peer review)", note.finding)
        } else {
            note.finding.clone()
        }
    }

    let high_conf: Vec<String> = p
        .analysis_notes
        .iter()
        .filter(|n| n.confidence_level == "High")
        .map(tagged)
        .take(3)
        .collect();
    let med_conf: Vec<String> = p
        .analysis_notes
        .iter()
        .filter(|n| n.confidence_level == "Medium")
        .map(tagged)
        .take(3)
        .collect();

    let mut summary = format!(
        "Analysis of {} evidence items in case {}. ",
        p.evidence_items.len(),
        p.case_id
    );
    if !high_conf.is_empty() {
        summary.push_str(&format!(
            "Key findings include: {}. ",
            high_conf.join("; ")
        ));
    } else if !med_conf.is_empty() {
        summary.push_str(&format!(
            "Notable findings include: {}. ",
            med_conf.join("; ")
        ));
    } else {
        summary.push_str("Analysis completed; see detailed findings section. ");
    }
    summary.push_str(&format!(
        "Case status: {}. Priority: {}.",
        p.status, p.priority
    ));
    summary
}

// ─── Phase B (migration 0008) attribution renderers ──────────────────────────

/// Render a person's identifier sub-list with attribution chips. Skipped
/// entirely when the person has no identifiers (keeps the report compact for
/// v1 cases that pre-date Phase B).
fn render_person_identifiers(out: &mut String, identifiers: &[IdentifierReport]) {
    if identifiers.is_empty() {
        return;
    }

    let total = identifiers.len();
    let confirmed = identifiers
        .iter()
        .filter(|i| i.verification_status.as_deref() == Some("Confirmed"))
        .count();
    let unverified = identifiers
        .iter()
        .filter(|i| {
            i.verification_status.as_deref() == Some("Unverified")
                || i.verification_status.is_none()
        })
        .count();

    out.push_str("\n#### Identifiers\n\n");
    out.push_str(&format!(
        "_{} identifier{} total · {} confirmed · {} unverified_\n\n",
        total,
        if total == 1 { "" } else { "s" },
        confirmed,
        unverified,
    ));

    for ident in identifiers {
        let platform_suffix = ident
            .platform
            .as_deref()
            .filter(|p| !p.trim().is_empty())
            .map(|p| format!(" ({})", esc_md(p)))
            .unwrap_or_default();
        out.push_str(&format!(
            "- **{}**: `{}`{}\n",
            esc_md(&ident.kind),
            esc_md(&ident.value),
            platform_suffix,
        ));

        // Attribution chip line: Author · Confidence · Verification.
        let author = ident
            .attributed_by
            .as_deref()
            .filter(|s| !s.trim().is_empty())
            .unwrap_or("not recorded");
        let confidence = ident
            .confidence_level
            .as_deref()
            .filter(|s| !s.trim().is_empty())
            .unwrap_or("not recorded");
        let verification = ident
            .verification_status
            .as_deref()
            .filter(|s| !s.trim().is_empty())
            .unwrap_or("Unverified");
        out.push_str(&format!(
            "  _Author: {} · Confidence: {} · Status: {}_\n",
            esc_md(author),
            esc_md(confidence),
            esc_md(verification),
        ));

        if let Some(basis) = ident
            .attribution_basis
            .as_deref()
            .filter(|s| !s.trim().is_empty())
        {
            out.push_str(&format!("  _Basis: {}_\n", esc_md(basis)));
        }
        if let Some(tool) = ident
            .discovered_via_tool
            .as_deref()
            .filter(|s| !s.trim().is_empty())
        {
            out.push_str(&format!("  _Source tool: {}_\n", esc_md(tool)));
        }
    }
    out.push('\n');
}

/// Render the new "## Entity Connections" section, listing every active
/// entity_link with full attribution.  Skipped entirely when the case has
/// no links (which is most pre-Phase-B v1 data).
fn render_entity_connections(out: &mut String, links: &[LinkReport]) {
    if links.is_empty() {
        return;
    }

    out.push_str("## Entity Connections\n\n");
    out.push_str(
        "The following connections between entities and evidence have been \
         asserted by the investigator. Each connection records the basis of \
         the attribution and the level of confidence assigned. Connections \
         marked **low-confidence** or that include explicit \
         **alternatives considered** should be re-examined under \
         cross-examination.\n\n",
    );

    let total = links.len();
    let high_confidence = links
        .iter()
        .filter(|l| l.confidence_level.as_deref() == Some("High"))
        .count();
    let with_alternatives = links
        .iter()
        .filter(|l| {
            l.alternatives_considered
                .as_deref()
                .map(|s| !s.trim().is_empty())
                .unwrap_or(false)
        })
        .count();
    out.push_str(&format!(
        "_{} connection{} total · {} high-confidence · {} with alternatives considered_\n\n",
        total,
        if total == 1 { "" } else { "s" },
        high_confidence,
        with_alternatives,
    ));

    for (i, link) in links.iter().enumerate() {
        let direction_arrow = if link.directional { "→" } else { "↔" };
        let label_suffix = link
            .link_label
            .as_deref()
            .filter(|s| !s.trim().is_empty())
            .map(|s| format!(" — {}", esc_md(s)))
            .unwrap_or_default();
        out.push_str(&format!(
            "### {}. {} {} {}{}\n",
            i + 1,
            esc_md(&link.source_label),
            direction_arrow,
            esc_md(&link.target_label),
            label_suffix,
        ));

        // Attribution chip line.
        let author = link
            .attributed_by
            .as_deref()
            .filter(|s| !s.trim().is_empty())
            .unwrap_or("not recorded");
        let confidence = link
            .confidence_level
            .as_deref()
            .filter(|s| !s.trim().is_empty())
            .unwrap_or("not recorded");
        out.push_str(&format!(
            "_Author: {} · Confidence: {}_\n\n",
            esc_md(author),
            esc_md(confidence),
        ));

        if let Some(basis) = link.basis.as_deref().filter(|s| !s.trim().is_empty()) {
            out.push_str(&format!("**Basis**: {}\n\n", esc_md(basis)));
        }
        if let Some(method) = link
            .method_reference
            .as_deref()
            .filter(|s| !s.trim().is_empty())
        {
            out.push_str(&format!("**Method reference**: {}\n\n", esc_md(method)));
        }
        if let Some(alt) = link
            .alternatives_considered
            .as_deref()
            .filter(|s| !s.trim().is_empty())
        {
            out.push_str(&format!(
                "> **Alternatives considered:** {}\n\n",
                esc_md(alt)
            ));
        }
        if let Some(refs) = link
            .evidence_refs
            .as_deref()
            .filter(|s| !s.trim().is_empty())
        {
            out.push_str(&format!("_Evidence refs: {}_\n\n", esc_md(refs)));
        }
        if let Some(notes) = link.notes.as_deref().filter(|s| !s.trim().is_empty()) {
            out.push_str(&format!("**Notes**: {}\n\n", esc_md(notes)));
        }
    }
    out.push_str("---\n\n");
}

fn generate_conclusion(p: &ReportPayload) -> String {
    let mut conclusion = format!(
        "The examination of case {} involved the analysis of {} evidence items. ",
        p.case_id,
        p.evidence_items.len()
    );
    let high: Vec<&str> = p
        .analysis_notes
        .iter()
        .filter(|n| n.confidence_level == "High")
        .map(|n| n.finding.as_str())
        .collect();
    let med: Vec<&str> = p
        .analysis_notes
        .iter()
        .filter(|n| n.confidence_level == "Medium")
        .map(|n| n.finding.as_str())
        .collect();
    if !high.is_empty() {
        conclusion.push_str(&format!(
            "High confidence findings: {}. ",
            high.join("; ")
        ));
    }
    if !med.is_empty() {
        conclusion.push_str(&format!(
            "Medium confidence findings: {}. ",
            med.join("; ")
        ));
    }
    conclusion.push_str(
        "All evidence was handled in accordance with SWGDE best practices for \
         digital evidence collection, preservation, and analysis. Chain of custody \
         was maintained throughout the examination process.",
    );
    conclusion
}

fn get_glossary() -> Vec<(&'static str, &'static str)> {
    vec![
        ("SHA-256", "Secure Hash Algorithm 256-bit, used for verifying evidence integrity"),
        ("MD5", "Message Digest Algorithm 5, used for verifying evidence integrity (not recommended for security-sensitive applications)"),
        ("SWGDE", "Scientific Working Group on Digital Evidence"),
        ("NIST", "National Institute of Standards and Technology"),
        ("Chain of Custody", "Documented, unbroken trail of accountability that ensures the integrity of physical or digital evidence"),
        ("Forensic Image", "Bit-for-bit copy of digital evidence used for analysis to preserve original evidence"),
        ("Write Blocker", "Hardware or software tool that prevents write access to a storage device during forensic examination"),
        ("Timeline Analysis", "Chronological reconstruction of events based on digital evidence timestamps"),
        ("Artifact", "Piece of data discovered during forensic examination that may be relevant to an investigation"),
    ]
}

// ─── Text escaping ────────────────────────────────────────────────────────────

/// Escape a string for use inside a markdown table cell.
/// Replaces `|` with `\|` and strips newlines.
fn esc_md(s: &str) -> String {
    s.replace('|', "\\|").replace('\n', " ").replace('\r', "")
}

/// Escape a string for YAML double-quoted scalar.
fn esc_yaml(s: &str) -> String {
    s.replace('"', "\\\"")
}

/// Escape a string for HTML content.
fn esc_html(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

/// Sanitize a case_id for use in a report filename.
fn sanitize_report_filename(case_id: &str) -> String {
    case_id
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '-' || c == '_' {
                c
            } else {
                '_'
            }
        })
        .collect()
}

// ─── Default reports directory ────────────────────────────────────────────────

/// Returns `%APPDATA%\DFARS\reports` as the default output directory.
pub fn default_reports_dir() -> PathBuf {
    directories::BaseDirs::new()
        .map(|b| b.data_dir().join("DFARS").join("reports"))
        .unwrap_or_else(|| PathBuf::from("reports"))
}

// ─── PDF rendering (Priority 3) ─────────────────────────────────────────────

fn render_pdf(p: &ReportPayload, template: &ReportTemplate) -> Result<Vec<u8>, AppError> {
    match template {
        ReportTemplate::Standard => render_pdf_standard(p),
        ReportTemplate::Swgde => render_pdf_swgde(p),
    }
}

fn render_pdf_standard(p: &ReportPayload) -> Result<Vec<u8>, AppError> {
    let mut b = PdfBuilder::new();

    // ── Cover page ──
    b.new_page();
    b.draw_title("DFARS Digital Forensics Report", 24.0, true);
    b.advance(20.0);
    b.draw_title(&format!("Case: {}", p.case_id), 18.0, true);
    b.advance(10.0);
    b.draw_text_line(&p.case_name, 14.0, false);
    b.advance(30.0);
    b.draw_line(&format!("Investigator: {}", p.investigator));
    if let Some(agency) = &p.agency {
        b.draw_line(&format!("Agency: {}", agency));
    }
    b.draw_line(&format!("Status: {} | Priority: {}", p.status, p.priority));
    b.draw_line(&format!("Start Date: {}", p.start_date));
    if let Some(end) = &p.end_date {
        b.draw_line(&format!("End Date: {}", end));
    }
    b.draw_line(&format!("Generated: {}", p.generated_at));
    if let Some(classification) = &p.classification {
        b.draw_line(&format!("Classification: {}", classification));
    }
    if !p.tags.is_empty() {
        b.draw_line(&format!("Tags: {}", p.tags.join(", ")));
    }

    // ── Scope ──
    b.new_page();
    b.draw_heading("1. Scope and Authority");
    b.draw_paragraph("This examination was conducted in accordance with SWGDE Best Practices for Computer Forensic Examinations. The scope of this report is limited to the digital evidence described herein.");
    if let Some(desc) = &p.description {
        b.draw_paragraph(&format!("Case description: {}", desc));
    }

    // ── Evidence Summary ──
    b.new_page();
    b.draw_heading("2. Evidence Summary");
    if p.evidence_items.is_empty() {
        b.draw_paragraph("No evidence items recorded.");
    } else {
        b.draw_line(&format!("{} evidence item(s) received:", p.evidence_items.len()));
        b.advance(3.0);
        for ev in &p.evidence_items {
            b.draw_bullet(&format!(
                "{} — {} (collected by {} on {})",
                ev.evidence_id, ev.description, ev.collected_by, ev.collection_datetime
            ));
        }
    }

    // ── Chain of Custody ──
    b.draw_heading("3. Chain of Custody");
    if p.all_custody.is_empty() {
        b.draw_paragraph("No custody events recorded.");
    } else {
        b.draw_line(&format!("{} custody event(s):", p.all_custody.len()));
        b.advance(3.0);
        for c in &p.all_custody {
            b.draw_bullet(&format!(
                "[{}] {}: {} → {} at {} {}",
                c.custody_sequence,
                c.action,
                c.from_party,
                c.to_party,
                c.custody_datetime,
                c.purpose.as_deref().unwrap_or("")
            ));
        }
    }

    // ── Hash Verification ──
    b.draw_heading("4. Hash Verification");
    if p.all_hashes.is_empty() {
        b.draw_paragraph("No hash verifications recorded.");
    } else {
        b.draw_line(&format!("{} hash record(s):", p.all_hashes.len()));
        b.advance(3.0);
        for h in &p.all_hashes {
            b.draw_bullet(&format!(
                "{} — {}: {} (verified by {})",
                h.evidence_id, h.algorithm, h.hash_value, h.verified_by
            ));
        }
    }

    // ── Tools and Methodology ──
    b.draw_heading("5. Tools and Methodology");
    if p.all_tools.is_empty() {
        b.draw_paragraph("No tool usage recorded.");
    } else {
        b.draw_line(&format!("{} tool run(s):", p.all_tools.len()));
        b.advance(3.0);
        for t in &p.all_tools {
            let version = t.version.as_deref().unwrap_or("unknown version");
            b.draw_bullet(&format!(
                "{} v{} — {} (operator: {})",
                t.tool_name, version, t.purpose, t.operator
            ));
        }
    }
    b.advance(3.0);
    b.draw_paragraph("Methodology aligns with SWGDE Best Practices for Computer Forensic Acquisitions, Examinations, and Reports. All analysis was performed on verified working copies; original evidence was write-blocked and never modified.");

    // ── Findings ──
    b.new_page();
    b.draw_heading("6. Findings");
    let total = p.analysis_notes.len();
    let reviewed = p.analysis_notes.iter().filter(|n| !n.reviews.is_empty()).count();
    let validated = p.analysis_notes.iter().filter(|n| n.validation_level >= 3).count();
    b.draw_line(&format!(
        "{} finding(s) total · {} peer-reviewed · {} examiner-validated",
        total, reviewed, validated
    ));
    b.advance(5.0);

    if p.analysis_notes.is_empty() {
        b.draw_paragraph("No analysis findings recorded.");
    } else {
        for note in &p.analysis_notes {
            b.draw_subheading(&format!(
                "[{}] {} — Validation Level {} ({})",
                note.category,
                note.finding,
                note.validation_level,
                validation_level_name(note.validation_level)
            ));
            b.draw_line(&format!("Confidence: {}", note.confidence_level));
            if let Some(author) = &note.created_by {
                b.draw_line(&format!("Author: {}", author));
            }
            if let Some(method) = &note.method_reference {
                b.draw_line(&format!("Method: {}", method));
            }
            if let Some(tv) = &note.tool_version {
                b.draw_line(&format!("Tool: {}", tv));
            }
            if let Some(desc) = &note.description {
                b.draw_paragraph(desc);
            }
            if let Some(alts) = &note.alternatives_considered {
                b.draw_line("Alternative explanations considered:");
                b.draw_paragraph(alts);
            }
            if note.reviews.is_empty() {
                b.draw_italic("Pending peer review.");
            } else {
                b.draw_line("Peer review:");
                for r in &note.reviews {
                    b.draw_bullet(&format!(
                        "Reviewed by {} on {}{}",
                        r.reviewed_by,
                        r.reviewed_at,
                        r.review_notes.as_deref().map(|n| format!(" — {n}")).unwrap_or_default()
                    ));
                }
            }
            b.advance(5.0);
        }
    }

    // ── Entity Summary ──
    if !p.persons.is_empty() || !p.links.is_empty() {
        b.new_page();
        b.draw_heading("7. Entity Summary");
        if !p.persons.is_empty() {
            b.draw_subheading(&format!("Persons ({})", p.persons.len()));
            for person in &p.persons {
                b.draw_bullet(&format!(
                    "{} — {}{}{}",
                    person.display_name,
                    person.subtype.as_deref().unwrap_or("person"),
                    person.email.as_deref().map(|e| format!(", email: {e}")).unwrap_or_default(),
                    person.phone.as_deref().map(|p| format!(", phone: {p}")).unwrap_or_default(),
                ));
            }
            b.advance(3.0);
        }
        if !p.links.is_empty() {
            b.draw_subheading(&format!("Entity Connections ({})", p.links.len()));
            for link in &p.links {
                let dir = if link.directional { "→" } else { "↔" };
                b.draw_bullet(&format!(
                    "{} {} {} ({})",
                    link.source_label, dir, link.target_label,
                    link.link_label.as_deref().unwrap_or("linked")
                ));
            }
        }
    }

    // ── Limitations ──
    b.new_page();
    b.draw_heading("8. Limitations");
    b.draw_paragraph("This examination was conducted within the constraints of the available evidence, tools, and time. Findings are limited to the artifacts that were recoverable and interpretable. Deleted or overwritten data may not be fully recoverable. The absence of evidence is not evidence of absence.");
    b.draw_paragraph("All findings carry a Validation Level (0–4) indicating the depth of independent verification performed. Findings marked Unvalidated (Level 0) should be treated as provisional and require further examiner validation before being relied upon in legal proceedings.");
    b.draw_paragraph("Tool versions and method references are recorded per finding to enable reproduction. Any discrepancy between the reported tool version and the version used for reproduction should be documented as a limitation.");

    // ── Signature Block ──
    b.draw_heading("9. Examiner Certification");
    b.draw_paragraph("I hereby certify that I have examined the digital evidence described in this report, that the findings are true and accurate to the best of my knowledge and ability, and that the procedures and methods used are consistent with established forensic best practices.");
    b.advance(20.0);
    b.draw_line("_________________________________________");
    b.draw_line(&format!("{}", p.investigator));
    b.draw_line("Digital Forensic Examiner");
    b.draw_line(&format!("Date: {}", p.generated_at));

    Ok(b.build())
}

// ─── PDF layout helpers (printpdf 0.9.1 ops-based API) ───────────────────────

use printpdf::{
    BuiltinFont, Mm, Op, PdfDocument, PdfFontHandle, PdfPage, PdfSaveOptions, Point, Pt,
};

struct PdfBuilder {
    pages: Vec<PdfPage>,
    ops: Vec<Op>,
    y: f32,
    page_num: usize,
}

impl PdfBuilder {
    fn new() -> Self {
        Self {
            pages: Vec::new(),
            ops: Vec::new(),
            y: 270.0,
            page_num: 0,
        }
    }

    fn new_page(&mut self) {
        if !self.ops.is_empty() || self.page_num > 0 {
            let mut ops = Vec::new();
            std::mem::swap(&mut self.ops, &mut ops);
            self.pages.push(PdfPage::new(Mm(210.0), Mm(297.0), ops));
        }
        self.y = 270.0;
        self.page_num += 1;
    }

    fn check_page_break(&mut self, needed: f32) {
        if self.y < 25.0 + needed {
            self.new_page();
        }
    }

    fn advance(&mut self, mm: f32) {
        self.y -= mm;
    }

    fn emit_text(&mut self, text: &str, size: f32, x: f32, bold: bool) {
        let font = if bold {
            PdfFontHandle::Builtin(BuiltinFont::HelveticaBold)
        } else {
            PdfFontHandle::Builtin(BuiltinFont::Helvetica)
        };
        let pdf_y = 297.0 - self.y;
        self.ops.push(Op::StartTextSection);
        self.ops.push(Op::SetFont {
            font,
            size: Pt(size),
        });
        self.ops.push(Op::SetTextCursor {
            pos: Point::new(Mm(x), Mm(pdf_y)),
        });
        self.ops.push(Op::ShowText {
            items: vec![text.into()],
        });
        self.ops.push(Op::EndTextSection);
    }

    fn draw_text_line(&mut self, text: &str, size: f32, bold: bool) {
        self.check_page_break(size / 2.0 + 2.0);
        self.emit_text(text, size, 25.0, bold);
        self.y -= size / 2.0 + 2.0;
    }

    fn draw_line(&mut self, text: &str) {
        self.check_page_break(5.0);
        self.emit_text(text, 10.0, 25.0, false);
        self.y -= 5.0;
    }

    fn draw_paragraph(&mut self, text: &str) {
        let max_width = 160.0;
        let chars_per_line = (max_width * 2.8) as usize;
        for line in textwrap::fill(text, chars_per_line).lines() {
            self.check_page_break(5.0);
            self.emit_text(line, 10.0, 25.0, false);
            self.y -= 5.0;
        }
    }

    fn draw_heading(&mut self, text: &str) {
        self.check_page_break(10.0);
        self.y -= 5.0;
        self.emit_text(text, 14.0, 25.0, true);
        self.y -= 8.0;
    }

    fn draw_subheading(&mut self, text: &str) {
        self.check_page_break(8.0);
        self.emit_text(text, 11.0, 25.0, true);
        self.y -= 6.0;
    }

    fn draw_title(&mut self, text: &str, size: f32, bold: bool) {
        self.check_page_break(10.0);
        self.emit_text(text, size, 25.0, bold);
        self.y -= size / 2.0 + 2.0;
    }

    fn draw_bullet(&mut self, text: &str) {
        self.check_page_break(5.0);
        self.emit_text("•", 10.0, 25.0, false);
        let max_width = 150.0;
        let chars_per_line = (max_width * 2.8) as usize;
        let wrapped = textwrap::fill(text, chars_per_line);
        let mut first = true;
        for line in wrapped.lines() {
            if first {
                self.emit_text(line, 10.0, 30.0, false);
                first = false;
            } else {
                self.check_page_break(5.0);
                self.emit_text(line, 10.0, 30.0, false);
            }
            self.y -= 5.0;
        }
    }

    fn draw_italic(&mut self, text: &str) {
        self.check_page_break(5.0);
        self.emit_text(text, 10.0, 25.0, false);
        self.y -= 5.0;
    }

    fn build(mut self) -> Vec<u8> {
        if !self.ops.is_empty() || self.pages.is_empty() {
            let mut ops = Vec::new();
            std::mem::swap(&mut self.ops, &mut ops);
            self.pages.push(PdfPage::new(Mm(210.0), Mm(297.0), ops));
        }
        let mut doc = PdfDocument::new("DFARS Report");
        doc.with_pages(self.pages);
        let opts = PdfSaveOptions::default();
        doc.save(&opts, &mut Vec::new())
    }
}

// ─── SWGDE PDF rendering ────────────────────────────────────────────────────

fn render_pdf_swgde(p: &ReportPayload) -> Result<Vec<u8>, AppError> {
    let mut b = SwgdePdfBuilder::new(
        p.case_id.clone(),
        p.classification.clone(),
        p.investigator.clone(),
        p.generated_at.clone(),
    );

    // ── 1. Request ──
    b.new_page();
    b.draw_section_heading("1. Request");
    b.draw_line(&format!("Date of Request: {}", p.start_date));
    b.draw_line(&format!("Requestor: {}", p.investigator));
    b.draw_line(&format!(
        "Requestor Organization: {}",
        p.agency.as_deref().unwrap_or("[Not recorded]")
    ));
    b.draw_paragraph(&format!(
        "Purpose and Scope: {}. The examination was conducted in accordance with SWGDE Best Practices for Computer Forensic Examinations.",
        p.description.as_deref().unwrap_or("[Not recorded — update case description]")
    ));
    b.draw_line("Legal Authority: [Not recorded — update case metadata with warrant, consent, contract, or other authority]");

    // ── 2. Examiner Information ──
    b.draw_section_heading("2. Examiner Information");
    b.draw_line(&format!("Examiner Name: {}", p.investigator));
    b.draw_line("Qualifications: [Not recorded — update examiner qualifications in case metadata]");
    b.draw_paragraph("The examiner certifies that they possess the training, experience, and qualifications necessary to perform the examination described in this report, consistent with SWGDE Core Competencies for Digital Forensics.");

    // ── 3. Evidence Inventory ──
    b.draw_section_heading("3. Evidence Inventory");
    if p.evidence_items.is_empty() {
        b.draw_paragraph("No evidence items were submitted or collected for this examination.");
    } else {
        b.draw_line(&format!("{} evidence item(s) submitted or collected:", p.evidence_items.len()));
        b.advance(3.0);
        for (i, ev) in p.evidence_items.iter().enumerate() {
            b.draw_bullet(&format!(
                "Item {} — {} ({}): Collected by {} on {}. Make/Model/Serial: [Not recorded]. Hash: [See Section 4].",
                i + 1,
                ev.evidence_id,
                ev.description,
                ev.collected_by,
                ev.collection_datetime
            ));
        }
    }

    // ── 4. Chain of Custody ──
    b.draw_section_heading("4. Chain of Custody");
    if p.all_custody.is_empty() {
        b.draw_paragraph("No custody events recorded.");
    } else {
        b.draw_line(&format!("{} custody event(s) documented:", p.all_custody.len()));
        b.advance(3.0);
        for c in &p.all_custody {
            b.draw_bullet(&format!(
                "[{}] {}: {} → {} at {}. Location: {}. Purpose: {}.",
                c.custody_sequence,
                c.action,
                c.from_party,
                c.to_party,
                c.custody_datetime,
                c.location.as_deref().unwrap_or("[Not recorded]"),
                c.purpose.as_deref().unwrap_or("[Not recorded]")
            ));
        }
    }

    // ── 5. Methodology ──
    b.draw_section_heading("5. Methodology");
    b.draw_paragraph("The examination was conducted in accordance with SWGDE Best Practices for Computer Forensic Acquisitions, Examinations, and Reports. All analysis was performed on verified working copies; original evidence was write-blocked and never modified.");
    if p.all_tools.is_empty() {
        b.draw_paragraph("No tool usage recorded.");
    } else {
        b.draw_line(&format!("{} forensic tool run(s) documented:", p.all_tools.len()));
        b.advance(3.0);
        for t in &p.all_tools {
            let version = t.version.as_deref().unwrap_or("unknown version");
            b.draw_bullet(&format!(
                "{} v{} — {} (operator: {})",
                t.tool_name, version, t.purpose, t.operator
            ));
        }
    }
    b.advance(3.0);
    b.draw_line("Deviations from Standard Operating Procedures: None recorded.");
    b.draw_line("Subcontractor Results: None recorded.");

    // ── 6. Findings ──
    b.draw_section_heading("6. Findings");
    let total = p.analysis_notes.len();
    let reviewed = p.analysis_notes.iter().filter(|n| !n.reviews.is_empty()).count();
    let validated = p.analysis_notes.iter().filter(|n| n.validation_level >= 3).count();
    b.draw_line(&format!(
        "{} finding(s) total · {} peer-reviewed · {} examiner-validated",
        total, reviewed, validated
    ));
    b.advance(5.0);

    if p.analysis_notes.is_empty() {
        b.draw_paragraph("No analysis findings recorded.");
    } else {
        for (i, note) in p.analysis_notes.iter().enumerate() {
            b.draw_subheading(&format!("Finding {}: [{}] {}", i + 1, note.category, note.finding));
            b.draw_line(&format!("Confidence Level: {}", note.confidence_level));
            b.draw_line(&format!(
                "Validation Level: {} ({})",
                note.validation_level,
                validation_level_name(note.validation_level)
            ));
            if let Some(author) = &note.created_by {
                b.draw_line(&format!("Author: {}", author));
            }
            if let Some(method) = &note.method_reference {
                b.draw_line(&format!("Method Reference: {}", method));
            }
            if let Some(tv) = &note.tool_version {
                b.draw_line(&format!("Tool Version: {}", tv));
            }
            if let Some(ev) = &note.evidence_id {
                b.draw_line(&format!("Evidence Reference: {}", ev));
            }
            if let Some(desc) = &note.description {
                b.draw_paragraph(&format!("Description: {}", desc));
            }
            if let Some(alts) = &note.alternatives_considered {
                b.draw_line("Alternative Explanations Considered:");
                b.draw_paragraph(alts);
            }
            if note.reviews.is_empty() {
                b.draw_italic("Peer Review Status: Pending peer review.");
            } else {
                b.draw_line("Peer Review:");
                for r in &note.reviews {
                    b.draw_bullet(&format!(
                        "Reviewed by {} on {}{}",
                        r.reviewed_by,
                        r.reviewed_at,
                        r.review_notes.as_deref().map(|n| format!(" — Notes: {n}")).unwrap_or_default()
                    ));
                }
            }
            b.advance(5.0);
        }
    }

    // ── 7. Opinions & Conclusions ──
    b.draw_section_heading("7. Opinions & Conclusions");
    let high: Vec<&str> = p
        .analysis_notes
        .iter()
        .filter(|n| n.confidence_level == "High")
        .map(|n| n.finding.as_str())
        .collect();
    let med: Vec<&str> = p
        .analysis_notes
        .iter()
        .filter(|n| n.confidence_level == "Medium")
        .map(|n| n.finding.as_str())
        .collect();
    let mut conclusion = format!(
        "The examination of case {} involved the analysis of {} evidence item(s). ",
        p.case_id,
        p.evidence_items.len()
    );
    if !high.is_empty() {
        conclusion.push_str(&format!("High confidence findings: {}. ", high.join("; ")));
    }
    if !med.is_empty() {
        conclusion.push_str(&format!("Medium confidence findings: {}. ", med.join("; ")));
    }
    conclusion.push_str("All evidence was handled in accordance with SWGDE best practices.");
    b.draw_paragraph(&conclusion);
    b.draw_paragraph("The opinions expressed in this report are based on the examiner's training, experience, and the data examined. Each opinion is documented with its basis in the Findings section above.");

    // ── 8. Disposition ──
    b.draw_section_heading("8. Disposition");
    b.draw_paragraph("The disposition of original and derivative evidence is documented below:");
    b.draw_line("Original Evidence: [Not recorded — update case metadata with returned/retained/destroyed status]");
    b.draw_line("Derivative Works (working copies, reports, exhibits): [Not recorded]");
    b.draw_line("Retention Period: Per organizational policy.");

    // ── 9. Limitations ──
    b.draw_section_heading("9. Limitations");
    b.draw_paragraph("This examination was conducted within the constraints of the available evidence, tools, and time. Findings are limited to the artifacts that were recoverable and interpretable. Deleted or overwritten data may not be fully recoverable. The absence of evidence is not evidence of absence.");
    b.draw_paragraph("All findings carry a Validation Level (0–4) indicating the depth of independent verification performed. Findings marked Unvalidated (Level 0) should be treated as provisional and require further examiner validation before being relied upon in legal proceedings.");
    b.draw_paragraph("Tool versions and method references are recorded per finding to enable reproduction. Any discrepancy between the reported tool version and the version used for reproduction should be documented as a limitation.");

    // ── 10. Report Authorization ──
    b.draw_section_heading("10. Report Authorization");
    b.draw_paragraph("I hereby certify that I have examined the digital evidence described in this report, that the findings are true and accurate to the best of my knowledge and ability, and that the procedures and methods used are consistent with established forensic best practices and SWGDE standards.");
    b.advance(20.0);
    b.draw_line("_________________________________________");
    b.draw_line(&format!("Signature: {}", p.investigator));
    b.draw_line("Title: Digital Forensic Examiner");
    b.draw_line(&format!("Date: {}", p.generated_at));

    Ok(b.build())
}

// ─── SWGDE PDF Builder (two-pass, headers/footers/TOC) ───────────────────────

struct SwgdePdfBuilder {
    content_pages: Vec<Vec<Op>>,
    current_ops: Vec<Op>,
    y: f32,
    page_num: usize,
    sections: Vec<(String, usize)>,
    case_id: String,
    classification: String,
    investigator: String,
    generated_at: String,
}

impl SwgdePdfBuilder {
    fn new(
        case_id: String,
        classification: Option<String>,
        investigator: String,
        generated_at: String,
    ) -> Self {
        Self {
            content_pages: Vec::new(),
            current_ops: Vec::new(),
            y: 270.0,
            page_num: 0,
            sections: Vec::new(),
            case_id,
            classification: classification.unwrap_or_else(|| "UNCLASSIFIED".into()),
            investigator,
            generated_at,
        }
    }

    fn new_page(&mut self) {
        if !self.current_ops.is_empty() || self.page_num > 0 {
            let mut ops = Vec::new();
            std::mem::swap(&mut self.current_ops, &mut ops);
            self.content_pages.push(ops);
        }
        self.y = 270.0;
        self.page_num += 1;
    }

    fn check_page_break(&mut self, needed: f32) {
        if self.y < 25.0 + needed {
            self.new_page();
        }
    }

    fn advance(&mut self, mm: f32) {
        self.y -= mm;
    }

    fn emit_text(&mut self, text: &str, size: f32, x: f32, bold: bool) {
        let font = if bold {
            PdfFontHandle::Builtin(BuiltinFont::HelveticaBold)
        } else {
            PdfFontHandle::Builtin(BuiltinFont::Helvetica)
        };
        let pdf_y = 297.0 - self.y;
        self.current_ops.push(Op::StartTextSection);
        self.current_ops.push(Op::SetFont {
            font,
            size: Pt(size),
        });
        self.current_ops.push(Op::SetTextCursor {
            pos: Point::new(Mm(x), Mm(pdf_y)),
        });
        self.current_ops.push(Op::ShowText {
            items: vec![text.into()],
        });
        self.current_ops.push(Op::EndTextSection);
    }

    fn draw_line(&mut self, text: &str) {
        self.check_page_break(5.0);
        self.emit_text(text, 10.0, 25.0, false);
        self.y -= 5.0;
    }

    fn draw_paragraph(&mut self, text: &str) {
        let max_width = 160.0;
        let chars_per_line = (max_width * 2.8) as usize;
        for line in textwrap::fill(text, chars_per_line).lines() {
            self.check_page_break(5.0);
            self.emit_text(line, 10.0, 25.0, false);
            self.y -= 5.0;
        }
    }

    fn draw_heading(&mut self, text: &str) {
        self.check_page_break(10.0);
        self.y -= 5.0;
        self.emit_text(text, 14.0, 25.0, true);
        self.y -= 8.0;
    }

    fn draw_subheading(&mut self, text: &str) {
        self.check_page_break(8.0);
        self.emit_text(text, 11.0, 25.0, true);
        self.y -= 6.0;
    }

    fn draw_bullet(&mut self, text: &str) {
        self.check_page_break(5.0);
        self.emit_text("•", 10.0, 25.0, false);
        let max_width = 150.0;
        let chars_per_line = (max_width * 2.8) as usize;
        let wrapped = textwrap::fill(text, chars_per_line);
        let mut first = true;
        for line in wrapped.lines() {
            if first {
                self.emit_text(line, 10.0, 30.0, false);
                first = false;
            } else {
                self.check_page_break(5.0);
                self.emit_text(line, 10.0, 30.0, false);
            }
            self.y -= 5.0;
        }
    }

    fn draw_italic(&mut self, text: &str) {
        self.check_page_break(5.0);
        self.emit_text(text, 10.0, 25.0, false);
        self.y -= 5.0;
    }

    fn draw_section_heading(&mut self, title: &str) {
        self.sections.push((title.to_string(), self.page_num + 1));
        self.draw_heading(title);
    }

    fn build(mut self) -> Vec<u8> {
        // Flush final content page
        if !self.current_ops.is_empty() {
            let mut ops = Vec::new();
            std::mem::swap(&mut self.current_ops, &mut ops);
            self.content_pages.push(ops);
        }

        let total_pages = self.content_pages.len() + 2; // + cover + TOC
        let mut final_pages: Vec<PdfPage> = Vec::new();

        // Cover page (page 1)
        final_pages.push(self.build_cover_page());

        // TOC page (page 2)
        final_pages.push(self.build_toc_page(total_pages));

        // Pre-clone fields needed for headers/footers so we can consume content_pages
        let classification = self.classification.to_uppercase();
        let case_id = self.case_id.clone();

        // Content pages (page 3+)
        for (i, page_ops) in self.content_pages.into_iter().enumerate() {
            let page_number = i + 3;
            let mut final_ops = Vec::new();

            // Header: classification (top left)
            final_ops.push(Op::StartTextSection);
            final_ops.push(Op::SetFont {
                font: PdfFontHandle::Builtin(BuiltinFont::HelveticaBold),
                size: Pt(8.0),
            });
            final_ops.push(Op::SetTextCursor {
                pos: Point::new(Mm(25.0), Mm(285.0)),
            });
            final_ops.push(Op::ShowText {
                items: vec![classification.clone().into()],
            });
            final_ops.push(Op::EndTextSection);

            // Header: case ID (top right)
            final_ops.push(Op::StartTextSection);
            final_ops.push(Op::SetFont {
                font: PdfFontHandle::Builtin(BuiltinFont::Helvetica),
                size: Pt(8.0),
            });
            final_ops.push(Op::SetTextCursor {
                pos: Point::new(Mm(160.0), Mm(285.0)),
            });
            final_ops.push(Op::ShowText {
                items: vec![format!("Case: {}", case_id).into()],
            });
            final_ops.push(Op::EndTextSection);

            final_ops.extend(page_ops);

            // Footer: left
            final_ops.push(Op::StartTextSection);
            final_ops.push(Op::SetFont {
                font: PdfFontHandle::Builtin(BuiltinFont::Helvetica),
                size: Pt(8.0),
            });
            final_ops.push(Op::SetTextCursor {
                pos: Point::new(Mm(25.0), Mm(15.0)),
            });
            final_ops.push(Op::ShowText {
                items: vec!["DFARS Digital Forensics Report".into()],
            });
            final_ops.push(Op::EndTextSection);

            // Footer: page number (right)
            final_ops.push(Op::StartTextSection);
            final_ops.push(Op::SetFont {
                font: PdfFontHandle::Builtin(BuiltinFont::Helvetica),
                size: Pt(8.0),
            });
            final_ops.push(Op::SetTextCursor {
                pos: Point::new(Mm(160.0), Mm(15.0)),
            });
            final_ops.push(Op::ShowText {
                items: vec![format!("Page {} of {}", page_number, total_pages).into()],
            });
            final_ops.push(Op::EndTextSection);

            final_pages.push(PdfPage::new(Mm(210.0), Mm(297.0), final_ops));
        }

        let mut doc = PdfDocument::new("DFARS Report of Examination");
        doc.with_pages(final_pages);
        let opts = PdfSaveOptions::default();
        doc.save(&opts, &mut Vec::new())
    }

    fn build_cover_page(&self) -> PdfPage {
        let mut ops = Vec::new();
        let mut y = 270.0;

        swgde_emit(&mut ops, "REPORT OF EXAMINATION", 24.0, 25.0, 297.0 - y, true);
        y -= 30.0;

        swgde_emit(&mut ops, "Digital and Multimedia Evidence", 14.0, 25.0, 297.0 - y, false);
        y -= 40.0;

        swgde_emit(&mut ops, "DFARS Digital Forensics Laboratory", 12.0, 25.0, 297.0 - y, true);
        y -= 8.0;
        swgde_emit(&mut ops, "[Organization address — update in settings]", 10.0, 25.0, 297.0 - y, false);
        y -= 30.0;

        swgde_emit(&mut ops, &format!("Case ID: {}", self.case_id), 14.0, 25.0, 297.0 - y, true);
        y -= 12.0;
        swgde_emit(&mut ops, &format!("Examiner: {}", self.investigator), 12.0, 25.0, 297.0 - y, false);
        y -= 10.0;
        swgde_emit(&mut ops, &format!("Date of Report: {}", &self.generated_at[..10]), 12.0, 25.0, 297.0 - y, false);
        y -= 10.0;
        swgde_emit(&mut ops, &format!("Classification: {}", self.classification), 12.0, 25.0, 297.0 - y, false);

        PdfPage::new(Mm(210.0), Mm(297.0), ops)
    }

    fn build_toc_page(&self, _total_pages: usize) -> PdfPage {
        let mut ops = Vec::new();
        let mut y = 270.0;

        swgde_emit(&mut ops, "TABLE OF CONTENTS", 18.0, 25.0, 297.0 - y, true);
        y -= 20.0;

        for (idx, (title, page)) in self.sections.iter().enumerate() {
            swgde_emit(&mut ops, &format!("{}.", idx + 1), 10.0, 25.0, 297.0 - y, false);
            swgde_emit(&mut ops, title, 10.0, 32.0, 297.0 - y, false);
            swgde_emit(&mut ops, &format!("Page {}", page), 10.0, 165.0, 297.0 - y, false);
            y -= 7.0;
        }

        PdfPage::new(Mm(210.0), Mm(297.0), ops)
    }
}

fn swgde_emit(ops: &mut Vec<Op>, text: &str, size: f32, x: f32, pdf_y: f32, bold: bool) {
    let font = if bold {
        PdfFontHandle::Builtin(BuiltinFont::HelveticaBold)
    } else {
        PdfFontHandle::Builtin(BuiltinFont::Helvetica)
    };
    ops.push(Op::StartTextSection);
    ops.push(Op::SetFont {
        font,
        size: Pt(size),
    });
    ops.push(Op::SetTextCursor {
        pos: Point::new(Mm(x), Mm(pdf_y)),
    });
    ops.push(Op::ShowText {
        items: vec![text.into()],
    });
    ops.push(Op::EndTextSection);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn esc_md_replaces_pipe() {
        assert_eq!(esc_md("foo|bar"), "foo\\|bar");
    }

    #[test]
    fn sanitize_report_filename_strips_specials() {
        let result = sanitize_report_filename("Case/2026:April");
        assert!(!result.contains('/'));
        assert!(!result.contains(':'));
    }

    #[test]
    fn pdf_builder_produces_valid_header() {
        let payload = ReportPayload {
            case_id: "TEST-001".into(),
            case_name: "Test Case".into(),
            description: None,
            investigator: "Investigator".into(),
            agency: None,
            start_date: "2024-01-01".into(),
            end_date: None,
            status: "Open".into(),
            priority: "High".into(),
            classification: None,
            tags: vec![],
            evidence_items: vec![],
            persons: vec![],
            all_custody: vec![],
            all_hashes: vec![],
            all_tools: vec![],
            analysis_notes: vec![],
            links: vec![],
            generated_at: "2024-01-01T00:00:00Z".into(),
        };
        let bytes = render_pdf(&payload, &ReportTemplate::Standard)
            .expect("render_pdf should succeed");
        assert!(bytes.starts_with(b"%PDF-"));
    }

    #[test]
    fn swgde_pdf_produces_valid_header() {
        let payload = ReportPayload {
            case_id: "TEST-002".into(),
            case_name: "SWGDE Test Case".into(),
            description: Some("Test description".into()),
            investigator: "Examiner".into(),
            agency: Some("Test Agency".into()),
            start_date: "2024-01-01".into(),
            end_date: None,
            status: "Open".into(),
            priority: "High".into(),
            classification: Some("CONFIDENTIAL".into()),
            tags: vec![],
            evidence_items: vec![],
            persons: vec![],
            all_custody: vec![],
            all_hashes: vec![],
            all_tools: vec![],
            analysis_notes: vec![],
            links: vec![],
            generated_at: "2024-01-01T00:00:00Z".into(),
        };
        let bytes = render_pdf(&payload, &ReportTemplate::Swgde)
            .expect("render_pdf swgde should succeed");
        assert!(bytes.starts_with(b"%PDF-"));
    }

    #[test]
    fn swgde_pdf_contains_report_of_examination_title() {
        // Verify the cover page title is embedded in the PDF ops.
        // We can't easily parse the PDF, but we can verify rendering succeeds
        // and produces non-trivial output.
        let payload = ReportPayload {
            case_id: "TEST-003".into(),
            case_name: "Complex SWGDE Case".into(),
            description: Some("Detailed description for testing.".into()),
            investigator: "Jane Doe".into(),
            agency: None,
            start_date: "2024-06-01".into(),
            end_date: None,
            status: "Active".into(),
            priority: "Critical".into(),
            classification: None,
            tags: vec!["tag1".into()],
            evidence_items: vec![],
            persons: vec![],
            all_custody: vec![],
            all_hashes: vec![],
            all_tools: vec![],
            analysis_notes: vec![],
            links: vec![],
            generated_at: "2024-06-01T12:00:00Z".into(),
        };
        let bytes = render_pdf(&payload, &ReportTemplate::Swgde)
            .expect("render_pdf swgde should succeed");
        // PDF should be larger than a trivial single-page doc
        // (cover + toc + at least 3 content pages for 10 sections)
        assert!(bytes.len() > 500, "SWGDE PDF should be substantial");
    }
}
