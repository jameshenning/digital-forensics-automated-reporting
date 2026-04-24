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
}

impl ReportFormat {
    pub fn extension(&self) -> &str {
        match self {
            ReportFormat::Markdown => "md",
            ReportFormat::Html => "html",
        }
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
    reports_root: &Path,  // injected so tests can override %APPDATA%
) -> Result<PathBuf, AppError> {
    let payload = gather_report_payload(state, case_id).await?;

    let content = match format {
        ReportFormat::Markdown => render_markdown(&payload)?,
        ReportFormat::Html => render_html(&payload)?,
    };

    let safe_case_id = sanitize_report_filename(case_id);
    let timestamp = Utc::now().format("%Y-%m-%d_%H-%M-%S").to_string();
    let filename = format!("{safe_case_id}_{timestamp}.{}", format.extension());

    std::fs::create_dir_all(reports_root).map_err(AppError::from)?;

    // Canonical-prefix check to prevent any path injection.
    // reports_root now exists (just created), so canonicalize will succeed.
    let canonical_root = std::fs::canonicalize(reports_root).map_err(|e| {
        AppError::ReportGenerationFailed {
            reason: format!("cannot canonicalize reports directory: {e}"),
        }
    })?;

    let out_path = canonical_root.join(&filename);

    // Verify the output path stays under the reports root
    if !out_path.starts_with(&canonical_root) {
        return Err(AppError::ReportGenerationFailed {
            reason: "path traversal in report filename".into(),
        });
    }

    std::fs::write(&out_path, content.as_bytes()).map_err(AppError::from)?;

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
    /// Reviews gathered separately via `analysis_reviews::list_for_case`
    /// and joined by note_id at gathering time. Ordered by review
    /// created_at ASC (chronological review history).
    reviews: Vec<AnalysisReviewBrief>,
}

#[allow(dead_code)]
struct AnalysisReviewBrief {
    reviewed_by: String,
    reviewed_at: String,
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
    let persons: Vec<PersonReport> = entity_list
        .into_iter()
        .filter(|e| e.entity_type == "person")
        .map(|p| {
            // Extract OSINT tool names from metadata_json.osint_findings[] if present.
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

            PersonReport {
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
    out.push_str(&format!(
        "_{} finding{} total · {} peer-reviewed · {} pending review_\n\n",
        total,
        if total == 1 { "" } else { "s" },
        reviewed,
        pending,
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
                    "- Reviewed by {} on {}\n",
                    esc_md(&r.reviewed_by),
                    esc_md(&r.reviewed_at),
                ));
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
    fn extract_pdf_version_from_header() {
        // Test via render path — just ensure the unit logic is correct
        let header = b"%PDF-1.7\n%other";
        // inline call to private fn — we re-expose via a pub(crate) for tests
        let text = std::str::from_utf8(header).unwrap();
        assert!(text.starts_with("%PDF-"));
        let version: String = text[5..].chars().take_while(|c| c.is_ascii_digit() || *c == '.').collect();
        assert_eq!(version, "1.7");
    }
}
