/**
 * ToolCard — narrative card for a single tool_usage row.
 *
 * Extracted from tools-panel.tsx so it can be shared between:
 *   1. Case-wide Tools panel (tools with evidence_id = null — OSINT runs,
 *      case-level forensics)
 *   2. Per-evidence Tools panel (tools with a specific evidence_id —
 *      rendered inline under each evidence item in the Evidence tab)
 *
 * Renders six sections:
 *   1. About the tool (from forensic-tools KB)
 *   2. What it was used for in this case (user-recorded purpose + command)
 *   3. **Reproduce step-by-step** (collapsible — KB env_setup + steps +
 *      verification with placeholder substitution, then operator notes,
 *      then a Copy as Markdown button)
 *   4. What this tool typically finds (KB bullets)
 *   5. Why it matters (KB)
 *   6. Investigation chain — "consumes from" / "feeds into" resolved
 *      against the current case's tool list
 */

import React from "react";
import {
  Wrench,
  Terminal,
  ArrowDownCircle,
  ArrowUpCircle,
  Info,
  ChevronDown,
  ChevronRight,
  Copy,
  CopyCheck,
  Repeat,
  AlertTriangle,
} from "lucide-react";

import type { ToolUsage } from "@/lib/bindings";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import {
  lookupTool,
  findDependentsInCase,
  findPrerequisitesInCase,
  CATEGORY_LABEL,
  type ForensicTool,
} from "@/lib/forensic-tools";

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function fmtDatetime(iso: string | null): string {
  if (!iso) return "—";
  const d = new Date(iso.replace(" ", "T"));
  if (isNaN(d.getTime())) return iso;
  return d.toLocaleString(undefined, {
    year: "numeric",
    month: "short",
    day: "numeric",
    hour: "2-digit",
    minute: "2-digit",
  });
}

// ---------------------------------------------------------------------------
// Reproduction-step placeholder substitution
// ---------------------------------------------------------------------------

const PLACEHOLDER_PATTERN = /\{(input_file|output_file|command|version|operator|input_sha256|output_sha256)\}/g;

/**
 * Substitute KB-step placeholders with the actual tool_usage values.
 * Missing values are rendered as `⚠ NOT RECORDED` so a reviewer can see
 * which fields the original examiner failed to capture.
 */
function substitutePlaceholders(template: string, usage: ToolUsage): string {
  return template.replace(PLACEHOLDER_PATTERN, (_match, key: string) => {
    switch (key) {
      case "input_file":
        return usage.input_file ?? "⚠ NOT RECORDED";
      case "output_file":
        return usage.output_file ?? "⚠ NOT RECORDED";
      case "command":
        return usage.command_used ?? "⚠ NOT RECORDED";
      case "version":
        return usage.version ?? "⚠ NOT RECORDED";
      case "operator":
        return usage.operator;
      case "input_sha256":
        return usage.input_sha256 ?? "⚠ NOT RECORDED";
      case "output_sha256":
        return usage.output_sha256 ?? "⚠ NOT RECORDED";
      default:
        return _match;
    }
  });
}

/**
 * Build a complete Markdown reproduction block for a tool_usage row,
 * combining the KB's curated environment_setup / reproduction_steps /
 * verification_steps with the operator's recorded environment_notes and
 * reproduction_notes. Used by both the in-card preview and the "Copy as
 * Markdown" button.
 */
function buildReproductionMarkdown(
  usage: ToolUsage,
  kb: ForensicTool | null,
): string {
  const lines: string[] = [];
  lines.push(`### Reproduction — ${kb?.name ?? usage.tool_name}`);
  lines.push("");

  // Tool fingerprint
  lines.push("**Tool fingerprint**");
  lines.push("");
  lines.push(`- Tool: \`${kb?.name ?? usage.tool_name}\``);
  if (usage.version) lines.push(`- Version: \`${usage.version}\``);
  lines.push(`- Operator: ${usage.operator}`);
  lines.push(`- Executed: ${fmtDatetime(usage.execution_datetime)}`);
  lines.push("");

  // Environment setup (KB)
  if (kb && kb.environmentSetup.length > 0) {
    lines.push("**Environment setup (one-time)**");
    lines.push("");
    for (const cmd of kb.environmentSetup) {
      lines.push(`- ${cmd}`);
    }
    lines.push("");
  }

  // Operator's environment notes
  if (usage.environment_notes) {
    lines.push("**Environment used by the original examiner**");
    lines.push("");
    lines.push(usage.environment_notes);
    lines.push("");
  }

  // Input verification
  if (usage.input_file || usage.input_sha256) {
    lines.push("**Input file verification**");
    lines.push("");
    if (usage.input_file) lines.push(`- Path: \`${usage.input_file}\``);
    if (usage.input_sha256)
      lines.push(`- SHA-256: \`${usage.input_sha256}\``);
    lines.push(
      `- Verify before proceeding: \`sha256sum ${usage.input_file ?? "<file>"}\` should equal \`${usage.input_sha256 ?? "<recorded hash>"}\`.`,
    );
    lines.push("");
  }

  // Reproduction steps (KB, with substitution)
  if (kb && kb.reproductionSteps.length > 0) {
    lines.push("**Step-by-step reproduction**");
    lines.push("");
    for (const step of kb.reproductionSteps) {
      lines.push(substitutePlaceholders(step, usage));
      lines.push("");
    }
  } else {
    lines.push("**Step-by-step reproduction**");
    lines.push("");
    lines.push(
      "_This tool is not in the curated knowledge base. Use the operator's recorded command and notes below as the reproduction guide._",
    );
    lines.push("");
    if (usage.command_used) {
      lines.push("```");
      lines.push(usage.command_used);
      lines.push("```");
      lines.push("");
    }
  }

  // Verification (KB)
  if (kb && kb.verificationSteps.length > 0) {
    lines.push("**Verification**");
    lines.push("");
    for (const step of kb.verificationSteps) {
      lines.push(`- ${substitutePlaceholders(step, usage)}`);
    }
    lines.push("");
  } else if (usage.output_sha256) {
    lines.push("**Verification**");
    lines.push("");
    lines.push(
      `- Hash the output file: \`sha256sum ${usage.output_file ?? "<output>"}\` should equal \`${usage.output_sha256}\`.`,
    );
    lines.push("");
  }

  // Operator's reproduction notes
  if (usage.reproduction_notes) {
    lines.push("**Notes from the original examiner**");
    lines.push("");
    lines.push(usage.reproduction_notes);
    lines.push("");
  }

  return lines.join("\n").trimEnd() + "\n";
}

// ---------------------------------------------------------------------------
// Props
// ---------------------------------------------------------------------------

export interface ToolCardProps {
  usage: ToolUsage;
  /** All tool_name strings present in this case (for dependency chaining). */
  caseToolNames: string[];
  /**
   * When true, suppresses the "case-wide" / evidence-ID badge in the header.
   * Useful when the card is already rendered under an evidence item and
   * the grouping is obvious.
   */
  hideScopeBadge?: boolean;
}

// ---------------------------------------------------------------------------
// ToolCard
// ---------------------------------------------------------------------------

export function ToolCard({
  usage,
  caseToolNames,
  hideScopeBadge = false,
}: ToolCardProps) {
  const kb: ForensicTool | null = lookupTool(usage.tool_name);
  const dependents = kb ? findDependentsInCase(kb, caseToolNames) : [];
  const prerequisites = kb ? findPrerequisitesInCase(kb, caseToolNames) : [];

  // Reproduction section state — collapsed by default per the UX spec.
  const [reproOpen, setReproOpen] = React.useState(false);
  const [copied, setCopied] = React.useState(false);

  // Whether we have ANY reproduction content to show. If neither the KB nor
  // the operator filled in anything, we hide the toggle entirely.
  const hasKbRepro =
    !!kb &&
    (kb.environmentSetup.length > 0 ||
      kb.reproductionSteps.length > 0 ||
      kb.verificationSteps.length > 0);
  const hasOperatorRepro =
    !!usage.input_sha256 ||
    !!usage.output_sha256 ||
    !!usage.environment_notes ||
    !!usage.reproduction_notes;
  const showReproSection = hasKbRepro || hasOperatorRepro;

  async function handleCopyMarkdown() {
    const md = buildReproductionMarkdown(usage, kb);
    try {
      await navigator.clipboard.writeText(md);
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    } catch {
      // Clipboard API unavailable — silently swallow. The Markdown report
      // export still includes the same content.
    }
  }

  return (
    <div className="rounded-lg border bg-card text-card-foreground shadow-sm">
      {/* Header */}
      <div className="border-b px-5 py-4">
        <div className="flex flex-wrap items-start justify-between gap-3">
          <div className="min-w-0">
            <div className="flex items-center gap-2 flex-wrap">
              <Wrench className="h-5 w-5 text-primary shrink-0" />
              <h3 className="text-base font-semibold leading-tight">
                {kb?.name ?? usage.tool_name}
              </h3>
              {usage.version && (
                <span className="font-mono text-xs text-muted-foreground">
                  v{usage.version}
                </span>
              )}
              {kb && (
                <Badge variant="secondary" className="text-xs">
                  {CATEGORY_LABEL[kb.category]}
                </Badge>
              )}
              {!hideScopeBadge && usage.evidence_id && (
                <Badge variant="outline" className="text-xs font-mono">
                  {usage.evidence_id}
                </Badge>
              )}
              {!hideScopeBadge && !usage.evidence_id && (
                <Badge variant="outline" className="text-xs">
                  case-wide
                </Badge>
              )}
            </div>
            <p className="text-xs text-muted-foreground mt-1">
              Run by <span className="font-medium">{usage.operator}</span>
              {" · "}
              {fmtDatetime(usage.execution_datetime)}
            </p>
          </div>
        </div>
      </div>

      {/* Body */}
      <div className="p-5 space-y-4 text-sm">
        {/* About the tool */}
        <section>
          <h4 className="text-xs font-semibold uppercase tracking-wide text-muted-foreground mb-1.5">
            About the tool
          </h4>
          {kb ? (
            <p className="leading-relaxed">{kb.description}</p>
          ) : (
            <p className="text-muted-foreground italic leading-relaxed">
              {usage.tool_name} is not in the curated forensic-tools knowledge
              base. See the operator's recorded purpose and command below for
              case-specific context.
            </p>
          )}
          {kb && kb.reference && (
            <a
              href={kb.reference}
              target="_blank"
              rel="noreferrer noopener"
              className="text-xs text-primary hover:underline mt-1 inline-block"
            >
              Reference: {kb.reference}
            </a>
          )}
        </section>

        {/* What it was used for in this case */}
        <section>
          <h4 className="text-xs font-semibold uppercase tracking-wide text-muted-foreground mb-1.5">
            What it was used for in this case
          </h4>
          <p className="leading-relaxed">{usage.purpose}</p>
          {usage.command_used && (
            <div className="mt-2 flex items-start gap-2">
              <Terminal className="h-3.5 w-3.5 mt-1 text-muted-foreground shrink-0" />
              <code className="flex-1 font-mono text-xs bg-muted/50 rounded px-2 py-1 break-all">
                {usage.command_used}
              </code>
            </div>
          )}
          {(usage.input_file || usage.output_file) && (
            <div className="mt-2 grid gap-1 text-xs">
              {usage.input_file && (
                <div className="flex items-center gap-2">
                  <ArrowDownCircle className="h-3.5 w-3.5 text-muted-foreground" />
                  <span className="text-muted-foreground">Input:</span>
                  <code className="font-mono truncate" title={usage.input_file}>
                    {usage.input_file}
                  </code>
                </div>
              )}
              {usage.output_file && (
                <div className="flex items-center gap-2">
                  <ArrowUpCircle className="h-3.5 w-3.5 text-muted-foreground" />
                  <span className="text-muted-foreground">Output:</span>
                  <code className="font-mono truncate" title={usage.output_file}>
                    {usage.output_file}
                  </code>
                </div>
              )}
            </div>
          )}
        </section>

        {/* Reproduce step-by-step (collapsible) */}
        {showReproSection && (
          <section className="rounded-md border border-primary/20 bg-primary/5">
            <button
              type="button"
              onClick={() => setReproOpen(!reproOpen)}
              className="flex w-full items-center gap-2 px-3 py-2 text-left hover:bg-primary/10 transition-colors"
              aria-expanded={reproOpen}
            >
              {reproOpen ? (
                <ChevronDown className="h-4 w-4 text-primary shrink-0" />
              ) : (
                <ChevronRight className="h-4 w-4 text-primary shrink-0" />
              )}
              <Repeat className="h-4 w-4 text-primary shrink-0" />
              <span className="text-xs font-semibold uppercase tracking-wide text-primary">
                Reproduce step-by-step
              </span>
              {!hasKbRepro && (
                <Badge variant="outline" className="text-xs ml-auto">
                  Custom tool — operator notes only
                </Badge>
              )}
            </button>

            {reproOpen && (
              <div className="border-t border-primary/20 px-4 py-3 space-y-4 text-sm">
                {/* Environment setup (KB) */}
                {kb && kb.environmentSetup.length > 0 && (
                  <div>
                    <h5 className="text-xs font-semibold text-muted-foreground uppercase tracking-wide mb-1.5">
                      Environment setup (one-time)
                    </h5>
                    <ul className="space-y-1">
                      {kb.environmentSetup.map((cmd, i) => (
                        <li key={i} className="font-mono text-xs bg-muted/50 rounded px-2 py-1">
                          {cmd}
                        </li>
                      ))}
                    </ul>
                  </div>
                )}

                {/* Operator's environment notes */}
                {usage.environment_notes && (
                  <div>
                    <h5 className="text-xs font-semibold text-muted-foreground uppercase tracking-wide mb-1.5">
                      Original examiner's environment
                    </h5>
                    <p className="text-xs leading-relaxed whitespace-pre-wrap">
                      {usage.environment_notes}
                    </p>
                  </div>
                )}

                {/* Input file verification */}
                {(usage.input_file || usage.input_sha256) && (
                  <div>
                    <h5 className="text-xs font-semibold text-muted-foreground uppercase tracking-wide mb-1.5">
                      Verify input file before proceeding
                    </h5>
                    <div className="text-xs space-y-1">
                      {usage.input_file && (
                        <div>
                          Path:{" "}
                          <code className="font-mono bg-muted/50 rounded px-1.5 py-0.5">
                            {usage.input_file}
                          </code>
                        </div>
                      )}
                      {usage.input_sha256 ? (
                        <div className="break-all">
                          SHA-256:{" "}
                          <code className="font-mono bg-muted/50 rounded px-1.5 py-0.5">
                            {usage.input_sha256}
                          </code>
                        </div>
                      ) : (
                        <div className="text-destructive flex items-center gap-1.5">
                          <AlertTriangle className="h-3.5 w-3.5" />
                          <span>
                            Original examiner did not record an input SHA-256
                            — reproducibility is weakened.
                          </span>
                        </div>
                      )}
                    </div>
                  </div>
                )}

                {/* Reproduction steps (KB with substitution) */}
                {kb && kb.reproductionSteps.length > 0 ? (
                  <div>
                    <h5 className="text-xs font-semibold text-muted-foreground uppercase tracking-wide mb-1.5">
                      Steps
                    </h5>
                    <ol className="space-y-2">
                      {kb.reproductionSteps.map((step, i) => (
                        <li
                          key={i}
                          className="text-xs leading-relaxed whitespace-pre-wrap"
                        >
                          {substitutePlaceholders(step, usage)}
                        </li>
                      ))}
                    </ol>
                  </div>
                ) : (
                  <div className="text-xs text-muted-foreground italic">
                    No curated reproduction steps for this tool — see the
                    operator's recorded command above and notes below.
                  </div>
                )}

                {/* Verification (KB) */}
                {kb && kb.verificationSteps.length > 0 && (
                  <div>
                    <h5 className="text-xs font-semibold text-muted-foreground uppercase tracking-wide mb-1.5">
                      Verification
                    </h5>
                    <ul className="space-y-1">
                      {kb.verificationSteps.map((step, i) => (
                        <li
                          key={i}
                          className="text-xs leading-relaxed flex gap-2"
                        >
                          <span className="text-muted-foreground shrink-0">•</span>
                          <span>{substitutePlaceholders(step, usage)}</span>
                        </li>
                      ))}
                    </ul>
                  </div>
                )}

                {/* Operator's reproduction notes */}
                {usage.reproduction_notes && (
                  <div>
                    <h5 className="text-xs font-semibold text-muted-foreground uppercase tracking-wide mb-1.5">
                      Notes from the original examiner
                    </h5>
                    <p className="text-xs leading-relaxed whitespace-pre-wrap">
                      {usage.reproduction_notes}
                    </p>
                  </div>
                )}

                {/* Copy as Markdown */}
                <div className="flex justify-end pt-1 border-t border-primary/20">
                  <Button
                    type="button"
                    size="sm"
                    variant="outline"
                    onClick={() => void handleCopyMarkdown()}
                  >
                    {copied ? (
                      <>
                        <CopyCheck className="h-4 w-4 mr-1.5" />
                        Copied
                      </>
                    ) : (
                      <>
                        <Copy className="h-4 w-4 mr-1.5" />
                        Copy as Markdown
                      </>
                    )}
                  </Button>
                </div>
              </div>
            )}
          </section>
        )}

        {/* Typical findings */}
        {kb && kb.typicalFindings.length > 0 && (
          <section>
            <h4 className="text-xs font-semibold uppercase tracking-wide text-muted-foreground mb-1.5">
              What this tool typically finds
            </h4>
            <ul className="space-y-1">
              {kb.typicalFindings.map((f, i) => (
                <li key={i} className="flex gap-2 leading-relaxed">
                  <span className="text-muted-foreground shrink-0">•</span>
                  <span>{f}</span>
                </li>
              ))}
            </ul>
          </section>
        )}

        {/* Why it matters */}
        {kb && (
          <section>
            <h4 className="text-xs font-semibold uppercase tracking-wide text-muted-foreground mb-1.5">
              Why it matters
            </h4>
            <p className="leading-relaxed">{kb.whyItMatters}</p>
          </section>
        )}

        {/* Investigation chain */}
        {(prerequisites.length > 0 || dependents.length > 0) && (
          <section className="border-t pt-3">
            <h4 className="text-xs font-semibold uppercase tracking-wide text-muted-foreground mb-2 flex items-center gap-1.5">
              <Info className="h-3.5 w-3.5" />
              Investigation chain in this case
            </h4>
            <div className="space-y-2 text-xs">
              {prerequisites.length > 0 && (
                <div className="flex items-start gap-2 flex-wrap">
                  <span className="text-muted-foreground shrink-0">
                    Consumes output from:
                  </span>
                  <div className="flex flex-wrap gap-1.5">
                    {prerequisites.map((p) => (
                      <Badge key={p.name} variant="secondary" className="text-xs">
                        {p.tool?.name ?? p.name}
                      </Badge>
                    ))}
                  </div>
                </div>
              )}
              {dependents.length > 0 && (
                <div className="flex items-start gap-2 flex-wrap">
                  <span className="text-muted-foreground shrink-0">
                    Feeds into:
                  </span>
                  <div className="flex flex-wrap gap-1.5">
                    {dependents.map((d) => (
                      <Badge key={d.name} variant="secondary" className="text-xs">
                        {d.tool?.name ?? d.name}
                      </Badge>
                    ))}
                  </div>
                </div>
              )}
            </div>
          </section>
        )}
      </div>
    </div>
  );
}
