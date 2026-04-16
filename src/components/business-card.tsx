/**
 * BusinessCard — display card for a business entity.
 *
 * Renders:
 *   1. Building2 icon placeholder (128px circle) — no photo support for businesses
 *   2. Display name + Industry badge (organizational_rank)
 *   3. Contact grid: domain, email, phone from the identifier list
 *   4. Notes block (if present)
 *   5. Business identifiers (read-only via BusinessIdentifierEditor)
 *   6. OSINT findings block (reads metadata_json.osint_findings[])
 *   7. Action row: Run OSINT (Pass 1 placeholder toast), Edit, Delete
 */

import React from "react";
import { Building2, Globe, Mail, Phone, Pencil, Trash2, Sparkles, Network, Loader2 } from "lucide-react";
import { useQuery } from "@tanstack/react-query";

import type { Entity } from "@/lib/bindings";
import { businessIdentifierList } from "@/lib/bindings";
import { getToken } from "@/lib/session";
import { queryKeys } from "@/lib/query";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { BusinessIdentifierEditor } from "@/components/business-identifier-editor";

// ---------------------------------------------------------------------------
// OSINT findings shape — written by the AI OSINT command into entity.metadata_json.
// ---------------------------------------------------------------------------

interface OsintFinding {
  tool_name: string;
  findings_summary: string;
  execution_datetime?: string;
}

function parseOsintFindings(metadataJson: string | null): OsintFinding[] {
  if (!metadataJson) return [];
  try {
    const parsed = JSON.parse(metadataJson);
    if (parsed && typeof parsed === "object" && Array.isArray(parsed.osint_findings)) {
      return parsed.osint_findings.filter(
        (f: unknown): f is OsintFinding =>
          typeof f === "object" &&
          f !== null &&
          typeof (f as OsintFinding).tool_name === "string" &&
          typeof (f as OsintFinding).findings_summary === "string",
      );
    }
  } catch {
    // ignore — metadata_json may hold other shapes
  }
  return [];
}

// ---------------------------------------------------------------------------
// Props
// ---------------------------------------------------------------------------

interface BusinessCardProps {
  business: Entity;
  onEdit: () => void;
  onDelete: () => void;
  onRunOsint: () => void;
  osintPending?: boolean;
}

// ---------------------------------------------------------------------------
// BusinessCard
// ---------------------------------------------------------------------------

export function BusinessCard({ business, onEdit, onDelete, onRunOsint, osintPending = false }: BusinessCardProps) {
  const token = getToken() ?? "";

  const findings = React.useMemo(
    () => parseOsintFindings(business.metadata_json),
    [business.metadata_json],
  );

  // Fetch identifiers to extract domain, email, phone for the contact grid.
  const { data: identifiers } = useQuery({
    queryKey: queryKeys.businessIdentifiers.listForEntity(business.entity_id),
    queryFn: () => businessIdentifierList({ token, entity_id: business.entity_id }),
    enabled: !!token,
  });

  const firstDomain = identifiers?.find((i) => i.kind === "domain")?.value ?? null;
  const firstEmail = identifiers?.find((i) => i.kind === "email")?.value ?? null;
  const firstPhone = identifiers?.find((i) => i.kind === "phone")?.value ?? null;

  return (
    <div className="rounded-lg border bg-card text-card-foreground shadow-sm overflow-hidden">
      {/* Top: icon + headline */}
      <div className="p-5">
        <div className="flex flex-col sm:flex-row sm:items-start gap-4">
          {/* Building icon placeholder — no photo for businesses */}
          <div className="mx-auto sm:mx-0 h-24 w-24 sm:h-32 sm:w-32 rounded-full overflow-hidden bg-muted border-2 border-border flex items-center justify-center shrink-0">
            <Building2 className="h-12 w-12 text-muted-foreground" />
          </div>

          {/* Headline + badges */}
          <div className="min-w-0 flex-1 text-center sm:text-left">
            <h3 className="text-lg font-semibold leading-tight">
              {business.display_name}
            </h3>
            <div className="mt-1.5 flex flex-wrap gap-1.5 justify-center sm:justify-start">
              {business.organizational_rank && (
                <Badge variant="secondary" className="text-xs">
                  {business.organizational_rank}
                </Badge>
              )}
            </div>

            {/* Contact grid from identifier list */}
            <div className="mt-3 grid grid-cols-1 sm:grid-cols-2 gap-x-4 gap-y-1.5 text-sm text-left">
              {firstDomain && (
                <div className="flex items-center gap-1.5 min-w-0">
                  <Globe className="h-3.5 w-3.5 text-muted-foreground shrink-0" />
                  <span className="truncate" title={firstDomain}>
                    {firstDomain}
                  </span>
                </div>
              )}
              {firstEmail && (
                <div className="flex items-center gap-1.5 min-w-0">
                  <Mail className="h-3.5 w-3.5 text-muted-foreground shrink-0" />
                  <span className="truncate" title={firstEmail}>
                    {firstEmail}
                  </span>
                </div>
              )}
              {firstPhone && (
                <div className="flex items-center gap-1.5 min-w-0">
                  <Phone className="h-3.5 w-3.5 text-muted-foreground shrink-0" />
                  <span className="truncate" title={firstPhone}>
                    {firstPhone}
                  </span>
                </div>
              )}
            </div>
          </div>
        </div>
      </div>

      {/* Notes block */}
      {business.notes && (
        <div className="border-t px-5 py-3">
          <p className="text-xs font-semibold uppercase tracking-wide text-muted-foreground mb-1">
            Notes
          </p>
          <p className="text-sm whitespace-pre-wrap leading-relaxed">
            {business.notes}
          </p>
        </div>
      )}

      {/* Business identifiers (migration 0005) — rendered read-only */}
      <div className="border-t px-5 py-3">
        <BusinessIdentifierEditor entityId={business.entity_id} readOnly />
      </div>

      {/* OSINT findings block */}
      <div className="border-t px-5 py-3 bg-muted/20">
        <div className="flex items-center gap-1.5 mb-2">
          <Network className="h-3.5 w-3.5 text-muted-foreground" />
          <p className="text-xs font-semibold uppercase tracking-wide text-muted-foreground">
            OSINT findings (via Agent Zero)
          </p>
        </div>
        {findings.length === 0 ? (
          <p className="text-xs text-muted-foreground italic">
            No OSINT runs yet. Click <span className="font-medium">Run OSINT</span> to
            send known fields to Agent Zero for orchestrated Kali tool runs.
          </p>
        ) : (
          <ul className="space-y-1.5">
            {findings.map((f, i) => (
              <li key={i} className="flex gap-2 text-sm">
                <span className="text-muted-foreground shrink-0">▸</span>
                <div className="min-w-0 flex-1">
                  <span className="font-medium">{f.tool_name}</span>
                  <span className="text-muted-foreground"> — {f.findings_summary}</span>
                  {f.execution_datetime && (
                    <span className="text-xs text-muted-foreground block">
                      {f.execution_datetime}
                    </span>
                  )}
                </div>
              </li>
            ))}
          </ul>
        )}
      </div>

      {/* Action row */}
      <div className="border-t px-5 py-3 flex flex-wrap gap-2">
        <Button
          size="sm"
          variant="default"
          onClick={onRunOsint}
          disabled={osintPending}
        >
          {osintPending ? (
            <Loader2 className="h-4 w-4 mr-1.5 animate-spin" />
          ) : (
            <Sparkles className="h-4 w-4 mr-1.5" />
          )}
          {osintPending ? "Running OSINT…" : "Run OSINT"}
        </Button>
        <Button size="sm" variant="outline" onClick={onEdit}>
          <Pencil className="h-4 w-4 mr-1.5" />
          Edit
        </Button>
        <div className="ml-auto">
          <Button size="sm" variant="ghost" onClick={onDelete}>
            <Trash2 className="h-4 w-4 mr-1.5" />
            Delete
          </Button>
        </div>
      </div>
    </div>
  );
}
