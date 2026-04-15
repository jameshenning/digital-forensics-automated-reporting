/**
 * PersonCard — baseball-card / social-media layout for a person entity.
 *
 * Renders:
 *   1. Circular photo (128px on desktop, 96px on mobile) via convertFileSrc,
 *      or a fallback User icon when no photo is set
 *   2. Display name + role badge + organizational rank + employer
 *   3. Contact grid (email, phone) and identifier grid (username, DOB)
 *   4. Notes block (if present)
 *   5. OSINT findings block (reads metadata_json.osint_findings[] — empty
 *      until Agent Zero has been run)
 *   6. Action row: Run OSINT (stub — wired in PR6), Edit, Clear photo, Delete
 */

import React from "react";
import { convertFileSrc } from "@tauri-apps/api/core";
import {
  User,
  Mail,
  Phone,
  AtSign,
  Cake,
  Briefcase,
  Pencil,
  Trash2,
  ImageOff,
  Sparkles,
  Network,
} from "lucide-react";

import type { Entity } from "@/lib/bindings";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";

// ---------------------------------------------------------------------------
// OSINT findings shape — written by the ai_osint_person command into the
// entity's metadata_json field. We tolerate missing / malformed JSON.
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
    // ignore — metadata_json may hold other shapes from pre-OSINT data
  }
  return [];
}

// ---------------------------------------------------------------------------
// Subtype badge styling
// ---------------------------------------------------------------------------

function subtypeBadgeClass(subtype: string | null): string {
  switch (subtype) {
    case "suspect":
      return "bg-destructive/10 text-destructive border-destructive/30";
    case "victim":
      return "bg-amber-500/10 text-amber-700 dark:text-amber-400 border-amber-500/30";
    case "witness":
      return "bg-blue-500/10 text-blue-700 dark:text-blue-400 border-blue-500/30";
    case "investigator":
      return "bg-emerald-500/10 text-emerald-700 dark:text-emerald-400 border-emerald-500/30";
    case "poi":
      return "bg-purple-500/10 text-purple-700 dark:text-purple-400 border-purple-500/30";
    default:
      return "bg-muted text-muted-foreground border-border";
  }
}

// ---------------------------------------------------------------------------
// Props
// ---------------------------------------------------------------------------

interface PersonCardProps {
  person: Entity;
  onEdit: () => void;
  onDelete: () => void;
  onClearPhoto: () => void;
  onRunOsint: () => void;
  /** True when the OSINT mutation is in-flight for this person. */
  osintPending?: boolean;
}

// ---------------------------------------------------------------------------
// PersonCard
// ---------------------------------------------------------------------------

export function PersonCard({
  person,
  onEdit,
  onDelete,
  onClearPhoto,
  onRunOsint,
  osintPending = false,
}: PersonCardProps) {
  const findings = React.useMemo(
    () => parseOsintFindings(person.metadata_json),
    [person.metadata_json],
  );

  const photoSrc = React.useMemo(() => {
    if (!person.photo_path) return null;
    try {
      return convertFileSrc(person.photo_path);
    } catch {
      return null;
    }
  }, [person.photo_path]);

  return (
    <div className="rounded-lg border bg-card text-card-foreground shadow-sm overflow-hidden">
      {/* Top: photo + headline */}
      <div className="p-5">
        <div className="flex flex-col sm:flex-row sm:items-start gap-4">
          {/* Circular photo */}
          <div className="mx-auto sm:mx-0 h-24 w-24 sm:h-32 sm:w-32 rounded-full overflow-hidden bg-muted border-2 border-border flex items-center justify-center shrink-0">
            {photoSrc ? (
              <img
                src={photoSrc}
                alt={person.display_name}
                className="h-full w-full object-cover"
              />
            ) : (
              <User className="h-12 w-12 text-muted-foreground" />
            )}
          </div>

          {/* Headline + badges */}
          <div className="min-w-0 flex-1 text-center sm:text-left">
            <h3 className="text-lg font-semibold leading-tight">
              {person.display_name}
            </h3>
            <div className="mt-1.5 flex flex-wrap gap-1.5 justify-center sm:justify-start">
              {person.subtype && (
                <span
                  className={`inline-flex items-center rounded-full border px-2.5 py-0.5 text-xs font-medium ${subtypeBadgeClass(person.subtype)}`}
                >
                  {person.subtype}
                </span>
              )}
              {person.organizational_rank && (
                <Badge variant="secondary" className="text-xs">
                  {person.organizational_rank}
                </Badge>
              )}
              {person.employer && (
                <Badge variant="outline" className="text-xs">
                  <Briefcase className="h-3 w-3 mr-1" />
                  {person.employer}
                </Badge>
              )}
            </div>

            {/* Contact + identifier grid */}
            <div className="mt-3 grid grid-cols-1 sm:grid-cols-2 gap-x-4 gap-y-1.5 text-sm text-left">
              {person.email && (
                <div className="flex items-center gap-1.5 min-w-0">
                  <Mail className="h-3.5 w-3.5 text-muted-foreground shrink-0" />
                  <span className="truncate" title={person.email}>
                    {person.email}
                  </span>
                </div>
              )}
              {person.phone && (
                <div className="flex items-center gap-1.5 min-w-0">
                  <Phone className="h-3.5 w-3.5 text-muted-foreground shrink-0" />
                  <span className="truncate" title={person.phone}>
                    {person.phone}
                  </span>
                </div>
              )}
              {person.username && (
                <div className="flex items-center gap-1.5 min-w-0">
                  <AtSign className="h-3.5 w-3.5 text-muted-foreground shrink-0" />
                  <span className="font-mono truncate" title={person.username}>
                    {person.username}
                  </span>
                </div>
              )}
              {person.dob && (
                <div className="flex items-center gap-1.5 min-w-0">
                  <Cake className="h-3.5 w-3.5 text-muted-foreground shrink-0" />
                  <span>{person.dob}</span>
                </div>
              )}
            </div>
          </div>
        </div>
      </div>

      {/* Notes block */}
      {person.notes && (
        <div className="border-t px-5 py-3">
          <p className="text-xs font-semibold uppercase tracking-wide text-muted-foreground mb-1">
            Notes
          </p>
          <p className="text-sm whitespace-pre-wrap leading-relaxed">
            {person.notes}
          </p>
        </div>
      )}

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
          <Sparkles className="h-4 w-4 mr-1.5" />
          {osintPending ? "Running OSINT…" : "Run OSINT"}
        </Button>
        <Button size="sm" variant="outline" onClick={onEdit}>
          <Pencil className="h-4 w-4 mr-1.5" />
          Edit
        </Button>
        {person.photo_path && (
          <Button size="sm" variant="ghost" onClick={onClearPhoto}>
            <ImageOff className="h-4 w-4 mr-1.5" />
            Clear photo
          </Button>
        )}
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
