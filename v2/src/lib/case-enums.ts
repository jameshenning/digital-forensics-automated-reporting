/**
 * Case status and priority enums.
 *
 * These must match the Rust backend allowlists exactly:
 *   CaseStatus  → Active | Closed | Pending | Archived
 *   CasePriority → Low | Medium | High | Critical
 *
 * Used in <Select> components and Zod enum schemas.  Single source of truth
 * on the frontend — do not inline these string arrays anywhere else.
 */

import type { CasePriority, CaseStatus } from "@/lib/bindings";

export const CASE_STATUSES: readonly CaseStatus[] = [
  "Active",
  "Pending",
  "Closed",
  "Archived",
] as const;

export const CASE_PRIORITIES: readonly CasePriority[] = [
  "Critical",
  "High",
  "Medium",
  "Low",
] as const;

// ---------------------------------------------------------------------------
// Badge variant helpers — maps enum values to Tailwind class strings
// ---------------------------------------------------------------------------

/** Returns a Tailwind className string for the status badge. */
export function statusBadgeClass(status: CaseStatus): string {
  switch (status) {
    case "Active":
      return "bg-green-600/20 text-green-400 border-green-600/30";
    case "Pending":
      return "bg-yellow-600/20 text-yellow-400 border-yellow-600/30";
    case "Closed":
      return "bg-slate-600/20 text-slate-400 border-slate-600/30";
    case "Archived":
      return "bg-zinc-600/20 text-zinc-400 border-zinc-600/30";
  }
}

/** Returns a Tailwind className string for the priority badge. */
export function priorityBadgeClass(priority: CasePriority): string {
  switch (priority) {
    case "Critical":
      return "bg-red-600/20 text-red-400 border-red-600/30";
    case "High":
      return "bg-orange-600/20 text-orange-400 border-orange-600/30";
    case "Medium":
      return "bg-blue-600/20 text-blue-400 border-blue-600/30";
    case "Low":
      return "bg-slate-600/20 text-slate-400 border-slate-600/30";
  }
}

// ---------------------------------------------------------------------------
// Tag normalization — matches backend normalization (trim, lowercase, dedupe)
// ---------------------------------------------------------------------------

/**
 * Parse and normalize a comma-separated tag string into a deduplicated,
 * sorted array of lowercase tag strings.  Empty segments are dropped.
 */
export function normalizeTags(raw: string): string[] {
  const seen = new Set<string>();
  const result: string[] = [];
  for (const part of raw.split(",")) {
    const tag = part.trim().toLowerCase();
    if (tag && !seen.has(tag)) {
      seen.add(tag);
      result.push(tag);
    }
  }
  result.sort();
  return result;
}
