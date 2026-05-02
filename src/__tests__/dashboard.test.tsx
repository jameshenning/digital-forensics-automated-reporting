/**
 * Tests for dashboard page helpers: StatsCards, compareCases, filter+sort pipeline.
 *
 * Does NOT mount the full DashboardPage because it is a TanStack Router route
 * component (depends on router context).  Instead we test the pure helpers and
 * a local replica of the filter/sort pipeline.
 */

import { describe, it, expect, vi } from "vitest";
import { render, screen } from "@testing-library/react";
import {
  StatsCards,
  compareCases,
  activityIcon,
  activityLabel,
  fmtActivityTime,
} from "@/routes/dashboard";
import type { CaseSummary } from "@/lib/bindings";
import { FolderPlus, Pencil, Trash2, Share2, CircleDot } from "lucide-react";

// ── Mock Tauri IPC before any import that touches bindings.ts ────────────────
vi.mock("@tauri-apps/api/core", () => ({ invoke: vi.fn() }));

const MOCK_CASES: CaseSummary[] = [
  {
    case_id: "CASE-2026-0001",
    case_name: "Alpha Investigation",
    investigator: "jsmith",
    start_date: "2026-01-15",
    status: "Active",
    priority: "High",
    evidence_count: 3,
    created_at: "2026-01-15T09:00:00Z",
  },
  {
    case_id: "CASE-2026-0002",
    case_name: "Beta Device",
    investigator: "jdoe",
    start_date: "2026-02-10",
    status: "Pending",
    priority: "Medium",
    evidence_count: 0,
    created_at: "2026-02-10T14:30:00Z",
  },
  {
    case_id: "CASE-2026-0003",
    case_name: "Critical Breach",
    investigator: "admin",
    start_date: "2026-03-01",
    status: "Active",
    priority: "Critical",
    evidence_count: 12,
    created_at: "2026-03-01T08:00:00Z",
  },
  {
    case_id: "CASE-2026-0004",
    case_name: "Archived Review",
    investigator: "jsmith",
    start_date: "2025-12-01",
    status: "Archived",
    priority: "Low",
    evidence_count: 1,
    created_at: "2025-12-01T10:00:00Z",
  },
];

// ── StatsCards ───────────────────────────────────────────────────────────────

describe("StatsCards", () => {
  it("renders total cases count", () => {
    render(<StatsCards cases={MOCK_CASES} />);
    expect(screen.getByText("4")).toBeDefined();
    expect(screen.getByText("Total Cases")).toBeDefined();
  });

  it("renders active cases count", () => {
    render(<StatsCards cases={MOCK_CASES} />);
    expect(screen.getByText("2")).toBeDefined(); // Active
    expect(screen.getByText("Active")).toBeDefined();
  });

  it("renders critical priority count", () => {
    render(<StatsCards cases={MOCK_CASES} />);
    expect(screen.getByText("1")).toBeDefined(); // Critical
    expect(screen.getByText("Critical")).toBeDefined();
  });

  it("renders total evidence items", () => {
    render(<StatsCards cases={MOCK_CASES} />);
    expect(screen.getByText("16")).toBeDefined(); // 3 + 0 + 12 + 1
    expect(screen.getByText("Evidence Items")).toBeDefined();
  });

  it("handles empty cases array", () => {
    render(<StatsCards cases={[]} />);
    expect(screen.getAllByText("0")).toHaveLength(4);
  });
});

// ── compareCases ─────────────────────────────────────────────────────────────

describe("compareCases", () => {
  it("sorts by case_name ascending", () => {
    const sorted = [...MOCK_CASES].sort((a, b) =>
      compareCases(a, b, "case_name", "asc")
    );
    expect(sorted[0].case_name).toBe("Alpha Investigation");
    expect(sorted[3].case_name).toBe("Critical Breach");
  });

  it("sorts by case_name descending", () => {
    const sorted = [...MOCK_CASES].sort((a, b) =>
      compareCases(a, b, "case_name", "desc")
    );
    expect(sorted[0].case_name).toBe("Critical Breach");
    expect(sorted[3].case_name).toBe("Alpha Investigation");
  });

  it("sorts by start_date ascending", () => {
    const sorted = [...MOCK_CASES].sort((a, b) =>
      compareCases(a, b, "start_date", "asc")
    );
    expect(sorted[0].case_id).toBe("CASE-2026-0004"); // Dec 2025
    expect(sorted[3].case_id).toBe("CASE-2026-0003"); // Mar 2026
  });

  it("sorts by start_date descending (default)", () => {
    const sorted = [...MOCK_CASES].sort((a, b) =>
      compareCases(a, b, "start_date", "desc")
    );
    expect(sorted[0].case_id).toBe("CASE-2026-0003"); // Mar 2026
    expect(sorted[3].case_id).toBe("CASE-2026-0004"); // Dec 2025
  });

  it("sorts by priority with custom weight ascending", () => {
    const sorted = [...MOCK_CASES].sort((a, b) =>
      compareCases(a, b, "priority", "asc")
    );
    expect(sorted[0].priority).toBe("Low");
    expect(sorted[1].priority).toBe("Medium");
    expect(sorted[2].priority).toBe("High");
    expect(sorted[3].priority).toBe("Critical");
  });

  it("sorts by priority descending", () => {
    const sorted = [...MOCK_CASES].sort((a, b) =>
      compareCases(a, b, "priority", "desc")
    );
    expect(sorted[0].priority).toBe("Critical");
    expect(sorted[3].priority).toBe("Low");
  });

  it("sorts by evidence_count ascending", () => {
    const sorted = [...MOCK_CASES].sort((a, b) =>
      compareCases(a, b, "evidence_count", "asc")
    );
    expect(sorted[0].evidence_count).toBe(0);
    expect(sorted[3].evidence_count).toBe(12);
  });

  it("sorts by investigator ascending", () => {
    const sorted = [...MOCK_CASES].sort((a, b) =>
      compareCases(a, b, "investigator", "asc")
    );
    expect(sorted[0].investigator).toBe("admin");
    expect(sorted[3].investigator).toBe("jsmith");
  });

  it("sorts by status ascending", () => {
    const sorted = [...MOCK_CASES].sort((a, b) =>
      compareCases(a, b, "status", "asc")
    );
    expect(sorted[0].status).toBe("Active");
    expect(sorted[3].status).toBe("Pending");
  });

  it("sorts by created_at ascending", () => {
    const sorted = [...MOCK_CASES].sort((a, b) =>
      compareCases(a, b, "created_at", "asc")
    );
    expect(sorted[0].case_id).toBe("CASE-2026-0004"); // Dec 2025
    expect(sorted[3].case_id).toBe("CASE-2026-0003"); // Mar 2026
  });
});

// ── Filter + Sort pipeline (replica of DashboardPage logic) ──────────────────

function applyFilterAndSort(
  cases: CaseSummary[],
  search: string,
  statusFilter: string,
  priorityFilter: string,
  sortField: Parameters<typeof compareCases>[2],
  sortDirection: "asc" | "desc"
): CaseSummary[] {
  const q = search.trim().toLowerCase();
  const filtered = cases.filter((c) => {
    if (q) {
      const haystack = `${c.case_name} ${c.case_id} ${c.investigator}`.toLowerCase();
      if (!haystack.includes(q)) return false;
    }
    if (statusFilter !== "all" && c.status !== statusFilter) return false;
    if (priorityFilter !== "all" && c.priority !== priorityFilter) return false;
    return true;
  });
  return [...filtered].sort((a, b) =>
    compareCases(a, b, sortField, sortDirection)
  );
}

describe("filter + sort pipeline", () => {
  it("filters by search text across name, id, and investigator", () => {
    const result = applyFilterAndSort(
      MOCK_CASES, "jsmith", "all", "all", "case_name", "asc"
    );
    expect(result).toHaveLength(2);
    expect(result.map((c) => c.case_id)).toEqual([
      "CASE-2026-0001",
      "CASE-2026-0004",
    ]);
  });

  it("filters by status", () => {
    const result = applyFilterAndSort(
      MOCK_CASES, "", "Active", "all", "case_name", "asc"
    );
    expect(result).toHaveLength(2);
    expect(result.every((c) => c.status === "Active")).toBe(true);
  });

  it("filters by priority", () => {
    const result = applyFilterAndSort(
      MOCK_CASES, "", "all", "Critical", "case_name", "asc"
    );
    expect(result).toHaveLength(1);
    expect(result[0].priority).toBe("Critical");
  });

  it("combines search + status + priority filters", () => {
    const result = applyFilterAndSort(
      MOCK_CASES, "jsmith", "Active", "High", "case_name", "asc"
    );
    expect(result).toHaveLength(1);
    expect(result[0].case_id).toBe("CASE-2026-0001");
  });

  it("returns empty when no cases match filters", () => {
    const result = applyFilterAndSort(
      MOCK_CASES, "nonexistent", "all", "all", "case_name", "asc"
    );
    expect(result).toHaveLength(0);
  });

  it("sorts filtered results", () => {
    const result = applyFilterAndSort(
      MOCK_CASES, "", "Active", "all", "priority", "desc"
    );
    expect(result).toHaveLength(2);
    expect(result[0].priority).toBe("Critical");
    expect(result[1].priority).toBe("High");
  });
});

// ── Activity helpers ─────────────────────────────────────────────────────────

describe("activityIcon", () => {
  it("returns FolderPlus for CASE_CREATED", () => {
    expect(activityIcon("CASE_CREATED")).toBe(FolderPlus);
  });

  it("returns Pencil for CASE_UPDATED", () => {
    expect(activityIcon("CASE_UPDATED")).toBe(Pencil);
  });

  it("returns Trash2 for CASE_DELETED", () => {
    expect(activityIcon("CASE_DELETED")).toBe(Trash2);
  });

  it("returns Share2 for RECORD_SHARED", () => {
    expect(activityIcon("RECORD_SHARED")).toBe(Share2);
  });

  it("returns CircleDot for unknown actions", () => {
    expect(activityIcon("MYSTERY_ACTION")).toBe(CircleDot);
  });
});

describe("activityLabel", () => {
  it("formats known actions", () => {
    expect(activityLabel("CASE_CREATED")).toBe("Case created");
    expect(activityLabel("CASE_UPDATED")).toBe("Case updated");
    expect(activityLabel("CASE_DELETED")).toBe("Case deleted");
    expect(activityLabel("RECORD_SHARED")).toBe("Record shared");
  });

  it("lowercases and replaces underscores for unknown actions", () => {
    expect(activityLabel("MYSTERY_ACTION")).toBe("mystery action");
  });
});

describe("fmtActivityTime", () => {
  it("formats a valid ISO timestamp", () => {
    const result = fmtActivityTime("2026-01-15T09:00:00Z");
    expect(result).toContain("2026");
    expect(result).toContain("Jan");
    expect(result).toContain("15");
  });

  it("returns the raw string for invalid input", () => {
    expect(fmtActivityTime("not-a-date")).toBe("not-a-date");
  });
});
