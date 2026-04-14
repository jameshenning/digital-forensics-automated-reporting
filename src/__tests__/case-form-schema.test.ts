/**
 * Tests for the case create/edit form Zod schema — src/lib/case-schema.ts
 *
 * Covers:
 *   - Valid input passes
 *   - Empty required fields fail with correct path
 *   - case_id format (allowlist regex)
 *   - end_date before start_date fails
 *   - status / priority enum mismatch fails
 *   - Tag normalization helper (normalizeTags)
 */

import { describe, it, expect } from "vitest";
import { caseFormSchema, type CaseFormValues } from "@/lib/case-schema";
import { normalizeTags } from "@/lib/case-enums";

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function isValid(data: unknown): boolean {
  return caseFormSchema.safeParse(data).success;
}

function errorPaths(data: unknown): string[] {
  const result = caseFormSchema.safeParse(data);
  if (result.success) return [];
  return result.error.issues.map((i) => i.path.join("."));
}

function validBase(): CaseFormValues {
  return {
    case_id: "CASE-2026-0001",
    case_name: "Test Case",
    description: "",
    investigator: "jsmith",
    agency: "",
    start_date: "2026-01-15",
    end_date: "",
    status: "Active",
    priority: "Medium",
    classification: "",
    evidence_drive_path: "",
    tags_raw: "",
  };
}

// ---------------------------------------------------------------------------
// Valid input
// ---------------------------------------------------------------------------

describe("caseFormSchema — valid input", () => {
  it("accepts a fully populated valid input", () => {
    const data: CaseFormValues = {
      ...validBase(),
      description: "A forensic investigation.",
      agency: "FBI",
      end_date: "2026-06-30",
      status: "Active",
      priority: "High",
      classification: "Unclassified",
      evidence_drive_path: "E:\\",
      tags_raw: "#forensics, drone",
    };
    expect(isValid(data)).toBe(true);
  });

  it("accepts minimal required fields with optional fields omitted", () => {
    expect(isValid(validBase())).toBe(true);
  });
});

// ---------------------------------------------------------------------------
// Required field validation
// ---------------------------------------------------------------------------

describe("caseFormSchema — required fields", () => {
  it("rejects empty case_id", () => {
    const data = { ...validBase(), case_id: "" };
    expect(isValid(data)).toBe(false);
    expect(errorPaths(data)).toContain("case_id");
  });

  it("rejects empty case_name", () => {
    const data = { ...validBase(), case_name: "" };
    expect(isValid(data)).toBe(false);
    expect(errorPaths(data)).toContain("case_name");
  });

  it("rejects empty investigator", () => {
    const data = { ...validBase(), investigator: "" };
    expect(isValid(data)).toBe(false);
    expect(errorPaths(data)).toContain("investigator");
  });

  it("rejects empty start_date", () => {
    const data = { ...validBase(), start_date: "" };
    expect(isValid(data)).toBe(false);
    expect(errorPaths(data)).toContain("start_date");
  });
});

// ---------------------------------------------------------------------------
// case_id format
// ---------------------------------------------------------------------------

describe("caseFormSchema — case_id format", () => {
  it("accepts alphanumeric with dots, dashes, and underscores", () => {
    for (const id of [
      "CASE-2026-0042",
      "case.001",
      "my_case",
      "A1B2C3",
      "DRONE.2026-001",
    ]) {
      expect(isValid({ ...validBase(), case_id: id })).toBe(true);
    }
  });

  it("rejects case_id with spaces", () => {
    const data = { ...validBase(), case_id: "CASE 001" };
    expect(isValid(data)).toBe(false);
    expect(errorPaths(data)).toContain("case_id");
  });

  it("rejects case_id with slashes", () => {
    const data = { ...validBase(), case_id: "CASE/001" };
    expect(isValid(data)).toBe(false);
  });

  it("rejects case_id with @ symbol", () => {
    const data = { ...validBase(), case_id: "case@domain" };
    expect(isValid(data)).toBe(false);
  });

  it("rejects case_id longer than 64 characters", () => {
    const data = { ...validBase(), case_id: "A".repeat(65) };
    expect(isValid(data)).toBe(false);
    expect(errorPaths(data)).toContain("case_id");
  });

  it("accepts case_id of exactly 64 characters", () => {
    const data = { ...validBase(), case_id: "A".repeat(64) };
    expect(isValid(data)).toBe(true);
  });
});

// ---------------------------------------------------------------------------
// end_date ≥ start_date
// ---------------------------------------------------------------------------

describe("caseFormSchema — date ordering", () => {
  it("accepts end_date equal to start_date", () => {
    const data = {
      ...validBase(),
      start_date: "2026-03-01",
      end_date: "2026-03-01",
    };
    expect(isValid(data)).toBe(true);
  });

  it("accepts end_date after start_date", () => {
    const data = {
      ...validBase(),
      start_date: "2026-01-01",
      end_date: "2026-12-31",
    };
    expect(isValid(data)).toBe(true);
  });

  it("rejects end_date before start_date", () => {
    const data = {
      ...validBase(),
      start_date: "2026-06-01",
      end_date: "2026-01-01",
    };
    expect(isValid(data)).toBe(false);
    expect(errorPaths(data)).toContain("end_date");
  });

  it("accepts empty end_date (optional)", () => {
    const data = { ...validBase(), end_date: "" };
    expect(isValid(data)).toBe(true);
  });
});

// ---------------------------------------------------------------------------
// Status / priority enum
// ---------------------------------------------------------------------------

describe("caseFormSchema — status / priority enum", () => {
  it("accepts all valid status values", () => {
    for (const status of ["Active", "Closed", "Pending", "Archived"] as const) {
      expect(isValid({ ...validBase(), status })).toBe(true);
    }
  });

  it("accepts all valid priority values", () => {
    for (const priority of ["Low", "Medium", "High", "Critical"] as const) {
      expect(isValid({ ...validBase(), priority })).toBe(true);
    }
  });

  it("rejects invalid status enum value", () => {
    const data = { ...validBase(), status: "Open" as unknown as "Active" };
    expect(isValid(data)).toBe(false);
    expect(errorPaths(data)).toContain("status");
  });

  it("rejects invalid priority enum value", () => {
    const data = { ...validBase(), priority: "Urgent" as unknown as "Low" };
    expect(isValid(data)).toBe(false);
    expect(errorPaths(data)).toContain("priority");
  });
});

// ---------------------------------------------------------------------------
// Field length limits
// ---------------------------------------------------------------------------

describe("caseFormSchema — field length limits", () => {
  it("rejects case_name longer than 200 characters", () => {
    const data = { ...validBase(), case_name: "x".repeat(201) };
    expect(isValid(data)).toBe(false);
    expect(errorPaths(data)).toContain("case_name");
  });

  it("rejects description longer than 2000 characters", () => {
    const data = { ...validBase(), description: "x".repeat(2001) };
    expect(isValid(data)).toBe(false);
  });

  it("rejects evidence_drive_path longer than 512 characters", () => {
    const data = {
      ...validBase(),
      evidence_drive_path: "E:\\".padEnd(513, "a"),
    };
    expect(isValid(data)).toBe(false);
  });
});

// ---------------------------------------------------------------------------
// normalizeTags helper
// ---------------------------------------------------------------------------

describe("normalizeTags", () => {
  it("splits on commas and trims whitespace", () => {
    expect(normalizeTags("  forensics , drone  , uav")).toEqual([
      "drone",
      "forensics",
      "uav",
    ]);
  });

  it("lowercases all tags", () => {
    expect(normalizeTags("Forensics,DRONE,UAV")).toEqual([
      "drone",
      "forensics",
      "uav",
    ]);
  });

  it("deduplicates tags", () => {
    expect(normalizeTags("drone, drone, Drone")).toEqual(["drone"]);
  });

  it("drops empty segments", () => {
    expect(normalizeTags(",,,")).toEqual([]);
    expect(normalizeTags("  ,  ,  ")).toEqual([]);
  });

  it("returns sorted result", () => {
    expect(normalizeTags("zebra, apple, mango")).toEqual([
      "apple",
      "mango",
      "zebra",
    ]);
  });

  it("handles empty string", () => {
    expect(normalizeTags("")).toEqual([]);
  });
});
