/**
 * Tests for analysisFormSchema.
 *
 * Coverage: category/confidence allowlists, finding length, description length,
 * optional evidence_id.
 */
import { describe, it, expect } from "vitest";
import { analysisFormSchema } from "@/lib/analysis-schema";
import { ANALYSIS_CATEGORIES, CONFIDENCE_LEVELS } from "@/lib/record-enums";

function isValid(data: unknown): boolean {
  return analysisFormSchema.safeParse(data).success;
}

function errorPaths(data: unknown): string[] {
  const result = analysisFormSchema.safeParse(data);
  if (result.success) return [];
  return result.error.issues.map((i) => i.path.join("."));
}

function validBase() {
  return {
    evidence_id: "",
    category: "Observation" as const,
    finding: "Suspicious file timestamp found",
    description: "",
    confidence_level: "Medium" as const,
  };
}

describe("analysisFormSchema — category allowlist", () => {
  it("accepts all valid categories", () => {
    for (const category of ANALYSIS_CATEGORIES) {
      expect(isValid({ ...validBase(), category })).toBe(true);
    }
  });

  it("rejects an invalid category string", () => {
    expect(isValid({ ...validBase(), category: "Hypothesis" })).toBe(false);
    expect(errorPaths({ ...validBase(), category: "Hypothesis" })).toContain("category");
  });
});

describe("analysisFormSchema — confidence_level allowlist", () => {
  it("accepts all valid confidence levels", () => {
    for (const confidence_level of CONFIDENCE_LEVELS) {
      expect(isValid({ ...validBase(), confidence_level })).toBe(true);
    }
  });

  it("rejects an invalid confidence level string", () => {
    expect(isValid({ ...validBase(), confidence_level: "Critical" })).toBe(false);
    expect(errorPaths({ ...validBase(), confidence_level: "Critical" })).toContain("confidence_level");
  });
});

describe("analysisFormSchema — finding length", () => {
  it("rejects empty finding", () => {
    expect(isValid({ ...validBase(), finding: "" })).toBe(false);
    expect(errorPaths({ ...validBase(), finding: "" })).toContain("finding");
  });

  it("accepts finding at exactly 500 characters", () => {
    expect(isValid({ ...validBase(), finding: "A".repeat(500) })).toBe(true);
  });

  it("rejects finding over 500 characters", () => {
    expect(isValid({ ...validBase(), finding: "A".repeat(501) })).toBe(false);
  });
});

describe("analysisFormSchema — description length", () => {
  it("accepts empty description (optional)", () => {
    expect(isValid({ ...validBase(), description: "" })).toBe(true);
  });

  it("accepts description at exactly 5000 characters", () => {
    expect(isValid({ ...validBase(), description: "A".repeat(5000) })).toBe(true);
  });

  it("rejects description over 5000 characters", () => {
    expect(isValid({ ...validBase(), description: "A".repeat(5001) })).toBe(false);
  });
});

describe("analysisFormSchema — evidence_id", () => {
  it("accepts empty evidence_id (case-level note)", () => {
    expect(isValid({ ...validBase(), evidence_id: "" })).toBe(true);
  });

  it("accepts a populated evidence_id", () => {
    expect(isValid({ ...validBase(), evidence_id: "EV-001" })).toBe(true);
  });
});

// ─── Migration 0007: validation principles ──────────────────────────────────

describe("analysisFormSchema — validation fields (migration 0007)", () => {
  it("accepts empty strings for all four new fields (backward-compat)", () => {
    expect(
      isValid({
        ...validBase(),
        created_by: "",
        method_reference: "",
        alternatives_considered: "",
        tool_version: "",
      })
    ).toBe(true);
  });

  it("accepts populated validation fields", () => {
    expect(
      isValid({
        ...validBase(),
        created_by: "J. Henning",
        method_reference: "NIST SP 800-86 §5.2",
        alternatives_considered: "Ruled out file corruption by SHA256 match",
        tool_version: "exiftool 12.76",
      })
    ).toBe(true);
  });

  it("rejects created_by over 200 chars", () => {
    expect(isValid({ ...validBase(), created_by: "A".repeat(201) })).toBe(false);
    expect(errorPaths({ ...validBase(), created_by: "A".repeat(201) })).toContain(
      "created_by"
    );
  });

  it("rejects method_reference over 500 chars", () => {
    expect(isValid({ ...validBase(), method_reference: "A".repeat(501) })).toBe(false);
  });

  it("rejects alternatives_considered over 5000 chars", () => {
    expect(
      isValid({ ...validBase(), alternatives_considered: "A".repeat(5001) })
    ).toBe(false);
  });

  it("rejects tool_version over 200 chars", () => {
    expect(isValid({ ...validBase(), tool_version: "A".repeat(201) })).toBe(false);
  });
});
