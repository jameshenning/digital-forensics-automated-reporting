/**
 * Tests for evidenceFormSchema.
 *
 * Coverage: evidence_id format, description limits, collected_by limits,
 * collection_datetime ISO format, optional fields, required field enforcement.
 */
import { describe, it, expect } from "vitest";
import { evidenceFormSchema } from "@/lib/evidence-schema";

function isValid(data: unknown): boolean {
  return evidenceFormSchema.safeParse(data).success;
}

function errorPaths(data: unknown): string[] {
  const result = evidenceFormSchema.safeParse(data);
  if (result.success) return [];
  return result.error.issues.map((i) => i.path.join("."));
}

function validBase() {
  return {
    evidence_id: "EV-001",
    description: "Test evidence item",
    collected_by: "Examiner Smith",
    collection_datetime: "2026-01-15T10:30",
    location: "",
    status: "Collected",
    evidence_type: "",
    make_model: "",
    serial_number: "",
    storage_location: "",
  };
}

describe("evidenceFormSchema — evidence_id", () => {
  it("accepts a valid alphanumeric ID", () => {
    expect(isValid(validBase())).toBe(true);
  });

  it("accepts ID with dots, underscores, and hyphens", () => {
    expect(isValid({ ...validBase(), evidence_id: "EV.2026_001-A" })).toBe(true);
  });

  it("rejects empty evidence_id", () => {
    expect(isValid({ ...validBase(), evidence_id: "" })).toBe(false);
    expect(errorPaths({ ...validBase(), evidence_id: "" })).toContain("evidence_id");
  });

  it("rejects evidence_id longer than 64 characters", () => {
    expect(isValid({ ...validBase(), evidence_id: "A".repeat(65) })).toBe(false);
  });

  it("accepts evidence_id of exactly 64 characters", () => {
    expect(isValid({ ...validBase(), evidence_id: "A".repeat(64) })).toBe(true);
  });

  it("rejects evidence_id with spaces", () => {
    expect(isValid({ ...validBase(), evidence_id: "EV 001" })).toBe(false);
  });

  it("rejects evidence_id with special chars beyond allowlist", () => {
    expect(isValid({ ...validBase(), evidence_id: "EV/001" })).toBe(false);
    expect(isValid({ ...validBase(), evidence_id: "EV@001" })).toBe(false);
  });
});

describe("evidenceFormSchema — description", () => {
  it("rejects empty description", () => {
    expect(isValid({ ...validBase(), description: "" })).toBe(false);
    expect(errorPaths({ ...validBase(), description: "" })).toContain("description");
  });

  it("accepts description up to 2000 characters", () => {
    expect(isValid({ ...validBase(), description: "A".repeat(2000) })).toBe(true);
  });

  it("rejects description over 2000 characters", () => {
    expect(isValid({ ...validBase(), description: "A".repeat(2001) })).toBe(false);
  });
});

describe("evidenceFormSchema — collection_datetime", () => {
  it("accepts valid YYYY-MM-DDTHH:MM format", () => {
    expect(isValid({ ...validBase(), collection_datetime: "2026-04-12T14:30" })).toBe(true);
  });

  it("rejects empty collection_datetime", () => {
    expect(isValid({ ...validBase(), collection_datetime: "" })).toBe(false);
  });

  it("rejects date-only format (missing time)", () => {
    expect(isValid({ ...validBase(), collection_datetime: "2026-04-12" })).toBe(false);
  });

  it("rejects datetime with seconds (YYYY-MM-DDTHH:MM:SS) — datetime-local strips seconds", () => {
    // datetime-local input produces HH:MM, not HH:MM:SS
    expect(isValid({ ...validBase(), collection_datetime: "2026-04-12T14:30:00" })).toBe(false);
  });
});

describe("evidenceFormSchema — required fields", () => {
  it("rejects missing collected_by", () => {
    expect(isValid({ ...validBase(), collected_by: "" })).toBe(false);
    expect(errorPaths({ ...validBase(), collected_by: "" })).toContain("collected_by");
  });

  it("rejects collected_by over 100 characters", () => {
    expect(isValid({ ...validBase(), collected_by: "A".repeat(101) })).toBe(false);
  });

  it("accepts all optional fields empty", () => {
    expect(
      isValid({
        ...validBase(),
        location: "",
        status: "",
        evidence_type: "",
        make_model: "",
        serial_number: "",
        storage_location: "",
      })
    ).toBe(true);
  });
});
