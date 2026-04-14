/**
 * Tests for custodyFormSchema.
 *
 * Coverage: action allowlist, required fields, datetime format, optional fields.
 */
import { describe, it, expect } from "vitest";
import { custodyFormSchema } from "@/lib/custody-schema";
import { CUSTODY_ACTIONS } from "@/lib/record-enums";

function isValid(data: unknown): boolean {
  return custodyFormSchema.safeParse(data).success;
}

function errorPaths(data: unknown): string[] {
  const result = custodyFormSchema.safeParse(data);
  if (result.success) return [];
  return result.error.issues.map((i) => i.path.join("."));
}

function validBase() {
  return {
    action: "Seized" as const,
    from_party: "Officer Jones",
    to_party: "Evidence Lab",
    custody_datetime: "2026-04-12T09:00",
    location: "",
    purpose: "",
    notes: "",
  };
}

describe("custodyFormSchema — action allowlist", () => {
  it("accepts all valid custody actions", () => {
    for (const action of CUSTODY_ACTIONS) {
      expect(isValid({ ...validBase(), action })).toBe(true);
    }
  });

  it("rejects an invalid action string", () => {
    expect(isValid({ ...validBase(), action: "Confiscated" })).toBe(false);
    expect(errorPaths({ ...validBase(), action: "Confiscated" })).toContain("action");
  });

  it("rejects empty action", () => {
    expect(isValid({ ...validBase(), action: "" })).toBe(false);
  });
});

describe("custodyFormSchema — required fields", () => {
  it("rejects empty from_party", () => {
    expect(isValid({ ...validBase(), from_party: "" })).toBe(false);
    expect(errorPaths({ ...validBase(), from_party: "" })).toContain("from_party");
  });

  it("rejects empty to_party", () => {
    expect(isValid({ ...validBase(), to_party: "" })).toBe(false);
    expect(errorPaths({ ...validBase(), to_party: "" })).toContain("to_party");
  });

  it("rejects empty custody_datetime", () => {
    expect(isValid({ ...validBase(), custody_datetime: "" })).toBe(false);
    expect(errorPaths({ ...validBase(), custody_datetime: "" })).toContain("custody_datetime");
  });
});

describe("custodyFormSchema — datetime format", () => {
  it("accepts YYYY-MM-DDTHH:MM format", () => {
    expect(isValid({ ...validBase(), custody_datetime: "2026-04-12T09:00" })).toBe(true);
  });

  it("rejects date-only format", () => {
    expect(isValid({ ...validBase(), custody_datetime: "2026-04-12" })).toBe(false);
  });

  it("rejects datetime with seconds", () => {
    expect(isValid({ ...validBase(), custody_datetime: "2026-04-12T09:00:00" })).toBe(false);
  });
});

describe("custodyFormSchema — optional fields", () => {
  it("accepts all optional fields empty", () => {
    expect(
      isValid({ ...validBase(), location: "", purpose: "", notes: "" })
    ).toBe(true);
  });

  it("rejects notes over 2000 characters", () => {
    expect(isValid({ ...validBase(), notes: "A".repeat(2001) })).toBe(false);
  });

  it("accepts notes at exactly 2000 characters", () => {
    expect(isValid({ ...validBase(), notes: "A".repeat(2000) })).toBe(true);
  });
});
