/**
 * Tests for toolFormSchema.
 *
 * Coverage: required fields (tool_name, purpose, operator),
 * optional fields (evidence_id, version, etc).
 */
import { describe, it, expect } from "vitest";
import { toolFormSchema } from "@/lib/tool-schema";

function isValid(data: unknown): boolean {
  return toolFormSchema.safeParse(data).success;
}

function errorPaths(data: unknown): string[] {
  const result = toolFormSchema.safeParse(data);
  if (result.success) return [];
  return result.error.issues.map((i) => i.path.join("."));
}

function validBase() {
  return {
    evidence_id: "",
    tool_name: "FTK Imager",
    version: "4.7.1",
    purpose: "Forensic disk imaging",
    command_used: "",
    input_file: "",
    output_file: "",
    execution_datetime: "2026-04-12T10:00",
    operator: "Examiner Smith",
  };
}

describe("toolFormSchema — required fields", () => {
  it("accepts a fully valid input", () => {
    expect(isValid(validBase())).toBe(true);
  });

  it("rejects empty tool_name", () => {
    expect(isValid({ ...validBase(), tool_name: "" })).toBe(false);
    expect(errorPaths({ ...validBase(), tool_name: "" })).toContain("tool_name");
  });

  it("rejects empty purpose", () => {
    expect(isValid({ ...validBase(), purpose: "" })).toBe(false);
    expect(errorPaths({ ...validBase(), purpose: "" })).toContain("purpose");
  });

  it("rejects empty operator", () => {
    expect(isValid({ ...validBase(), operator: "" })).toBe(false);
    expect(errorPaths({ ...validBase(), operator: "" })).toContain("operator");
  });
});

describe("toolFormSchema — nullable evidence_id", () => {
  it("accepts empty string evidence_id (case-wide)", () => {
    expect(isValid({ ...validBase(), evidence_id: "" })).toBe(true);
  });

  it("accepts a populated evidence_id", () => {
    expect(isValid({ ...validBase(), evidence_id: "EV-001" })).toBe(true);
  });
});

describe("toolFormSchema — optional fields", () => {
  it("accepts all optional fields empty", () => {
    expect(
      isValid({
        ...validBase(),
        version: "",
        command_used: "",
        input_file: "",
        output_file: "",
        execution_datetime: "",
      })
    ).toBe(true);
  });

  it("rejects tool_name over 200 characters", () => {
    expect(isValid({ ...validBase(), tool_name: "A".repeat(201) })).toBe(false);
  });

  it("rejects purpose over 500 characters", () => {
    expect(isValid({ ...validBase(), purpose: "A".repeat(501) })).toBe(false);
  });

  it("rejects operator over 100 characters", () => {
    expect(isValid({ ...validBase(), operator: "A".repeat(101) })).toBe(false);
  });
});
