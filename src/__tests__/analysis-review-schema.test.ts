/**
 * Tests for analysisReviewFormSchema (migration 0007 — peer review).
 */
import { describe, it, expect } from "vitest";
import { analysisReviewFormSchema } from "@/lib/analysis-review-schema";

function isValid(data: unknown): boolean {
  return analysisReviewFormSchema.safeParse(data).success;
}

function errorPaths(data: unknown): string[] {
  const r = analysisReviewFormSchema.safeParse(data);
  if (r.success) return [];
  return r.error.issues.map((i) => i.path.join("."));
}

const validBase = () => ({
  reviewed_by: "Dr. Peer Reviewer",
  reviewed_at: "2026-04-22T10:00",
  review_notes: "",
});

describe("analysisReviewFormSchema", () => {
  it("accepts a minimal valid input", () => {
    expect(isValid(validBase())).toBe(true);
  });

  it("rejects empty reviewer", () => {
    expect(isValid({ ...validBase(), reviewed_by: "" })).toBe(false);
    expect(errorPaths({ ...validBase(), reviewed_by: "" })).toContain("reviewed_by");
  });

  it("rejects whitespace-only reviewer", () => {
    expect(isValid({ ...validBase(), reviewed_by: "   " })).toBe(false);
  });

  it("rejects empty reviewed_at", () => {
    expect(isValid({ ...validBase(), reviewed_at: "" })).toBe(false);
    expect(errorPaths({ ...validBase(), reviewed_at: "" })).toContain("reviewed_at");
  });

  it("accepts review_notes up to 2000 chars", () => {
    expect(isValid({ ...validBase(), review_notes: "A".repeat(2000) })).toBe(true);
  });

  it("rejects review_notes over 2000 chars", () => {
    expect(isValid({ ...validBase(), review_notes: "A".repeat(2001) })).toBe(false);
  });

  it("rejects reviewer over 200 chars", () => {
    expect(isValid({ ...validBase(), reviewed_by: "A".repeat(201) })).toBe(false);
  });
});
