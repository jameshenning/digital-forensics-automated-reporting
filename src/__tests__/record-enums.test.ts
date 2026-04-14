/**
 * Tests for record-enums.ts — enum tuples and hashLengthFor().
 */
import { describe, it, expect } from "vitest";
import {
  CUSTODY_ACTIONS,
  HASH_ALGORITHMS,
  ANALYSIS_CATEGORIES,
  CONFIDENCE_LEVELS,
  hashLengthFor,
} from "@/lib/record-enums";

describe("CUSTODY_ACTIONS", () => {
  it("is non-empty", () => {
    expect(CUSTODY_ACTIONS.length).toBeGreaterThan(0);
  });

  it("contains expected values", () => {
    expect(CUSTODY_ACTIONS).toContain("Seized");
    expect(CUSTODY_ACTIONS).toContain("Transferred");
    expect(CUSTODY_ACTIONS).toContain("Analyzed");
    expect(CUSTODY_ACTIONS).toContain("Destroyed");
  });

  it("has exactly 8 entries", () => {
    expect(CUSTODY_ACTIONS.length).toBe(8);
  });
});

describe("HASH_ALGORITHMS", () => {
  it("is non-empty", () => {
    expect(HASH_ALGORITHMS.length).toBeGreaterThan(0);
  });

  it("contains the core algorithms", () => {
    expect(HASH_ALGORITHMS).toContain("MD5");
    expect(HASH_ALGORITHMS).toContain("SHA1");
    expect(HASH_ALGORITHMS).toContain("SHA256");
    expect(HASH_ALGORITHMS).toContain("SHA512");
    expect(HASH_ALGORITHMS).toContain("SHA3-256");
    expect(HASH_ALGORITHMS).toContain("SHA3-512");
  });
});

describe("ANALYSIS_CATEGORIES", () => {
  it("is non-empty", () => {
    expect(ANALYSIS_CATEGORIES.length).toBeGreaterThan(0);
  });

  it("contains expected categories", () => {
    expect(ANALYSIS_CATEGORIES).toContain("Observation");
    expect(ANALYSIS_CATEGORIES).toContain("Timeline");
    expect(ANALYSIS_CATEGORIES).toContain("Conclusion");
    expect(ANALYSIS_CATEGORIES).toContain("Other");
  });
});

describe("CONFIDENCE_LEVELS", () => {
  it("is non-empty", () => {
    expect(CONFIDENCE_LEVELS.length).toBeGreaterThan(0);
  });

  it("contains Low, Medium, High", () => {
    expect(CONFIDENCE_LEVELS).toContain("Low");
    expect(CONFIDENCE_LEVELS).toContain("Medium");
    expect(CONFIDENCE_LEVELS).toContain("High");
  });

  it("has exactly 3 entries", () => {
    expect(CONFIDENCE_LEVELS.length).toBe(3);
  });
});

describe("hashLengthFor()", () => {
  it("returns 32 for MD5", () => {
    expect(hashLengthFor("MD5")).toBe(32);
  });

  it("returns 40 for SHA1", () => {
    expect(hashLengthFor("SHA1")).toBe(40);
  });

  it("returns 64 for SHA256", () => {
    expect(hashLengthFor("SHA256")).toBe(64);
  });

  it("returns 64 for SHA3-256", () => {
    expect(hashLengthFor("SHA3-256")).toBe(64);
  });

  it("returns 128 for SHA512", () => {
    expect(hashLengthFor("SHA512")).toBe(128);
  });

  it("returns 128 for SHA3-512", () => {
    expect(hashLengthFor("SHA3-512")).toBe(128);
  });

  it("returns an even number for every algorithm (hex nibble pairs)", () => {
    for (const algo of HASH_ALGORITHMS) {
      expect(hashLengthFor(algo) % 2).toBe(0);
    }
  });
});
