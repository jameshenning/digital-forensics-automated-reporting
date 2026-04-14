/**
 * Tests for hashFormSchema.
 *
 * Coverage: algorithm allowlist, hash_value length per algorithm,
 * hex-only validation, uppercase acceptance, required fields.
 */
import { describe, it, expect } from "vitest";
import { hashFormSchema } from "@/lib/hash-schema";
import { HASH_ALGORITHMS, hashLengthFor } from "@/lib/record-enums";

function isValid(data: unknown): boolean {
  return hashFormSchema.safeParse(data).success;
}

function errorPaths(data: unknown): string[] {
  const result = hashFormSchema.safeParse(data);
  if (result.success) return [];
  return result.error.issues.map((i) => i.path.join("."));
}

// Generate a hex string of exactly `n` characters
function hexOf(n: number, char = "a"): string {
  return char.repeat(n);
}

function validBase(
  algorithm: (typeof HASH_ALGORITHMS)[number] = "SHA256",
  hash_value?: string
) {
  const len = hashLengthFor(algorithm);
  return {
    algorithm,
    hash_value: hash_value ?? hexOf(len),
    verified_by: "Examiner Smith",
    verification_datetime: "2026-04-12T14:30",
    notes: "",
  };
}

describe("hashFormSchema — algorithm allowlist", () => {
  it("accepts all valid algorithms", () => {
    for (const algo of HASH_ALGORITHMS) {
      expect(isValid(validBase(algo))).toBe(true);
    }
  });

  it("rejects an invalid algorithm string", () => {
    expect(isValid({ ...validBase(), algorithm: "CRC32" })).toBe(false);
    expect(errorPaths({ ...validBase(), algorithm: "CRC32" })).toContain("algorithm");
  });
});

describe("hashFormSchema — hash_value length per algorithm", () => {
  it("MD5: accepts 32 hex chars", () => {
    expect(isValid(validBase("MD5", hexOf(32)))).toBe(true);
  });

  it("MD5: rejects 31 hex chars", () => {
    expect(isValid(validBase("MD5", hexOf(31)))).toBe(false);
  });

  it("MD5: rejects 33 hex chars", () => {
    expect(isValid(validBase("MD5", hexOf(33)))).toBe(false);
  });

  it("SHA1: accepts 40 hex chars", () => {
    expect(isValid(validBase("SHA1", hexOf(40)))).toBe(true);
  });

  it("SHA1: rejects 39 hex chars", () => {
    expect(isValid(validBase("SHA1", hexOf(39)))).toBe(false);
  });

  it("SHA256: accepts 64 hex chars", () => {
    expect(isValid(validBase("SHA256", hexOf(64)))).toBe(true);
  });

  it("SHA256: rejects 63 hex chars", () => {
    expect(isValid(validBase("SHA256", hexOf(63)))).toBe(false);
  });

  it("SHA256: rejects 65 hex chars", () => {
    expect(isValid(validBase("SHA256", hexOf(65)))).toBe(false);
  });

  it("SHA3-256: accepts 64 hex chars", () => {
    expect(isValid(validBase("SHA3-256", hexOf(64)))).toBe(true);
  });

  it("SHA512: accepts 128 hex chars", () => {
    expect(isValid(validBase("SHA512", hexOf(128)))).toBe(true);
  });

  it("SHA512: rejects 127 hex chars", () => {
    expect(isValid(validBase("SHA512", hexOf(127)))).toBe(false);
  });

  it("SHA3-512: accepts 128 hex chars", () => {
    expect(isValid(validBase("SHA3-512", hexOf(128)))).toBe(true);
  });
});

describe("hashFormSchema — hex-only validation", () => {
  it("rejects non-hex characters in hash_value", () => {
    // 64 chars but contains 'g' which is not hex
    const notHex = "g".repeat(64);
    expect(isValid(validBase("SHA256", notHex))).toBe(false);
    expect(errorPaths(validBase("SHA256", notHex))).toContain("hash_value");
  });

  it("accepts uppercase hex characters (A-F)", () => {
    // Uppercase is allowed — submit handler lowercases it
    expect(isValid(validBase("SHA256", "A".repeat(64)))).toBe(true);
  });

  it("accepts lowercase hex characters", () => {
    expect(isValid(validBase("SHA256", "a".repeat(64)))).toBe(true);
  });

  it("accepts mixed case hex characters", () => {
    const mixed = ("aB3F" as string).repeat(16); // 64 chars
    expect(isValid(validBase("SHA256", mixed))).toBe(true);
  });
});

describe("hashFormSchema — required fields", () => {
  it("rejects empty hash_value", () => {
    expect(isValid({ ...validBase(), hash_value: "" })).toBe(false);
    expect(errorPaths({ ...validBase(), hash_value: "" })).toContain("hash_value");
  });

  it("rejects empty verified_by", () => {
    expect(isValid({ ...validBase(), verified_by: "" })).toBe(false);
    expect(errorPaths({ ...validBase(), verified_by: "" })).toContain("verified_by");
  });

  it("rejects empty verification_datetime", () => {
    expect(isValid({ ...validBase(), verification_datetime: "" })).toBe(false);
  });
});
