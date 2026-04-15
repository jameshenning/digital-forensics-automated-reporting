/**
 * Tests for personIdentifierFormSchema — migration 0004 multi-valued
 * OSINT identifiers (email, username, handle, phone, url).
 *
 * Covers: kind allowlist, value min/max, optional platform/notes, oversize
 * rejection. Matches the Rust-side VALID_KINDS allowlist in
 * src-tauri/src/db/person_identifiers.rs.
 */
import { describe, it, expect } from "vitest";
import {
  personIdentifierFormSchema,
  PERSON_IDENTIFIER_KINDS,
} from "@/lib/person-schema";

const VALID_EMAIL = {
  kind: "email" as const,
  value: "alice@example.com",
  platform: "gmail",
  notes: "primary contact",
};

describe("personIdentifierFormSchema — valid cases", () => {
  it("accepts a fully-populated email identifier", () => {
    const result = personIdentifierFormSchema.safeParse(VALID_EMAIL);
    expect(result.success).toBe(true);
  });

  it.each(PERSON_IDENTIFIER_KINDS)(
    "accepts each allowed kind: %s",
    (kind) => {
      const result = personIdentifierFormSchema.safeParse({
        kind,
        value: "some-value",
      });
      expect(result.success).toBe(true);
    },
  );

  it("accepts minimal input (kind + value only)", () => {
    const result = personIdentifierFormSchema.safeParse({
      kind: "handle",
      value: "@alice",
    });
    expect(result.success).toBe(true);
  });

  it("accepts a URL identifier with a 499-char value", () => {
    const result = personIdentifierFormSchema.safeParse({
      kind: "url",
      value: "https://" + "a".repeat(491),
    });
    expect(result.success).toBe(true);
  });
});

describe("personIdentifierFormSchema — invalid cases", () => {
  it("rejects a kind outside the allowlist", () => {
    const result = personIdentifierFormSchema.safeParse({
      kind: "facebook",
      value: "alice.facebook",
    });
    expect(result.success).toBe(false);
  });

  it("rejects an empty value", () => {
    const result = personIdentifierFormSchema.safeParse({
      kind: "email",
      value: "",
    });
    expect(result.success).toBe(false);
    if (!result.success) {
      const valueIssue = result.error.issues.find((i) => i.path.join(".") === "value");
      expect(valueIssue).toBeDefined();
    }
  });

  it("rejects a whitespace-only value (trim refine)", () => {
    // Without the .refine, .min(1) would accept "   " because raw length is 3.
    // The refine must trim and reject.
    const result = personIdentifierFormSchema.safeParse({
      kind: "email",
      value: "   ",
    });
    expect(result.success).toBe(false);
    if (!result.success) {
      const valueIssue = result.error.issues.find((i) => i.path.join(".") === "value");
      expect(valueIssue).toBeDefined();
      expect(valueIssue?.message).toMatch(/blank/i);
    }
  });

  it("rejects a value longer than 500 chars", () => {
    const result = personIdentifierFormSchema.safeParse({
      kind: "email",
      value: "a".repeat(501),
    });
    expect(result.success).toBe(false);
  });

  it("rejects a platform longer than 100 chars", () => {
    const result = personIdentifierFormSchema.safeParse({
      kind: "email",
      value: "alice@example.com",
      platform: "p".repeat(101),
    });
    expect(result.success).toBe(false);
  });

  it("rejects notes longer than 2000 chars", () => {
    const result = personIdentifierFormSchema.safeParse({
      kind: "email",
      value: "alice@example.com",
      notes: "x".repeat(2001),
    });
    expect(result.success).toBe(false);
  });

  it("rejects a missing kind", () => {
    const result = personIdentifierFormSchema.safeParse({
      value: "alice@example.com",
    });
    expect(result.success).toBe(false);
  });
});

describe("PERSON_IDENTIFIER_KINDS — Rust/TS contract", () => {
  it("matches the Rust VALID_KINDS allowlist exactly", () => {
    // Keep in sync with src-tauri/src/db/person_identifiers.rs::VALID_KINDS.
    // If you change this test, change that constant (and vice versa).
    expect(PERSON_IDENTIFIER_KINDS).toEqual([
      "email",
      "username",
      "handle",
      "phone",
      "url",
    ]);
  });
});
