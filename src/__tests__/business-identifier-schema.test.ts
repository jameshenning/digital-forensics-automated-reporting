/**
 * Tests for businessIdentifierFormSchema — migration 0005 multi-valued
 * OSINT identifiers (domain, registration, ein, email, phone, address, social, url).
 *
 * Covers: kind allowlist, value min/max, optional platform/notes, oversize
 * rejection. Matches the Rust-side VALID_KINDS allowlist in
 * src-tauri/src/db/business_identifiers.rs.
 */
import { describe, it, expect } from "vitest";
import {
  businessIdentifierFormSchema,
  BUSINESS_IDENTIFIER_KINDS,
} from "@/lib/business-schema";

const VALID_DOMAIN = {
  kind: "domain" as const,
  value: "acme.com",
  platform: "cloudflare",
  notes: "primary domain",
};

describe("businessIdentifierFormSchema — valid cases", () => {
  it("accepts a fully-populated domain identifier", () => {
    const result = businessIdentifierFormSchema.safeParse(VALID_DOMAIN);
    expect(result.success).toBe(true);
  });

  it.each(BUSINESS_IDENTIFIER_KINDS)(
    "accepts each allowed kind: %s",
    (kind) => {
      const result = businessIdentifierFormSchema.safeParse({
        kind,
        value: "some-value",
      });
      expect(result.success).toBe(true);
    },
  );

  it("accepts minimal input (kind + value only)", () => {
    const result = businessIdentifierFormSchema.safeParse({
      kind: "ein",
      value: "12-3456789",
    });
    expect(result.success).toBe(true);
  });

  it("accepts a URL identifier with a 499-char value", () => {
    const result = businessIdentifierFormSchema.safeParse({
      kind: "url",
      value: "https://" + "a".repeat(491),
    });
    expect(result.success).toBe(true);
  });

  it("accepts a registration identifier", () => {
    const result = businessIdentifierFormSchema.safeParse({
      kind: "registration",
      value: "DE-2024-123456",
    });
    expect(result.success).toBe(true);
  });

  it("accepts a social identifier with platform", () => {
    const result = businessIdentifierFormSchema.safeParse({
      kind: "social",
      value: "https://linkedin.com/company/acme",
      platform: "linkedin",
    });
    expect(result.success).toBe(true);
  });
});

describe("businessIdentifierFormSchema — invalid cases", () => {
  it("rejects a kind outside the allowlist", () => {
    const result = businessIdentifierFormSchema.safeParse({
      kind: "facebook",
      value: "acme.facebook",
    });
    expect(result.success).toBe(false);
  });

  it("rejects 'username' (person kind, not a business kind)", () => {
    const result = businessIdentifierFormSchema.safeParse({
      kind: "username",
      value: "acme_corp",
    });
    expect(result.success).toBe(false);
  });

  it("rejects 'handle' (person kind, not a business kind)", () => {
    const result = businessIdentifierFormSchema.safeParse({
      kind: "handle",
      value: "@acme",
    });
    expect(result.success).toBe(false);
  });

  it("rejects an empty value", () => {
    const result = businessIdentifierFormSchema.safeParse({
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
    const result = businessIdentifierFormSchema.safeParse({
      kind: "domain",
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
    const result = businessIdentifierFormSchema.safeParse({
      kind: "domain",
      value: "a".repeat(501),
    });
    expect(result.success).toBe(false);
  });

  it("rejects a platform longer than 100 chars", () => {
    const result = businessIdentifierFormSchema.safeParse({
      kind: "domain",
      value: "acme.com",
      platform: "p".repeat(101),
    });
    expect(result.success).toBe(false);
  });

  it("rejects notes longer than 2000 chars", () => {
    const result = businessIdentifierFormSchema.safeParse({
      kind: "domain",
      value: "acme.com",
      notes: "x".repeat(2001),
    });
    expect(result.success).toBe(false);
  });

  it("rejects a missing kind", () => {
    const result = businessIdentifierFormSchema.safeParse({
      value: "acme.com",
    });
    expect(result.success).toBe(false);
  });
});

describe("BUSINESS_IDENTIFIER_KINDS — Rust/TS contract", () => {
  it("matches the Rust VALID_KINDS allowlist exactly", () => {
    // Keep in sync with src-tauri/src/db/business_identifiers.rs::VALID_KINDS.
    // If you change this test, change that constant (and vice versa).
    expect(BUSINESS_IDENTIFIER_KINDS).toEqual([
      "domain",
      "registration",
      "ein",
      "email",
      "phone",
      "address",
      "social",
      "url",
    ]);
  });
});
