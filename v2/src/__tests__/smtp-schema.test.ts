/**
 * Tests for smtp-schema.ts
 *
 * Covers required fields, port bounds, email format validation.
 */

import { describe, it, expect } from "vitest";
import { smtpSchema } from "@/lib/smtp-schema";

const VALID_BASE = {
  host: "smtp.example.com",
  port: 587,
  username: "user@example.com",
  password: "",
  from: "dfars@example.com",
  tls: true,
};

describe("smtpSchema — valid inputs", () => {
  it("accepts a complete valid SMTP config", () => {
    const result = smtpSchema.safeParse(VALID_BASE);
    expect(result.success).toBe(true);
  });

  it("accepts port 25 (SMTP standard)", () => {
    const result = smtpSchema.safeParse({ ...VALID_BASE, port: 25 });
    expect(result.success).toBe(true);
  });

  it("accepts port 465 (SMTPS)", () => {
    const result = smtpSchema.safeParse({ ...VALID_BASE, port: 465 });
    expect(result.success).toBe(true);
  });

  it("accepts empty password (leave unchanged semantics)", () => {
    const result = smtpSchema.safeParse({ ...VALID_BASE, password: "" });
    expect(result.success).toBe(true);
  });

  it("accepts a new plaintext password", () => {
    const result = smtpSchema.safeParse({ ...VALID_BASE, password: "s3cr3t!" });
    expect(result.success).toBe(true);
  });

  it("accepts tls: false", () => {
    const result = smtpSchema.safeParse({ ...VALID_BASE, tls: false });
    expect(result.success).toBe(true);
  });
});

describe("smtpSchema — invalid inputs", () => {
  it("rejects missing host", () => {
    const { host: _, ...rest } = VALID_BASE;
    const result = smtpSchema.safeParse(rest);
    expect(result.success).toBe(false);
  });

  it("rejects empty host", () => {
    const result = smtpSchema.safeParse({ ...VALID_BASE, host: "" });
    expect(result.success).toBe(false);
  });

  it("rejects port 0", () => {
    const result = smtpSchema.safeParse({ ...VALID_BASE, port: 0 });
    expect(result.success).toBe(false);
  });

  it("rejects port 65536", () => {
    const result = smtpSchema.safeParse({ ...VALID_BASE, port: 65536 });
    expect(result.success).toBe(false);
  });

  it("accepts port 1 (minimum)", () => {
    const result = smtpSchema.safeParse({ ...VALID_BASE, port: 1 });
    expect(result.success).toBe(true);
  });

  it("accepts port 65535 (maximum)", () => {
    const result = smtpSchema.safeParse({ ...VALID_BASE, port: 65535 });
    expect(result.success).toBe(true);
  });

  it("rejects missing username", () => {
    const { username: _, ...rest } = VALID_BASE;
    const result = smtpSchema.safeParse(rest);
    expect(result.success).toBe(false);
  });

  it("rejects empty username", () => {
    const result = smtpSchema.safeParse({ ...VALID_BASE, username: "" });
    expect(result.success).toBe(false);
  });

  it("rejects missing from address", () => {
    const { from: _, ...rest } = VALID_BASE;
    const result = smtpSchema.safeParse(rest);
    expect(result.success).toBe(false);
  });

  it("rejects invalid from email", () => {
    const result = smtpSchema.safeParse({ ...VALID_BASE, from: "not-an-email" });
    expect(result.success).toBe(false);
  });

  it("rejects empty from address", () => {
    const result = smtpSchema.safeParse({ ...VALID_BASE, from: "" });
    expect(result.success).toBe(false);
  });
});
