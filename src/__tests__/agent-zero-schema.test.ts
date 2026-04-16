/**
 * Tests for agent-zero-schema.ts
 *
 * Covers:
 *   - URL allowlist pattern
 *   - allow_custom_url bypass
 *   - Port bounds (1–65535)
 *   - Required fields
 *   - isAllowlistedUrl helper
 */

import { describe, it, expect } from "vitest";
import { agentZeroSchema, isAllowlistedUrl } from "@/lib/agent-zero-schema";

// ---------------------------------------------------------------------------
// isAllowlistedUrl helper
// ---------------------------------------------------------------------------

describe("isAllowlistedUrl", () => {
  it("accepts http://localhost (no port)", () => {
    expect(isAllowlistedUrl("http://localhost")).toBe(true);
  });

  it("accepts http://localhost:5099", () => {
    expect(isAllowlistedUrl("http://localhost:5099")).toBe(true);
  });

  it("accepts http://localhost:1234", () => {
    expect(isAllowlistedUrl("http://localhost:1234")).toBe(true);
  });

  it("accepts http://127.0.0.1", () => {
    expect(isAllowlistedUrl("http://127.0.0.1")).toBe(true);
  });

  it("accepts http://127.0.0.1:5099", () => {
    expect(isAllowlistedUrl("http://127.0.0.1:5099")).toBe(true);
  });

  it("accepts http://host.docker.internal", () => {
    expect(isAllowlistedUrl("http://host.docker.internal")).toBe(true);
  });

  it("accepts http://host.docker.internal:50080", () => {
    expect(isAllowlistedUrl("http://host.docker.internal:50080")).toBe(true);
  });

  it("rejects https://localhost:5099 (wrong scheme)", () => {
    expect(isAllowlistedUrl("https://localhost:5099")).toBe(false);
  });

  it("rejects http://external.example.com", () => {
    expect(isAllowlistedUrl("http://external.example.com")).toBe(false);
  });

  it("rejects http://192.168.1.1:5099", () => {
    expect(isAllowlistedUrl("http://192.168.1.1:5099")).toBe(false);
  });

  it("rejects an empty string", () => {
    expect(isAllowlistedUrl("")).toBe(false);
  });

  it("rejects a plain domain without scheme", () => {
    expect(isAllowlistedUrl("localhost:5099")).toBe(false);
  });
});

// ---------------------------------------------------------------------------
// agentZeroSchema
// ---------------------------------------------------------------------------

describe("agentZeroSchema — valid inputs", () => {
  it("accepts a standard localhost URL", () => {
    const result = agentZeroSchema.safeParse({
      url: "http://localhost:5099",
      api_key: "some-key",
      port: 5099,
      allow_custom_url: false,
    });
    expect(result.success).toBe(true);
  });

  it("accepts a Docker internal URL", () => {
    const result = agentZeroSchema.safeParse({
      url: "http://host.docker.internal:50080",
      port: 50080,
      allow_custom_url: false,
    });
    expect(result.success).toBe(true);
  });

  it("allows empty api_key (leave unchanged)", () => {
    const result = agentZeroSchema.safeParse({
      url: "http://localhost:5099",
      api_key: "",
      port: 5099,
      allow_custom_url: false,
    });
    expect(result.success).toBe(true);
  });

  it("allows custom URL when allow_custom_url is true", () => {
    const result = agentZeroSchema.safeParse({
      url: "http://192.168.1.50:5099",
      api_key: "",
      port: 5099,
      allow_custom_url: true,
    });
    expect(result.success).toBe(true);
  });

  it("defaults tor_enabled to false when the field is omitted", () => {
    const result = agentZeroSchema.safeParse({
      url: "http://localhost:5099",
      port: 5099,
      allow_custom_url: false,
    });
    expect(result.success).toBe(true);
    if (result.success) {
      expect(result.data.tor_enabled).toBe(false);
    }
  });

  it("accepts tor_enabled = true", () => {
    const result = agentZeroSchema.safeParse({
      url: "http://localhost:5099",
      port: 5099,
      allow_custom_url: false,
      tor_enabled: true,
    });
    expect(result.success).toBe(true);
    if (result.success) {
      expect(result.data.tor_enabled).toBe(true);
    }
  });
});

describe("agentZeroSchema — invalid inputs", () => {
  it("rejects external URL when allow_custom_url is false", () => {
    const result = agentZeroSchema.safeParse({
      url: "http://attacker.example.com",
      port: 5099,
      allow_custom_url: false,
    });
    expect(result.success).toBe(false);
    if (!result.success) {
      const urlError = result.error.issues.find((i) => i.path.includes("url"));
      expect(urlError).toBeDefined();
    }
  });

  it("rejects port 0 (out of range)", () => {
    const result = agentZeroSchema.safeParse({
      url: "http://localhost:5099",
      port: 0,
      allow_custom_url: false,
    });
    expect(result.success).toBe(false);
  });

  it("rejects port 65536 (out of range)", () => {
    const result = agentZeroSchema.safeParse({
      url: "http://localhost:5099",
      port: 65536,
      allow_custom_url: false,
    });
    expect(result.success).toBe(false);
  });

  it("accepts port 1 (minimum)", () => {
    const result = agentZeroSchema.safeParse({
      url: "http://localhost:1",
      port: 1,
      allow_custom_url: false,
    });
    expect(result.success).toBe(true);
  });

  it("accepts port 65535 (maximum)", () => {
    const result = agentZeroSchema.safeParse({
      url: "http://localhost:65535",
      port: 65535,
      allow_custom_url: false,
    });
    expect(result.success).toBe(true);
  });

  it("rejects missing URL", () => {
    const result = agentZeroSchema.safeParse({
      port: 5099,
      allow_custom_url: false,
    });
    expect(result.success).toBe(false);
  });

  it("rejects non-URL string for url field", () => {
    const result = agentZeroSchema.safeParse({
      url: "not a url",
      port: 5099,
      allow_custom_url: false,
    });
    expect(result.success).toBe(false);
  });

  it("rejects https:// scheme even for localhost", () => {
    const result = agentZeroSchema.safeParse({
      url: "https://localhost:5099",
      port: 5099,
      allow_custom_url: false,
    });
    // The URL is valid format but fails the allowlist check
    expect(result.success).toBe(false);
  });
});
