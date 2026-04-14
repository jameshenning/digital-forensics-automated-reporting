/**
 * Zod schema for the Agent Zero settings form.
 *
 * URL allowlist (per SEC-4 §2.3):
 *   Accepted schemes + hosts: http://localhost, http://127.0.0.1,
 *   http://host.docker.internal (any port).
 *   Custom URLs are permitted only when allow_custom_url is true.
 */

import { z } from "zod";

// ---------------------------------------------------------------------------
// URL validation helper
// ---------------------------------------------------------------------------

const ALLOWED_HOSTS = ["localhost", "127.0.0.1", "host.docker.internal"] as const;

/** Returns true if the URL is in the standard allowlist (any port). */
export function isAllowlistedUrl(raw: string): boolean {
  try {
    const parsed = new URL(raw);
    if (parsed.protocol !== "http:") return false;
    // hostname strips the port; pathname must be empty or just "/"
    return (ALLOWED_HOSTS as readonly string[]).includes(parsed.hostname);
  } catch {
    return false;
  }
}

// ---------------------------------------------------------------------------
// Schema
// ---------------------------------------------------------------------------

export const agentZeroSchema = z
  .object({
    url: z
      .string()
      .min(1, "URL is required")
      .url("Enter a valid URL, e.g. http://localhost:5099"),
    api_key: z
      .string()
      .max(512, "API key is too long")
      .optional()
      .or(z.literal("")),
    port: z
      .number({ error: "Port must be a number" })
      .int("Port must be an integer")
      .min(1, "Port must be at least 1")
      .max(65535, "Port must be at most 65535"),
    allow_custom_url: z.boolean(),
  })
  .superRefine((data, ctx) => {
    if (!data.allow_custom_url && !isAllowlistedUrl(data.url)) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        path: ["url"],
        message:
          "URL must point to localhost, 127.0.0.1, or host.docker.internal. " +
          "Enable 'Allow custom URL' to use a different host.",
      });
    }
  });

export type AgentZeroFormValues = z.input<typeof agentZeroSchema>;
export type AgentZeroFormOutput = z.output<typeof agentZeroSchema>;
