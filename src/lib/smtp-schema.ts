/**
 * Zod schema for the SMTP settings form.
 *
 * Passwords are never persisted client-side — the form collects a new
 * plaintext value that is passed straight through to the Tauri command,
 * or the field is left blank to signal "do not change".
 */

import { z } from "zod";

export const smtpSchema = z.object({
  host: z
    .string()
    .min(1, "SMTP host is required")
    .max(253, "Host is too long"),
  port: z
    .number({ error: "Port must be a number" })
    .int("Port must be an integer")
    .min(1, "Port must be at least 1")
    .max(65535, "Port must be at most 65535"),
  username: z
    .string()
    .min(1, "Username is required")
    .max(320, "Username is too long"),
  password: z
    .string()
    .max(1024, "Password is too long")
    .optional()
    .or(z.literal("")),
  from: z
    .string()
    .min(1, "From address is required")
    .email("Enter a valid email address")
    .max(320, "Address is too long"),
  tls: z.boolean(),
});

export type SmtpFormValues = z.input<typeof smtpSchema>;
export type SmtpFormOutput = z.output<typeof smtpSchema>;
