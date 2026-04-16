/**
 * Zod validation schemas for the Business OSINT feature — migration 0005.
 *
 * Covers:
 *   - businessIdentifierFormSchema  — add/edit a business identifier row
 *   - businessFormSchema            — add/edit a business entity
 *
 * Use z.input<> (not z.infer<>) for form value types — required by
 * @hookform/resolvers/zod v5. See case-schema.ts for full explanation.
 */

import { z } from "zod";

// ─── Business identifier schema (migration 0005) ──────────────────────────────

/**
 * Allowed identifier kinds for business entities. Must match the Rust
 * VALID_KINDS allowlist in `src-tauri/src/db/business_identifiers.rs`.
 */
export const BUSINESS_IDENTIFIER_KINDS = [
  "domain",
  "registration",
  "ein",
  "email",
  "phone",
  "address",
  "social",
  "url",
] as const;

export const businessIdentifierFormSchema = z.object({
  kind: z.enum(BUSINESS_IDENTIFIER_KINDS, {
    error: "Select a valid kind",
  }),
  value: z
    .string()
    .min(1, "Value is required")
    .max(500, "Value must be at most 500 characters")
    .refine((v) => v.trim().length > 0, {
      message: "Value must not be blank",
    }),
  platform: z
    .string()
    .max(100, "Platform must be at most 100 characters")
    .optional(),
  notes: z
    .string()
    .max(2000, "Notes must be at most 2000 characters")
    .optional(),
});

export type BusinessIdentifierFormValues = z.input<
  typeof businessIdentifierFormSchema
>;

// ─── Business entity form schema ──────────────────────────────────────────────

/**
 * Form schema for creating / updating a business entity.
 *
 * `organizational_rank` is repurposed as "Industry / Sector" for business
 * entities — the underlying DB column is the same, we just label it differently.
 */
export const businessFormSchema = z.object({
  display_name: z
    .string()
    .min(1, "Display name is required")
    .max(200, "Display name must be at most 200 characters"),
  /** Industry / Sector — stored in organizational_rank column */
  organizational_rank: z
    .string()
    .max(100, "Industry / Sector must be at most 100 characters")
    .optional(),
  notes: z
    .string()
    .max(2000, "Notes must be at most 2000 characters")
    .optional(),
});

export type BusinessFormValues = z.input<typeof businessFormSchema>;
