/**
 * Zod validation schema for the Persons form.
 *
 * Person is stored as an `entities` row with `entity_type = 'person'`. This
 * schema covers the person-specific subset of EntityInput: the baseline
 * fields (display_name, subtype, organizational_rank, notes, metadata_json)
 * plus the migration 0002 person columns (email, phone, username, employer,
 * dob).
 *
 * `photo_path` is NOT part of this form — it's managed by the dedicated
 * personPhotoUpload command after the entity is created.
 *
 * Use z.input<> (not z.infer<>) for PersonFormValues — required by
 * @hookform/resolvers/zod v5. See case-schema.ts / evidence-schema.ts for
 * full explanation.
 */

import { z } from "zod";
import { PERSON_SUBTYPES } from "@/lib/link-analysis-enums";

export const personFormSchema = z.object({
  display_name: z
    .string()
    .min(1, "Display name is required")
    .max(200, "Display name must be at most 200 characters"),
  subtype: z
    .enum(PERSON_SUBTYPES, { error: "Select a valid subtype" })
    .nullable()
    .optional(),
  organizational_rank: z
    .string()
    .max(100, "Rank or title must be at most 100 characters")
    .optional(),
  email: z
    .string()
    .max(254, "Email must be at most 254 characters")
    .optional()
    .refine(
      (val) => {
        if (!val || val.trim().length === 0) return true;
        // Permissive email check — backend does no format validation so we
        // don't want to reject unusual but valid forensic data (foreign
        // domains, subaddresses, etc.). Just require an @ with non-empty
        // local and domain parts.
        const parts = val.trim().split("@");
        return parts.length === 2 && parts[0].length > 0 && parts[1].length > 0;
      },
      { message: "Email must contain a single @ with non-empty parts" },
    ),
  phone: z
    .string()
    .max(50, "Phone must be at most 50 characters")
    .optional(),
  username: z
    .string()
    .max(100, "Username must be at most 100 characters")
    .optional(),
  employer: z
    .string()
    .max(200, "Employer must be at most 200 characters")
    .optional(),
  dob: z
    .string()
    .optional()
    .refine(
      (val) => {
        if (!val || val.trim().length === 0) return true;
        // Loose date check — accept any string the HTML date input produces
        // (YYYY-MM-DD) and any v1-format datetime. Deeper validation lives
        // at the backend layer where we know v1-compat rules.
        return /^\d{4}-\d{2}-\d{2}/.test(val);
      },
      { message: "Date of birth must be in YYYY-MM-DD format" },
    ),
  notes: z
    .string()
    .max(2000, "Notes must be at most 2000 characters")
    .optional(),
});

export type PersonFormValues = z.input<typeof personFormSchema>;

// ─── Person identifier schema (migration 0004) ───────────────────────────────

/**
 * Allowed identifier kinds. Must match the Rust VALID_KINDS allowlist in
 * `src-tauri/src/db/person_identifiers.rs`.
 */
export const PERSON_IDENTIFIER_KINDS = [
  "email",
  "username",
  "handle",
  "phone",
  "url",
] as const;

export const personIdentifierFormSchema = z.object({
  kind: z.enum(PERSON_IDENTIFIER_KINDS, {
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

export type PersonIdentifierFormValues = z.input<
  typeof personIdentifierFormSchema
>;
