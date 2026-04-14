/**
 * Zod validation schema for the hash verification add form.
 *
 * Mirrors HashInput from bindings.ts.
 * No edit or delete — hashes are append-only (matches v1 behavior).
 *
 * Dynamic length validation:
 *   - hash_value must be lowercase hex only  (/^[0-9a-fA-F]+$/)
 *   - hash_value length must match hashLengthFor(algorithm)
 *   - Both are client-side; backend also validates (defense-in-depth).
 *
 * Use z.input<> (not z.infer<>) for the FormValues type alias.
 */

import { z } from "zod";
import { HASH_ALGORITHMS, hashLengthFor } from "@/lib/record-enums";

export const hashFormSchema = z
  .object({
    algorithm: z.enum(HASH_ALGORITHMS, {
      error: "Select a valid hash algorithm",
    }),
    hash_value: z
      .string()
      .min(1, "Hash value is required")
      .regex(/^[0-9a-fA-F]+$/, "Hash value must contain only hex characters (0-9, a-f, A-F)"),
    verified_by: z
      .string()
      .min(1, "Verified by is required")
      .max(100, "Verified by must be at most 100 characters"),
    verification_datetime: z
      .string()
      .min(1, "Verification datetime is required")
      .regex(
        /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}$/,
        "Verification datetime must be in YYYY-MM-DDTHH:MM format"
      ),
    notes: z.string().max(2000, "Notes must be at most 2000 characters").default(""),
  })
  .superRefine((data, ctx) => {
    const expected = hashLengthFor(data.algorithm);
    if (data.hash_value.length !== expected) {
      ctx.addIssue({
        code: "custom",
        path: ["hash_value"],
        message: `Hash value must be exactly ${expected} hex characters for ${data.algorithm}`,
      });
    }
  });

export type HashFormValues = z.input<typeof hashFormSchema>;
