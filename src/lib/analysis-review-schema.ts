/**
 * Zod schema for the peer-review dialog. Mirrors AnalysisReviewInput
 * from bindings.ts.
 *
 * The `reviewed_at` field uses an HTML `datetime-local` input which
 * emits `"YYYY-MM-DDTHH:MM"` without seconds; the submit mapper
 * appends `":00"` before the IPC call (same pattern as hash-panel /
 * tools-panel / TimelineFilter). The Rust-side parser tolerates both
 * forms via `parse_loose_datetime`, but normalizing to HH:MM:SS keeps
 * the round-trip stable.
 */

import { z } from "zod";

export const analysisReviewFormSchema = z.object({
  reviewed_by: z
    .string()
    .trim()
    .min(1, "Reviewer name is required")
    .max(200, "Reviewer name must be at most 200 characters"),
  reviewed_at: z
    .string()
    .min(1, "Review date/time is required"),
  review_notes: z
    .string()
    .max(2000, "Review notes must be at most 2000 characters")
    .default(""),
});

export type AnalysisReviewFormValues = z.input<typeof analysisReviewFormSchema>;
