/**
 * Zod validation schema for the analysis notes add form.
 *
 * Mirrors AnalysisInput from bindings.ts.
 *   - category: from ANALYSIS_CATEGORIES allowlist
 *   - finding: required, max 500
 *   - description: optional, max 5000
 *   - confidence_level: from CONFIDENCE_LEVELS, default "Medium"
 *   - evidence_id: optional (null = case-level note)
 *
 * Use z.input<> (not z.infer<>) for the FormValues type alias.
 */

import { z } from "zod";
import { ANALYSIS_CATEGORIES, CONFIDENCE_LEVELS } from "@/lib/record-enums";

export const analysisFormSchema = z.object({
  evidence_id: z.string().default(""),
  category: z.enum(ANALYSIS_CATEGORIES, {
    error: "Select a valid analysis category",
  }),
  finding: z
    .string()
    .min(1, "Finding is required")
    .max(500, "Finding must be at most 500 characters"),
  description: z.string().max(5000, "Description must be at most 5000 characters").default(""),
  confidence_level: z
    .enum(CONFIDENCE_LEVELS, {
      error: "Select a valid confidence level",
    })
    .default("Medium"),
});

export type AnalysisFormValues = z.input<typeof analysisFormSchema>;
