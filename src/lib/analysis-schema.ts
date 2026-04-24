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
 * Validation fields (migration 0007, link analysis #1 — validation
 * principles). All optional at the form layer: empty strings are
 * submitted as-is and coerced to null in the mutation's input mapper
 * (matches the existing `description` pattern).
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
  // ─── Validation fields (migration 0007) ──────────────────────────────────
  created_by: z
    .string()
    .trim()
    .max(200, "Author must be at most 200 characters")
    .default(""),
  method_reference: z
    .string()
    .trim()
    .max(500, "Method reference must be at most 500 characters")
    .default(""),
  alternatives_considered: z
    .string()
    .max(5000, "Alternatives considered must be at most 5000 characters")
    .default(""),
  tool_version: z
    .string()
    .trim()
    .max(200, "Tool + version must be at most 200 characters")
    .default(""),
});

export type AnalysisFormValues = z.input<typeof analysisFormSchema>;
