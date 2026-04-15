/**
 * Zod validation schema for the tool usage add form.
 *
 * Mirrors ToolInput from bindings.ts.
 *   - tool_name: required
 *   - purpose: required
 *   - operator: required
 *   - evidence_id: optional (null = case-wide, no specific evidence)
 *   - version/command_used/input_file/output_file: optional
 *   - execution_datetime: optional (null → backend uses now())
 *   - input_sha256/output_sha256/environment_notes/reproduction_notes:
 *     optional reproduction-tracking fields (migration 0003)
 *
 * Use z.input<> (not z.infer<>) for the FormValues type alias.
 */

import { z } from "zod";

export const toolFormSchema = z.object({
  evidence_id: z.string().default(""),
  tool_name: z
    .string()
    .min(1, "Tool name is required")
    .max(200, "Tool name must be at most 200 characters"),
  version: z.string().max(50, "Version must be at most 50 characters").default(""),
  purpose: z
    .string()
    .min(1, "Purpose is required")
    .max(500, "Purpose must be at most 500 characters"),
  command_used: z.string().max(2000, "Command must be at most 2000 characters").default(""),
  input_file: z.string().max(512, "Input file must be at most 512 characters").default(""),
  output_file: z.string().max(512, "Output file must be at most 512 characters").default(""),
  execution_datetime: z.string().default(""),
  operator: z
    .string()
    .min(1, "Operator is required")
    .max(100, "Operator must be at most 100 characters"),
  // Reproduction-tracking fields (migration 0003)
  input_sha256: z
    .string()
    .max(128, "SHA-256 must be at most 128 characters")
    .refine(
      (val) => val === "" || /^[a-f0-9]{64}$/i.test(val),
      "Must be a 64-character hex string (or blank)",
    )
    .default(""),
  output_sha256: z
    .string()
    .max(128, "SHA-256 must be at most 128 characters")
    .refine(
      (val) => val === "" || /^[a-f0-9]{64}$/i.test(val),
      "Must be a 64-character hex string (or blank)",
    )
    .default(""),
  environment_notes: z
    .string()
    .max(2000, "Environment notes must be at most 2000 characters")
    .default(""),
  reproduction_notes: z
    .string()
    .max(4000, "Reproduction notes must be at most 4000 characters")
    .default(""),
});

export type ToolFormValues = z.input<typeof toolFormSchema>;
