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
});

export type ToolFormValues = z.input<typeof toolFormSchema>;
