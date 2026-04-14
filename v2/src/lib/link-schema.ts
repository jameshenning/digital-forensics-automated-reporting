/**
 * Zod validation schema for link add forms.
 *
 * Mirrors LinkInput from bindings.ts.
 *
 * Constraints:
 *  - source_type / target_type: required enum ('entity' | 'evidence')
 *  - source_id / target_id: required non-empty strings
 *  - source and target may NOT be the same node (same type + same id)
 *  - link_label: optional, max 100
 *  - directional: number 0 or 1, default 1
 *  - weight: number 0–1000, default 1.0
 *  - notes: optional, max 2000
 *
 * Use z.input<> for LinkFormValues.
 */

import { z } from "zod";
import { LINK_ENDPOINT_KINDS } from "@/lib/link-analysis-enums";

export const linkFormSchema = z
  .object({
    source_type: z.enum(LINK_ENDPOINT_KINDS, {
      error: "Select a valid source type",
    }),
    source_id: z.string().min(1, "Source is required"),
    target_type: z.enum(LINK_ENDPOINT_KINDS, {
      error: "Select a valid target type",
    }),
    target_id: z.string().min(1, "Target is required"),
    link_label: z
      .string()
      .max(100, "Link label must be at most 100 characters")
      .optional(),
    directional: z
      .number()
      .int()
      .min(0, "Directional must be 0 or 1")
      .max(1, "Directional must be 0 or 1")
      .default(1),
    weight: z
      .number()
      .min(0, "Weight must be at least 0")
      .max(1000, "Weight must be at most 1000")
      .default(1.0),
    notes: z
      .string()
      .max(2000, "Notes must be at most 2000 characters")
      .optional(),
  })
  .superRefine((data, ctx) => {
    // A node may not link to itself (same type + same id)
    if (data.source_type === data.target_type && data.source_id === data.target_id) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        message: "Source and target must be different nodes",
        path: ["target_id"],
      });
    }
  });

export type LinkFormValues = z.input<typeof linkFormSchema>;
