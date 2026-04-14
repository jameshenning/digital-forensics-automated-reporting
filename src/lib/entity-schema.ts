/**
 * Zod validation schema for entity add/edit forms.
 *
 * Mirrors EntityInput from bindings.ts.
 *
 * Constraints:
 *  - entity_type: required enum
 *  - display_name: required, 1–200
 *  - subtype: optional enum, only allowed when entity_type === 'person'
 *  - organizational_rank: optional, max 100
 *  - parent_entity_id: optional number (for hierarchy)
 *  - notes: optional, max 2000
 *  - metadata_json: optional, max 2000, must parse as valid JSON if provided
 *
 * Use z.input<> (not z.infer<>) for EntityFormValues — required by
 * @hookform/resolvers/zod v5.  See evidence-schema.ts for full explanation.
 */

import { z } from "zod";
import { ENTITY_TYPES, PERSON_SUBTYPES } from "@/lib/link-analysis-enums";

export const entityFormSchema = z
  .object({
    entity_type: z.enum(ENTITY_TYPES, {
      error: "Select a valid entity type",
    }),
    display_name: z
      .string()
      .min(1, "Display name is required")
      .max(200, "Display name must be at most 200 characters"),
    subtype: z
      .enum(PERSON_SUBTYPES, {
        error: "Select a valid subtype",
      })
      .nullable()
      .optional(),
    organizational_rank: z
      .string()
      .max(100, "Rank or title must be at most 100 characters")
      .optional(),
    parent_entity_id: z.number().int().positive().nullable().optional(),
    notes: z
      .string()
      .max(2000, "Notes must be at most 2000 characters")
      .optional(),
    metadata_json: z
      .string()
      .max(2000, "Metadata must be at most 2000 characters")
      .optional()
      .superRefine((val, ctx) => {
        if (val && val.trim().length > 0) {
          try {
            JSON.parse(val);
          } catch {
            ctx.addIssue({
              code: z.ZodIssueCode.custom,
              message: "Metadata must be valid JSON (or leave blank)",
            });
          }
        }
      }),
  })
  .superRefine((data, ctx) => {
    // subtype is only meaningful for persons; reject if set on non-person
    if (data.entity_type !== "person" && data.subtype != null) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        message: "Subtype may only be set when entity type is 'person'",
        path: ["subtype"],
      });
    }
  });

export type EntityFormValues = z.input<typeof entityFormSchema>;
