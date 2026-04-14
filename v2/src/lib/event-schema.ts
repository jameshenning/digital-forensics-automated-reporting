/**
 * Zod validation schema for case event add/edit forms.
 *
 * Mirrors EventInput from bindings.ts.
 *
 * Constraints:
 *  - title: required, 1–200
 *  - description: optional, max 5000
 *  - event_datetime: required ISO datetime (datetime-local input format)
 *  - event_end_datetime: optional ISO datetime, if provided must be >= event_datetime
 *  - category: optional enum, nullable
 *  - related_entity_id: optional number
 *  - related_evidence_id: optional string
 *
 * Use z.input<> for EventFormValues.
 */

import { z } from "zod";
import { EVENT_CATEGORIES } from "@/lib/link-analysis-enums";

/** Accepts YYYY-MM-DDTHH:MM (datetime-local) or YYYY-MM-DDTHH:MM:SS */
const datetimeLocalRegex = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}(:\d{2})?$/;

export const eventFormSchema = z
  .object({
    title: z
      .string()
      .min(1, "Title is required")
      .max(200, "Title must be at most 200 characters"),
    description: z
      .string()
      .max(5000, "Description must be at most 5000 characters")
      .optional(),
    event_datetime: z
      .string()
      .min(1, "Event datetime is required")
      .regex(datetimeLocalRegex, "Event datetime must be in YYYY-MM-DDTHH:MM format"),
    event_end_datetime: z
      .string()
      .regex(datetimeLocalRegex, "End datetime must be in YYYY-MM-DDTHH:MM format")
      .nullable()
      .optional(),
    category: z
      .enum(EVENT_CATEGORIES, {
        error: "Select a valid category",
      })
      .nullable()
      .optional(),
    related_entity_id: z.number().int().positive().nullable().optional(),
    related_evidence_id: z.string().nullable().optional(),
  })
  .superRefine((data, ctx) => {
    // end must be >= start when both are provided
    if (
      data.event_end_datetime &&
      data.event_end_datetime.trim().length > 0 &&
      data.event_datetime
    ) {
      const start = new Date(data.event_datetime).getTime();
      const end = new Date(data.event_end_datetime).getTime();
      if (!isNaN(start) && !isNaN(end) && end < start) {
        ctx.addIssue({
          code: z.ZodIssueCode.custom,
          message: "End datetime must be on or after start datetime",
          path: ["event_end_datetime"],
        });
      }
    }
  });

export type EventFormValues = z.input<typeof eventFormSchema>;
