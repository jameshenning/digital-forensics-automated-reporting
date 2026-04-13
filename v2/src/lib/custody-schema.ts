/**
 * Zod validation schema for the chain-of-custody add/edit form.
 *
 * Mirrors CustodyInput from bindings.ts.
 * Used for BOTH add and edit — edit passes defaultValues to pre-populate.
 *
 * custody_sequence is backend-assigned; it is NOT a form field.
 *
 * Use z.input<> (not z.infer<>) for the FormValues type alias.
 */

import { z } from "zod";
import { CUSTODY_ACTIONS } from "@/lib/record-enums";

export const custodyFormSchema = z.object({
  action: z.enum(CUSTODY_ACTIONS, {
    error: "Select a valid custody action",
  }),
  from_party: z
    .string()
    .min(1, "From party is required")
    .max(100, "From party must be at most 100 characters"),
  to_party: z
    .string()
    .min(1, "To party is required")
    .max(100, "To party must be at most 100 characters"),
  custody_datetime: z
    .string()
    .min(1, "Custody datetime is required")
    .regex(
      /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}$/,
      "Custody datetime must be in YYYY-MM-DDTHH:MM format"
    ),
  location: z.string().max(500, "Location must be at most 500 characters").default(""),
  purpose: z.string().max(500, "Purpose must be at most 500 characters").default(""),
  notes: z.string().max(2000, "Notes must be at most 2000 characters").default(""),
});

export type CustodyFormValues = z.input<typeof custodyFormSchema>;
