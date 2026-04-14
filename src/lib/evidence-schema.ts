/**
 * Zod validation schema for the evidence add form.
 *
 * Mirrors EvidenceInput from bindings.ts.
 *
 * Constraints:
 *   - evidence_id: required, [A-Za-z0-9._-]+, max 64
 *   - description: required, 1–2000
 *   - collected_by: required, 1–100
 *   - collection_datetime: required, ISO datetime via <input type="datetime-local">
 *   - location: optional
 *   - status: optional, default "Collected"
 *   - evidence_type/make_model/serial_number/storage_location: all optional
 *
 * Use z.input<> (not z.infer<>) for the FormValues type alias — matches
 * what @hookform/resolvers/zod v5 expects at the useForm<> generic site.
 */

import { z } from "zod";

export const evidenceFormSchema = z.object({
  evidence_id: z
    .string()
    .min(1, "Evidence ID is required")
    .max(64, "Evidence ID must be at most 64 characters")
    .regex(
      /^[A-Za-z0-9._-]+$/,
      "Evidence ID may only contain letters, digits, '.', '_', or '-'"
    ),
  description: z
    .string()
    .min(1, "Description is required")
    .max(2000, "Description must be at most 2000 characters"),
  collected_by: z
    .string()
    .min(1, "Collected by is required")
    .max(100, "Collected by must be at most 100 characters"),
  collection_datetime: z
    .string()
    .min(1, "Collection datetime is required")
    .regex(
      /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}$/,
      "Collection datetime must be in YYYY-MM-DDTHH:MM format"
    ),
  location: z.string().max(500, "Location must be at most 500 characters").default(""),
  status: z.string().max(50, "Status must be at most 50 characters").default("Collected"),
  evidence_type: z.string().max(100, "Evidence type must be at most 100 characters").default(""),
  make_model: z.string().max(200, "Make/model must be at most 200 characters").default(""),
  serial_number: z.string().max(100, "Serial number must be at most 100 characters").default(""),
  storage_location: z
    .string()
    .max(500, "Storage location must be at most 500 characters")
    .default(""),
});

// Use z.input (pre-parse) rather than z.infer/z.output — see case-schema.ts
// for the full explanation of why this matters with @hookform/resolvers/zod v5.
export type EvidenceFormValues = z.input<typeof evidenceFormSchema>;
