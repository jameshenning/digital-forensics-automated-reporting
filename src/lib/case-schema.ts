/**
 * Zod validation schema for the case create/edit form.
 *
 * Mirrors CaseInput from bindings.ts.  Used by both case/new.tsx and
 * case/$caseId.edit.tsx — single source of truth.
 *
 * Constraints match v1's case_form.html and the Rust ValidationError rules:
 *   - case_id: required, [A-Za-z0-9._-]+, max 64
 *   - case_name: required, 1–200
 *   - description: optional, max 2000
 *   - investigator: required, 1–100
 *   - agency: optional, max 100
 *   - start_date: required, YYYY-MM-DD
 *   - end_date: optional, YYYY-MM-DD, must be >= start_date if provided
 *   - status: optional enum (Active | Closed | Pending | Archived)
 *   - priority: optional enum (Low | Medium | High | Critical)
 *   - classification: optional, max 200
 *   - evidence_drive_path: optional, max 512
 *   - tags: raw string, normalized on submit
 */

import { z } from "zod";

// Zod v4 z.enum() accepts a readonly string tuple.
// We spell out the tuples inline so TS infers the narrowest literal types.
const statusEnum = z.enum(["Active", "Pending", "Closed", "Archived"] as const);
const priorityEnum = z.enum(["Critical", "High", "Medium", "Low"] as const);

export const caseFormSchema = z
  .object({
    case_id: z
      .string()
      .min(1, "Case ID is required")
      .max(64, "Case ID must be at most 64 characters")
      .regex(
        /^[A-Za-z0-9._-]+$/,
        "Case ID may only contain letters, digits, '.', '_', or '-'"
      ),
    case_name: z
      .string()
      .min(1, "Case name is required")
      .max(200, "Case name must be at most 200 characters"),
    description: z
      .string()
      .max(2000, "Description must be at most 2000 characters")
      .default(""),
    investigator: z
      .string()
      .min(1, "Investigator is required")
      .max(100, "Investigator must be at most 100 characters"),
    agency: z.string().max(100, "Agency must be at most 100 characters").default(""),
    start_date: z
      .string()
      .min(1, "Start date is required")
      .regex(/^\d{4}-\d{2}-\d{2}$/, "Start date must be YYYY-MM-DD"),
    end_date: z
      .string()
      .refine(
        (val) => val === "" || /^\d{4}-\d{2}-\d{2}$/.test(val),
        "End date must be YYYY-MM-DD"
      )
      .default(""),
    status: statusEnum.optional(),
    priority: priorityEnum.optional(),
    classification: z
      .string()
      .max(200, "Classification must be at most 200 characters")
      .default(""),
    evidence_drive_path: z
      .string()
      .max(512, "Evidence drive path must be at most 512 characters")
      .default(""),
    tags_raw: z.string().default(""),
  })
  .refine(
    (data) => {
      if (!data.end_date || data.end_date === "") return true;
      if (!data.start_date) return true;
      return data.end_date >= data.start_date;
    },
    {
      message: "End date must be on or after start date",
      path: ["end_date"],
    }
  );

// Use z.input (pre-parse) rather than z.infer/z.output so that react-hook-form's
// Resolver<TFieldValues> generic matches what @hookform/resolvers/zod produces.
// Without this, zod's .default("") and .optional() create input/output drift that
// TypeScript reports as "two different types with this name" at the useForm site.
export type CaseFormValues = z.input<typeof caseFormSchema>;
