/**
 * Zod schema for the evidence file purge justification field.
 *
 * SEC-3 SHOULD-DO 4: purge is an audited, permanent hard-delete that requires
 * a human-written justification. The minimum 10-character floor ensures a
 * dismissable justification like "ok" or "done" cannot pass validation.
 */

import { z } from "zod";

export const purgeSchema = z.object({
  justification: z
    .string()
    .min(10, "Justification must be at least 10 characters")
    .max(500, "Justification must be at most 500 characters"),
});

export type PurgeFormValues = z.input<typeof purgeSchema>;
