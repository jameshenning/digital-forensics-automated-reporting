/**
 * Zod schema for report format selection.
 */

import { z } from "zod";

export const reportFormatSchema = z.enum(["Markdown", "Html"]);

export type ReportFormat = z.infer<typeof reportFormatSchema>;
