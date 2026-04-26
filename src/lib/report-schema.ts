/**
 * Zod schemas for report generation options.
 */

import { z } from "zod";

export const reportFormatSchema = z.enum(["Markdown", "Html", "Pdf"]);

export type ReportFormat = z.infer<typeof reportFormatSchema>;

export const reportTemplateSchema = z.enum(["Standard", "Swgde"]);

export type ReportTemplate = z.infer<typeof reportTemplateSchema>;
