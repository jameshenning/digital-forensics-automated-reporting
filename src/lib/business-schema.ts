/**
 * Zod validation schemas for the Business OSINT feature — migration 0005.
 *
 * Covers:
 *   - businessIdentifierFormSchema  — add/edit a business identifier row
 *   - businessFormSchema            — add/edit a business entity
 *
 * Use z.input<> (not z.infer<>) for form value types — required by
 * @hookform/resolvers/zod v5. See case-schema.ts for full explanation.
 */

import { z } from "zod";

// ─── Business identifier schema (migration 0005) ──────────────────────────────

/**
 * Allowed identifier kinds for business entities. Must match the Rust
 * VALID_KINDS allowlist in `src-tauri/src/db/business_identifiers.rs`.
 */
export const BUSINESS_IDENTIFIER_KINDS = [
  "domain",
  "registration",
  "ein",
  "email",
  "phone",
  "address",
  "social",
  "url",
] as const;

export const businessIdentifierFormSchema = z.object({
  kind: z.enum(BUSINESS_IDENTIFIER_KINDS, {
    error: "Select a valid kind",
  }),
  value: z
    .string()
    .min(1, "Value is required")
    .max(500, "Value must be at most 500 characters")
    .refine((v) => v.trim().length > 0, {
      message: "Value must not be blank",
    }),
  platform: z
    .string()
    .max(100, "Platform must be at most 100 characters")
    .optional(),
  notes: z
    .string()
    .max(2000, "Notes must be at most 2000 characters")
    .optional(),
});

export type BusinessIdentifierFormValues = z.input<
  typeof businessIdentifierFormSchema
>;

// ─── Industry / Sector dropdown constants ─────────────────────────────────────

/**
 * Common business/industry types for the BusinessForm dropdown. Storage is
 * free-text (organizational_rank column on entities), but the UI constrains
 * input to this list for consistency across cases. "other" reveals a
 * free-text input for anything not covered.
 *
 * Forensically-relevant categories included (shell company, crypto exchange,
 * gambling, etc.) — these are frequent OSINT investigation targets.
 */
export const BUSINESS_INDUSTRY_TYPES = [
  "technology",
  "financial_services",
  "healthcare",
  "legal_services",
  "retail",
  "manufacturing",
  "real_estate",
  "construction",
  "education",
  "energy_utilities",
  "transportation_logistics",
  "media_entertainment",
  "hospitality",
  "nonprofit_ngo",
  "government_public",
  "consulting",
  "agriculture",
  "telecommunications",
  "insurance",
  "shell_holding",
  "cryptocurrency",
  "gambling_gaming",
  "adult_industry",
  "defense_military",
  "other",
] as const;

export type BusinessIndustryType = typeof BUSINESS_INDUSTRY_TYPES[number];

/**
 * Human-readable labels for each industry value. Used by the BusinessForm
 * Select dropdown and by the BusinessCard industry badge when the stored
 * `organizational_rank` matches one of the known values.
 */
export const BUSINESS_INDUSTRY_LABELS: Record<BusinessIndustryType, string> = {
  technology: "Technology / Software",
  financial_services: "Financial Services / Banking",
  healthcare: "Healthcare / Medical",
  legal_services: "Legal Services",
  retail: "Retail / E-Commerce",
  manufacturing: "Manufacturing",
  real_estate: "Real Estate",
  construction: "Construction",
  education: "Education",
  energy_utilities: "Energy / Utilities",
  transportation_logistics: "Transportation / Logistics",
  media_entertainment: "Media / Entertainment",
  hospitality: "Hospitality / Food Service",
  nonprofit_ngo: "Non-Profit / NGO",
  government_public: "Government / Public Sector",
  consulting: "Consulting / Professional Services",
  agriculture: "Agriculture",
  telecommunications: "Telecommunications",
  insurance: "Insurance",
  shell_holding: "Shell Company / Holding Company",
  cryptocurrency: "Cryptocurrency / Digital Assets",
  gambling_gaming: "Gambling / Gaming",
  adult_industry: "Adult Industry",
  defense_military: "Defense / Military",
  other: "Other (specify below)",
};

// ─── Business entity form schema ──────────────────────────────────────────────

/**
 * Form schema for creating / updating a business entity.
 *
 * `organizational_rank` is repurposed as "Industry / Sector" for business
 * entities — the underlying DB column is the same, we just label it differently.
 */
export const businessFormSchema = z.object({
  display_name: z
    .string()
    .min(1, "Display name is required")
    .max(200, "Display name must be at most 200 characters"),
  /** Industry / Sector — stored in organizational_rank column */
  organizational_rank: z
    .string()
    .max(100, "Industry / Sector must be at most 100 characters")
    .optional(),
  notes: z
    .string()
    .max(2000, "Notes must be at most 2000 characters")
    .optional(),
});

export type BusinessFormValues = z.input<typeof businessFormSchema>;
