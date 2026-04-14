/**
 * Enum tuples for evidence-related record types.
 *
 * Used by:
 *  - Zod schemas (z.enum(...)) for allowlist validation
 *  - <Select> components for option lists
 *
 * hashLengthFor() returns the expected hex character count for a given
 * algorithm so the frontend can client-side-validate before submit.
 * The backend also validates — this is defense-in-depth.
 */

export const CUSTODY_ACTIONS = [
  "Seized",
  "Transferred",
  "Received",
  "Analyzed",
  "Returned",
  "Destroyed",
  "Sealed",
  "Unsealed",
] as const;
export type CustodyActionTuple = typeof CUSTODY_ACTIONS;

export const HASH_ALGORITHMS = [
  "MD5",
  "SHA1",
  "SHA256",
  "SHA512",
  "SHA3-256",
  "SHA3-512",
] as const;
export type HashAlgorithmTuple = typeof HASH_ALGORITHMS;

export const ANALYSIS_CATEGORIES = [
  "Observation",
  "Timeline",
  "Correlation",
  "Anomaly",
  "Recommendation",
  "Conclusion",
  "Other",
] as const;
export type AnalysisCategoryTuple = typeof ANALYSIS_CATEGORIES;

export const CONFIDENCE_LEVELS = ["Low", "Medium", "High"] as const;
export type ConfidenceLevelTuple = typeof CONFIDENCE_LEVELS;

// ---------------------------------------------------------------------------
// Hash length lookup
// ---------------------------------------------------------------------------

/** Returns the expected number of hex characters for a given hash algorithm. */
export function hashLengthFor(
  algorithm: (typeof HASH_ALGORITHMS)[number]
): number {
  switch (algorithm) {
    case "MD5":
      return 32;
    case "SHA1":
      return 40;
    case "SHA256":
      return 64;
    case "SHA3-256":
      return 64;
    case "SHA512":
      return 128;
    case "SHA3-512":
      return 128;
  }
}
