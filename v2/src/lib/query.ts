/**
 * Centralized TanStack Query keys.
 *
 * All components import keys from here — no inline string arrays.
 * This prevents cache-key typos and makes invalidation surgical.
 */

export const queryKeys = {
  /** auth_current_user — the session source of truth */
  currentUser: ["auth", "currentUser"] as const,

  /** settings_get_security_posture — keyring / MFA / recovery code status */
  securityPosture: ["settings", "securityPosture"] as const,

  /** auth_tokens_list — API bearer tokens for the security settings page */
  tokensList: ["auth", "tokensList"] as const,

  /** auth_mfa_enroll_start — MFA provisioning URI + recovery codes (single-use fetch) */
  mfaEnrollment: ["auth", "mfaEnrollment"] as const,

  /** Case query keys — all case queries nest under 'cases' */
  cases: {
    /** Invalidate everything case-related */
    all: ["cases"] as const,
    /** Paginated case list */
    list: (limit: number, offset: number) =>
      ["cases", "list", limit, offset] as const,
    /** Full case detail by ID */
    detail: (caseId: string) => ["cases", "detail", caseId] as const,
  },
} as const;
