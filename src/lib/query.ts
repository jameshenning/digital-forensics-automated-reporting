/**
 * Centralized TanStack Query keys.
 *
 * All components import keys from here — no inline string arrays.
 * This prevents cache-key typos and makes invalidation surgical.
 */

import type { GraphFilter, TimelineFilter } from "@/lib/bindings";

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

  /** Evidence query keys */
  evidence: {
    listForCase: (caseId: string) =>
      ["evidence", "list", "case", caseId] as const,
    detail: (evidenceId: string) =>
      ["evidence", "detail", evidenceId] as const,
  },

  /** Chain-of-custody query keys */
  custody: {
    listForEvidence: (evidenceId: string) =>
      ["custody", "list", "evidence", evidenceId] as const,
    listForCase: (caseId: string) =>
      ["custody", "list", "case", caseId] as const,
  },

  /** Hash verification query keys */
  hashes: {
    listForCase: (caseId: string) =>
      ["hashes", "list", "case", caseId] as const,
    listForEvidence: (evidenceId: string) =>
      ["hashes", "list", "evidence", evidenceId] as const,
  },

  /** Tool usage query keys */
  tools: {
    listForCase: (caseId: string) =>
      ["tools", "list", "case", caseId] as const,
    listForEvidence: (evidenceId: string) =>
      ["tools", "list", "evidence", evidenceId] as const,
  },

  /** Analysis note query keys */
  analysis: {
    listForCase: (caseId: string) =>
      ["analysis", "list", "case", caseId] as const,
    listForEvidence: (evidenceId: string) =>
      ["analysis", "list", "evidence", evidenceId] as const,
  },

  /** Evidence file query keys (Phase 3b) */
  evidenceFiles: {
    listForEvidence: (evidenceId: string) =>
      ["evidence-files", "list", "evidence", evidenceId] as const,
  },

  /** Report query keys (Phase 3b) */
  reports: {
    preview: (caseId: string) =>
      ["reports", "preview", caseId] as const,
  },

  /** Entity query keys (Phase 4) */
  entities: {
    listForCase: (caseId: string) =>
      ["entities", "list", caseId] as const,
    detail: (entityId: number) =>
      ["entities", "detail", entityId] as const,
  },

  /** Person identifier query keys (migration 0004) */
  personIdentifiers: {
    listForEntity: (entityId: number) =>
      ["person-identifiers", "list", entityId] as const,
  },

  /** Person employer query keys (employer combobox feature) */
  personEmployers: {
    listForPerson: (entityId: number) =>
      ["person-employers", "list", entityId] as const,
  },

  /** Business identifier query keys (migration 0005) */
  businessIdentifiers: {
    listForEntity: (entityId: number) =>
      ["business-identifiers", "list", entityId] as const,
  },

  /** Link query keys (Phase 4) */
  links: {
    listForCase: (caseId: string) =>
      ["links", "list", caseId] as const,
  },

  /** Case event query keys (Phase 4) */
  events: {
    listForCase: (caseId: string) =>
      ["events", "list", caseId] as const,
  },

  /** Graph query keys (Phase 4) */
  graph: {
    forCase: (caseId: string, filter: GraphFilter) =>
      ["graph", caseId, filter] as const,
  },

  /** Crime-line query keys (Phase 4) */
  crimeLine: {
    forCase: (caseId: string, filter: TimelineFilter) =>
      ["crime-line", caseId, filter] as const,
  },

  /** Agent Zero integration settings (Phase 5) */
  agentZero: {
    settings: ["agentZero", "settings"] as const,
    status: ["agentZero", "status"] as const,
  },

  /** SMTP settings (Phase 5) */
  smtp: {
    settings: ["smtp", "settings"] as const,
  },

  /** Drive list (Phase 5) */
  drives: {
    list: ["drives", "list"] as const,
  },

  /** Network binding status (Phase 5) */
  network: {
    status: ["network", "status"] as const,
  },
} as const;
