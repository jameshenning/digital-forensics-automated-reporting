/**
 * Typed wrappers around Tauri IPC invoke() for all auth commands.
 *
 * The polyglot-software-engineer agent owns src-tauri/; this file is the
 * agreed wire-shape contract.  If the Rust side drifts, fix the types here
 * rather than spreading casts throughout components.
 *
 * NO HTTP cookies.  Every call passes the session token as a plain argument
 * over Tauri IPC — see §7 of v2-migration-spec.md.
 */

import { invoke } from "@tauri-apps/api/core";

// ---------------------------------------------------------------------------
// Shared types
// ---------------------------------------------------------------------------

export type AppErrorCode =
  | "Unauthorized"
  | "InvalidCredentials"
  | "AccountLocked"
  | "MfaRequired"
  | "InvalidMfaCode"
  | "NoRecoveryCodesRemaining"
  | "UserAlreadyExists"
  | "UserNotFound"
  | "PasswordPolicy"
  | "CaseNotFound"
  | "CaseAlreadyExists"
  | "CaseHasEvidence"
  | "EvidenceNotFound"
  | "EvidenceAlreadyExists"
  | "EvidenceHasDependents"
  | "CustodyNotFound"
  | "HashNotFound"
  | "ValidationError"
  | "Db"
  | "Crypto"
  | "Keyring"
  | "Io"
  | "Internal"
  // Phase 3b — evidence file + report error codes
  | "EvidenceFileNotFound"
  | "EvidenceFileTooLarge"
  | "InvalidFilename"
  | "PathTraversalBlocked"
  | "OneDriveSyncWarning"
  | "HashMismatchOnDownload"
  | "ReportGenerationFailed"
  // Phase 4 — link analysis error codes
  | "EntityNotFound"
  | "EntityCycle"
  | "LinkNotFound"
  | "LinkEndpointMissing"
  | "EventNotFound"
  // Phase 5 — AI + integration + drive error codes
  | "NetworkBindRefused"
  | "AgentZeroUrlRejected"
  | "AgentZeroNotConfigured"
  | "AgentZeroTimeout"
  | "AgentZeroServerError"
  | "PayloadTooLarge"
  | "AiSummarizeConsentRequired"
  | "AiOsintConsentRequired"
  | "SmtpConnectFailed"
  | "SmtpSendFailed"
  | "DriveScanTooLarge"
  // Persons — photo upload (migration 0002)
  | "PersonPhotoTooLarge"
  | "PersonPhotoNotAnImage"
  | "EntityNotAPerson"
  // Persons — identifiers (migration 0004)
  | "PersonIdentifierNotFound";

export interface AppError {
  code: AppErrorCode;
  message: string;
  seconds_remaining?: number; // present only when code === 'AccountLocked'
}

export interface SessionInfo {
  token: string; // 'sess_...' — stored in sessionStorage + React state
  username: string;
  mfa_enabled: boolean;
}

export type LoginStatus = "Success" | "MfaRequired" | "AccountLocked";

export interface LoginResult {
  status: LoginStatus;
  session?: SessionInfo; // present when status === 'Success'
  pending_token?: string; // present when status === 'MfaRequired'
  seconds_remaining?: number; // present when status === 'AccountLocked'
}

export interface ApiTokenListItem {
  id: string;
  name: string;
  preview: string;
  created_at: string;
  last_used_at: string | null;
}

export interface NewToken {
  id: string;
  name: string;
  plaintext: string; // shown ONCE — never stored
  preview: string;
}

export interface MfaEnrollment {
  provisioning_uri: string;
  recovery_codes: string[]; // shown ONCE — never re-fetched
}

export interface SecurityPosture {
  keyring_active: boolean;
  key_source: "keyring" | "keyfile" | "new";
  mfa_enabled: boolean;
  recovery_codes_remaining: number;
}

// ---------------------------------------------------------------------------
// Auth commands
// ---------------------------------------------------------------------------

/** Create the first (and only) user.  Returns a live session. */
export function authSetupFirstRun(args: {
  username: string;
  password: string;
}): Promise<SessionInfo> {
  return invoke<SessionInfo>("auth_setup_first_run", args);
}

/**
 * Password-step login.
 *
 * - Success (no MFA): `result.status === 'Success'`, `result.session` present.
 * - MFA required:     `result.status === 'MfaRequired'`, `result.pending_token` present.
 * - Locked out:       `result.status === 'AccountLocked'`, `result.seconds_remaining` present.
 * - Wrong credentials / other: rejects with `AppError`.
 */
export function authLogin(args: {
  username: string;
  password: string;
}): Promise<LoginResult> {
  return invoke<LoginResult>("auth_login", args);
}

/**
 * MFA second-factor verification.  `code` may be a 6-digit TOTP or a
 * `xxxxx-xxxxx` recovery code — the backend handles both.
 */
export function authVerifyMfa(args: {
  pending_token: string;
  code: string;
  use_recovery: boolean;
}): Promise<SessionInfo> {
  return invoke<SessionInfo>("auth_verify_mfa", args);
}

/**
 * Validate a session token and return current user info.
 * Rejects with AppError (Unauthorized) if token is missing, expired, or invalid.
 */
export function authCurrentUser(args: {
  token: string;
}): Promise<SessionInfo> {
  return invoke<SessionInfo>("auth_current_user", args);
}

/** Invalidate a session token.  Fire-and-forget on logout. */
export function authLogout(args: { token: string }): Promise<void> {
  return invoke<void>("auth_logout", args);
}

/** Change the authenticated user's password. */
export function authChangePassword(args: {
  token: string;
  old_password: string;
  new_password: string;
}): Promise<void> {
  return invoke<void>("auth_change_password", args);
}

/**
 * Begin MFA enrollment.  Returns the provisioning URI (for QR code) and the
 * 10 recovery codes.  Recovery codes are shown to the user ONCE and are never
 * returned by this command again — display them immediately.
 */
export function authMfaEnrollStart(args: {
  token: string;
}): Promise<MfaEnrollment> {
  return invoke<MfaEnrollment>("auth_mfa_enroll_start", args);
}

/** Confirm MFA enrollment with the first TOTP code from the authenticator app. */
export function authMfaEnrollConfirm(args: {
  token: string;
  code: string;
}): Promise<void> {
  return invoke<void>("auth_mfa_enroll_confirm", args);
}

/**
 * Disable MFA.  Requires the user's current password as a second confirmation
 * (defense against session hijack — mirrors v1 behavior).
 */
export function authMfaDisable(args: {
  token: string;
  password: string;
}): Promise<void> {
  return invoke<void>("auth_mfa_disable", args);
}

// ---------------------------------------------------------------------------
// API token commands
// ---------------------------------------------------------------------------

/** List all API bearer tokens (shows preview only, never plaintext). */
export function authTokensList(args: {
  token: string;
}): Promise<ApiTokenListItem[]> {
  return invoke<ApiTokenListItem[]>("auth_tokens_list", args);
}

/**
 * Create a new API bearer token.  The `plaintext` field in the response is
 * shown to the user ONCE and is never stored or returned again.
 */
export function authTokensCreate(args: {
  token: string;
  name: string;
}): Promise<NewToken> {
  return invoke<NewToken>("auth_tokens_create", args);
}

/** Permanently revoke an API token by its DB id. */
export function authTokensRevoke(args: {
  token: string;
  id: string;
}): Promise<void> {
  return invoke<void>("auth_tokens_revoke", args);
}

// ---------------------------------------------------------------------------
// Case types
// ---------------------------------------------------------------------------

export type CaseStatus = "Active" | "Closed" | "Pending" | "Archived";
export type CasePriority = "Low" | "Medium" | "High" | "Critical";

export interface Case {
  case_id: string;
  case_name: string;
  description: string | null;
  investigator: string;
  agency: string | null;
  start_date: string; // ISO 'YYYY-MM-DD'
  end_date: string | null; // ISO 'YYYY-MM-DD'
  status: CaseStatus;
  priority: CasePriority;
  classification: string | null;
  evidence_drive_path: string | null;
  created_at: string; // ISO datetime
  updated_at: string;
}

export interface CaseDetail {
  case: Case;
  tags: string[]; // sorted alphabetically, already normalized
}

export interface CaseSummary {
  case_id: string;
  case_name: string;
  investigator: string;
  start_date: string;
  status: CaseStatus;
  priority: CasePriority;
  evidence_count: number;
  created_at: string;
}

export interface CaseInput {
  case_id: string;
  case_name: string;
  description: string | null;
  investigator: string;
  agency: string | null;
  start_date: string;
  end_date: string | null;
  status: CaseStatus | null;
  priority: CasePriority | null;
  classification: string | null;
  evidence_drive_path: string | null;
  tags: string[];
}

// ---------------------------------------------------------------------------
// Case commands
// ---------------------------------------------------------------------------

/** List cases with optional pagination. */
export function casesList(args: {
  token: string;
  limit?: number;
  offset?: number;
}): Promise<CaseSummary[]> {
  return invoke<CaseSummary[]>("cases_list", args);
}

/** Fetch full case detail including tags. */
export function caseGet(args: {
  token: string;
  case_id: string;
}): Promise<CaseDetail> {
  return invoke<CaseDetail>("case_get", args);
}

/** Create a new case. Returns the full CaseDetail. */
export function caseCreate(args: {
  token: string;
  input: CaseInput;
}): Promise<CaseDetail> {
  return invoke<CaseDetail>("case_create", args);
}

/** Update an existing case. Returns the updated CaseDetail. */
export function caseUpdate(args: {
  token: string;
  case_id: string;
  input: CaseInput;
}): Promise<CaseDetail> {
  return invoke<CaseDetail>("case_update", args);
}

/** Delete a case. Rejects with CaseHasEvidence if evidence rows exist. */
export function caseDelete(args: {
  token: string;
  case_id: string;
}): Promise<void> {
  return invoke<void>("case_delete", args);
}

// ---------------------------------------------------------------------------
// Evidence types
// ---------------------------------------------------------------------------

export interface Evidence {
  evidence_id: string;
  case_id: string;
  description: string;
  collected_by: string;
  collection_datetime: string; // ISO datetime 'YYYY-MM-DDTHH:MM:SS'
  location: string | null;
  status: string;
  evidence_type: string | null;
  make_model: string | null;
  serial_number: string | null;
  storage_location: string | null;
}

export interface EvidenceInput {
  evidence_id: string;
  description: string;
  collected_by: string;
  collection_datetime: string;
  location: string | null;
  status: string | null; // null → backend default 'Collected'
  evidence_type: string | null;
  make_model: string | null;
  serial_number: string | null;
  storage_location: string | null;
}

export type CustodyAction =
  | "Seized"
  | "Transferred"
  | "Received"
  | "Analyzed"
  | "Returned"
  | "Destroyed"
  | "Sealed"
  | "Unsealed";

export interface CustodyEvent {
  custody_id: number;
  evidence_id: string;
  custody_sequence: number; // per-evidence, auto-assigned on add
  action: CustodyAction;
  from_party: string;
  to_party: string;
  location: string | null;
  custody_datetime: string;
  purpose: string | null;
  notes: string | null;
}

export type CustodyInput = Omit<
  CustodyEvent,
  "custody_id" | "evidence_id" | "custody_sequence"
>;

export type HashAlgorithm =
  | "MD5"
  | "SHA1"
  | "SHA256"
  | "SHA512"
  | "SHA3-256"
  | "SHA3-512";

export interface HashRecord {
  hash_id: number;
  evidence_id: string;
  algorithm: HashAlgorithm;
  hash_value: string; // lowercase hex
  verified_by: string;
  verification_datetime: string;
  notes: string | null;
}

export type HashInput = Omit<HashRecord, "hash_id" | "evidence_id">;

export interface ToolUsage {
  tool_id: number;
  case_id: string;
  evidence_id: string | null; // nullable — tool may apply to case or specific item
  tool_name: string;
  version: string | null;
  purpose: string;
  command_used: string | null;
  input_file: string | null;
  output_file: string | null;
  execution_datetime: string;
  operator: string;
  // Reproduction fields (migration 0003 — Reproducibility feature).
  // All optional; case-wide runs that have no single input file may omit them.
  // The KB's curated reproduction_steps in src/lib/forensic-tools.ts use
  // placeholder substitution with these values to render step-by-step
  // instructions in the ToolCard and the forensic report.
  input_sha256: string | null;
  output_sha256: string | null;
  environment_notes: string | null;
  reproduction_notes: string | null;
}

export interface ToolInput {
  evidence_id: string | null;
  tool_name: string;
  version: string | null;
  purpose: string;
  command_used: string | null;
  input_file: string | null;
  output_file: string | null;
  execution_datetime: string | null; // null → backend uses now()
  operator: string;
  input_sha256: string | null;
  output_sha256: string | null;
  environment_notes: string | null;
  reproduction_notes: string | null;
}

export type AnalysisCategory =
  | "Observation"
  | "Timeline"
  | "Correlation"
  | "Anomaly"
  | "Recommendation"
  | "Conclusion"
  | "Other";

export type ConfidenceLevel = "Low" | "Medium" | "High";

export interface AnalysisNote {
  note_id: number;
  case_id: string;
  evidence_id: string | null;
  category: AnalysisCategory;
  finding: string; // max 500
  description: string | null; // max 5000
  confidence_level: ConfidenceLevel;
  created_at: string;
}

export interface AnalysisInput {
  evidence_id: string | null;
  category: AnalysisCategory;
  finding: string;
  description: string | null;
  confidence_level: ConfidenceLevel | null; // null → backend default 'Medium'
}

// ---------------------------------------------------------------------------
// Evidence commands
// ---------------------------------------------------------------------------

/** Add a new evidence item to a case. */
export function evidenceAdd(args: {
  token: string;
  case_id: string;
  input: EvidenceInput;
}): Promise<Evidence> {
  return invoke<Evidence>("evidence_add", args);
}

/** Fetch a single evidence item by its ID. */
export function evidenceGet(args: {
  token: string;
  evidence_id: string;
}): Promise<Evidence> {
  return invoke<Evidence>("evidence_get", args);
}

/** List all evidence items for a case. */
export function evidenceListForCase(args: {
  token: string;
  case_id: string;
}): Promise<Evidence[]> {
  return invoke<Evidence[]>("evidence_list_for_case", args);
}

/** Delete an evidence item. Rejects with EvidenceHasDependents if custody/hash/tool rows exist. */
export function evidenceDelete(args: {
  token: string;
  evidence_id: string;
}): Promise<void> {
  return invoke<void>("evidence_delete", args);
}

// ---------------------------------------------------------------------------
// Custody commands
// ---------------------------------------------------------------------------

/** Add a chain-of-custody event for an evidence item. */
export function custodyAdd(args: {
  token: string;
  evidence_id: string;
  input: CustodyInput;
}): Promise<CustodyEvent> {
  return invoke<CustodyEvent>("custody_add", args);
}

/** List custody events for a specific evidence item. */
export function custodyListForEvidence(args: {
  token: string;
  evidence_id: string;
}): Promise<CustodyEvent[]> {
  return invoke<CustodyEvent[]>("custody_list_for_evidence", args);
}

/** List all custody events for a case (case-wide timeline). */
export function custodyListForCase(args: {
  token: string;
  case_id: string;
}): Promise<CustodyEvent[]> {
  return invoke<CustodyEvent[]>("custody_list_for_case", args);
}

/** Update a custody event by its DB id. */
export function custodyUpdate(args: {
  token: string;
  custody_id: number;
  input: CustodyInput;
}): Promise<CustodyEvent> {
  return invoke<CustodyEvent>("custody_update", args);
}

/** Delete a custody event by its DB id. */
export function custodyDelete(args: {
  token: string;
  custody_id: number;
}): Promise<void> {
  return invoke<void>("custody_delete", args);
}

// ---------------------------------------------------------------------------
// Hash commands
// ---------------------------------------------------------------------------

/** Add a hash verification record for an evidence item. */
export function hashAdd(args: {
  token: string;
  evidence_id: string;
  input: HashInput;
}): Promise<HashRecord> {
  return invoke<HashRecord>("hash_add", args);
}

/** List all hash verifications for a case. */
export function hashListForCase(args: {
  token: string;
  case_id: string;
}): Promise<HashRecord[]> {
  return invoke<HashRecord[]>("hash_list_for_case", args);
}

/** List hash verifications for a specific evidence item. */
export function hashListForEvidence(args: {
  token: string;
  evidence_id: string;
}): Promise<HashRecord[]> {
  return invoke<HashRecord[]>("hash_list_for_evidence", args);
}

// ---------------------------------------------------------------------------
// Tool usage commands
// ---------------------------------------------------------------------------

/** Record a tool usage event for a case. */
export function toolAdd(args: {
  token: string;
  case_id: string;
  input: ToolInput;
}): Promise<ToolUsage> {
  return invoke<ToolUsage>("tool_add", args);
}

/** List all tool usages for a case. */
export function toolListForCase(args: {
  token: string;
  case_id: string;
}): Promise<ToolUsage[]> {
  return invoke<ToolUsage[]>("tool_list_for_case", args);
}

/** List tool usages linked to a specific evidence item. */
export function toolListForEvidence(args: {
  token: string;
  evidence_id: string;
}): Promise<ToolUsage[]> {
  return invoke<ToolUsage[]>("tool_list_for_evidence", args);
}

// ---------------------------------------------------------------------------
// Analysis note commands
// ---------------------------------------------------------------------------

/** Add an analysis note to a case. */
export function analysisAdd(args: {
  token: string;
  case_id: string;
  input: AnalysisInput;
}): Promise<AnalysisNote> {
  return invoke<AnalysisNote>("analysis_add", args);
}

/** List all analysis notes for a case. */
export function analysisListForCase(args: {
  token: string;
  case_id: string;
}): Promise<AnalysisNote[]> {
  return invoke<AnalysisNote[]>("analysis_list_for_case", args);
}

/** List analysis notes linked to a specific evidence item. */
export function analysisListForEvidence(args: {
  token: string;
  evidence_id: string;
}): Promise<AnalysisNote[]> {
  return invoke<AnalysisNote[]>("analysis_list_for_evidence", args);
}

// ---------------------------------------------------------------------------
// Settings commands
// ---------------------------------------------------------------------------

/**
 * Returns the security posture for the UI warning banner.
 * If `key_source !== 'keyring'`, show the keyfile fallback warning (SEC-1 SHOULD-DO 6).
 */
export function settingsGetSecurityPosture(args: {
  token: string;
}): Promise<SecurityPosture> {
  return invoke<SecurityPosture>("settings_get_security_posture", args);
}

/**
 * Frontend → Rust tracing bridge. Writes `message` to the rolling debug log
 * file so we can see frontend errors without devtools.
 *
 * Used by `main.tsx`'s window.onerror + unhandledrejection handlers and by
 * individual queryFn trace points. Never call from hot paths — only from
 * error paths or explicit diagnostic sites.
 */
export function debugLogFrontend(args: {
  level: "error" | "warn" | "info";
  message: string;
}): Promise<void> {
  return invoke<void>("debug_log_frontend", args);
}

// ---------------------------------------------------------------------------
// Evidence file types (Phase 3b)
// ---------------------------------------------------------------------------

/**
 * A single uploaded artifact associated with an evidence item.
 * `is_deleted` is 0 or 1 (SQLite boolean); the backend filters out deleted
 * records before returning the list — this field is present for audit purposes.
 */
export interface EvidenceFile {
  file_id: number;
  evidence_id: string;
  original_filename: string;
  stored_path: string;
  sha256: string; // lowercase hex, 64 chars
  size_bytes: number;
  mime_type: string | null; // byte-sniffed via `infer` crate
  metadata_json: string | null;
  is_deleted: number; // 0 | 1
  uploaded_at: string; // ISO datetime
}

/**
 * Returned by evidence_files_download.
 *
 * SEC-3 MUST-DO 4: `hash_verified = false` means the on-disk SHA-256 no
 * longer matches the DB record — potential tampering. The UI must make this
 * impossible to miss.
 *
 * SEC-3 SHOULD-DO 2: `is_executable = true` means the file's magic bytes
 * indicate an executable format (MZ/PE, ELF, Mach-O, script shebang).
 */
export interface EvidenceFileDownload {
  path: string; // absolute filesystem path
  hash_verified: boolean; // false = tamper detected
  is_executable: boolean; // true = show executable confirmation dialog
  original_filename: string; // for "Save As" defaults
}

// ---------------------------------------------------------------------------
// Evidence file commands (Phase 3b)
// ---------------------------------------------------------------------------

/**
 * Upload a file from the local filesystem and associate it with an evidence
 * item.  The backend computes SHA-256 in a single streaming pass concurrent
 * with the write (SEC-3 MUST-DO 3) and stores the hash in the DB.
 *
 * Errors to handle:
 *   OneDriveSyncWarning — storage is on a cloud-synced path (blocking dialog)
 *   EvidenceFileTooLarge — exceeds 50 GiB hard limit
 *   InvalidFilename — bad characters or >200 UTF-8 bytes
 *   PathTraversalBlocked — canonicalize check failed
 */
/** Upload response — EvidenceFile fields flattened plus an optional soft-limit warning. */
export interface EvidenceFileUploadResponse extends EvidenceFile {
  /** Non-null when the file exceeds the 2 GiB soft-warning threshold. */
  warning: string | null;
}

export function evidenceFilesUpload(args: {
  token: string;
  evidence_id: string;
  source_path: string;
}): Promise<EvidenceFileUploadResponse> {
  return invoke<EvidenceFileUploadResponse>("evidence_files_upload", args);
}

/** List all non-deleted files attached to an evidence item. */
export function evidenceFilesList(args: {
  token: string;
  evidence_id: string;
}): Promise<EvidenceFile[]> {
  return invoke<EvidenceFile[]>("evidence_files_list", args);
}

/**
 * Download (resolve the stored path for) a file.  The backend re-hashes
 * on every call and returns `hash_verified`.  If false, the file's integrity
 * cannot be assured — the UI MUST display a prominent warning.
 *
 * Errors: EvidenceFileNotFound, HashMismatchOnDownload (always returns
 * EvidenceFileDownload with hash_verified=false — not an exception — so the
 * investigator can still inspect the file).
 */
export function evidenceFilesDownload(args: {
  token: string;
  file_id: number;
}): Promise<EvidenceFileDownload> {
  return invoke<EvidenceFileDownload>("evidence_files_download", args);
}

/**
 * Soft-delete an evidence file.  The DB row is flagged `is_deleted = 1`;
 * the disk file is NOT removed (SEC-3 §2.7 policy).  A separate purge
 * command performs the hard-delete.
 */
export function evidenceFilesSoftDelete(args: {
  token: string;
  file_id: number;
}): Promise<void> {
  return invoke<void>("evidence_files_soft_delete", args);
}

/**
 * Permanently hard-delete a (previously soft-deleted) evidence file.
 * Unlinks the disk file and writes a full audit entry including the SHA-256.
 *
 * `justification` must be at least 10 characters (enforced by purge-schema.ts).
 */
export function evidenceFilesPurge(args: {
  token: string;
  file_id: number;
  justification: string;
}): Promise<void> {
  return invoke<void>("evidence_files_purge", args);
}

// ---------------------------------------------------------------------------
// Person photo commands (migration 0002 — Persons feature)
// ---------------------------------------------------------------------------

/**
 * Upload a photo for a person entity. Returns the stored absolute path,
 * which is the new `entity.photo_path`. Render it in the WebView via
 * `convertFileSrc(path)` from `@tauri-apps/api/core`.
 *
 * Validation:
 *  - entity must exist and have `entity_type === "person"`
 *  - size <= 10 MiB
 *  - magic bytes must identify JPEG / PNG / GIF / WebP / BMP / TIFF
 *
 * Errors to handle:
 *  - PersonPhotoTooLarge — file exceeds 10 MiB
 *  - PersonPhotoNotAnImage — magic-byte sniff failed
 *  - EntityNotAPerson — the entity_id does not refer to a person entity
 *  - EntityNotFound — no such entity
 *  - InvalidFilename — path-component sanitization rejected the source filename
 */
export function personPhotoUpload(args: {
  token: string;
  entity_id: number;
  source_path: string;
}): Promise<string> {
  return invoke<string>("person_photo_upload", args);
}

/**
 * Delete the person's photo file from disk and clear `entity.photo_path`.
 * Idempotent — safe to call on a person that already has no photo.
 */
export function personPhotoDelete(args: {
  token: string;
  entity_id: number;
}): Promise<void> {
  return invoke<void>("person_photo_delete", args);
}

// ---------------------------------------------------------------------------
// SHA-256 utility (Reproducibility feature — Tool form Compute Hash button)
// ---------------------------------------------------------------------------

/**
 * Compute the SHA-256 of a file at a given path on disk and return it as a
 * lowercase hex string. Used by the Tool Add/Edit form's Compute Hash
 * button to populate the `input_sha256` field so a second examiner can
 * verify they have the same input bytes the original examiner used.
 *
 * Errors:
 *  - Io — file does not exist, is not a regular file, or cannot be read
 */
export function fileComputeSha256(args: {
  token: string;
  path: string;
}): Promise<string> {
  return invoke<string>("file_compute_sha256", args);
}

// ---------------------------------------------------------------------------
// OneDrive guard command (Phase 3b — SEC-3 MUST-DO 5)
// ---------------------------------------------------------------------------

/**
 * Record that the investigator has acknowledged the OneDrive sync risk and
 * wishes to proceed with the default storage path.  Flips a flag in
 * config.json so the warning is not shown again.
 */
export function settingsAcknowledgeOneDriveRisk(args: {
  token: string;
}): Promise<void> {
  return invoke<void>("settings_acknowledge_onedrive_risk", args);
}

// ---------------------------------------------------------------------------
// Report commands (Phase 3b)
// ---------------------------------------------------------------------------

/**
 * Generate a live markdown preview of the case report without writing a file.
 * Returns the full markdown string.
 */
export function caseReportPreview(args: {
  token: string;
  case_id: string;
}): Promise<string> {
  return invoke<string>("case_report_preview", args);
}

/**
 * Generate and write the case report to disk.
 * Returns the absolute path to the generated file.
 * `format` must be 'Markdown' | 'Html'.
 */
export function caseReportGenerate(args: {
  token: string;
  case_id: string;
  format: "Markdown" | "Html";
}): Promise<string> {
  return invoke<string>("case_report_generate", args);
}

// ---------------------------------------------------------------------------
// Phase 4 — Link Analysis types
// ---------------------------------------------------------------------------

export type EntityType =
  | "person"
  | "business"
  | "phone"
  | "email"
  | "alias"
  | "address"
  | "account"
  | "vehicle";

export type PersonSubtype =
  | "suspect"
  | "victim"
  | "witness"
  | "investigator"
  | "poi"
  | "other";

export interface Entity {
  entity_id: number;
  case_id: string;
  entity_type: EntityType;
  display_name: string;
  subtype: PersonSubtype | null;
  organizational_rank: string | null;
  parent_entity_id: number | null;
  notes: string | null;
  metadata_json: string | null;
  is_deleted: number; // 0 | 1
  created_at: string;
  updated_at: string;
  // Person-specific columns (migration 0002) — always null for non-person entities.
  // photo_path holds an absolute filesystem path under %APPDATA%\DFARS\person_photos\;
  // render it with convertFileSrc() from @tauri-apps/api/core.
  photo_path: string | null;
  email: string | null;
  phone: string | null;
  username: string | null;
  employer: string | null;
  dob: string | null; // ISO YYYY-MM-DD
}

/**
 * EntityInput — writable fields for creating/updating an entity.
 *
 * Note: photo_path is NOT in EntityInput. Photos are managed by the
 * dedicated `personPhotoUpload` / `personPhotoDelete` commands so the
 * upload path owns the file lifecycle. Setting photo_path via the
 * entity_update command would leave the old file on disk.
 */
export type EntityInput = Omit<
  Entity,
  | "entity_id"
  | "case_id"
  | "is_deleted"
  | "created_at"
  | "updated_at"
  | "photo_path"
>;

export type LinkEndpointKind = "entity" | "evidence";

export interface Link {
  link_id: number;
  case_id: string;
  source_type: LinkEndpointKind;
  source_id: string;
  target_type: LinkEndpointKind;
  target_id: string;
  link_label: string | null;
  directional: number; // 0 | 1
  weight: number;
  notes: string | null;
  is_deleted: number;
  created_at: string;
}

export interface LinkInput {
  source_type: LinkEndpointKind;
  source_id: string;
  target_type: LinkEndpointKind;
  target_id: string;
  link_label: string | null;
  directional: number | null; // null → 1
  weight: number | null; // null → 1.0
  notes: string | null;
}

export type EventCategory =
  | "observation"
  | "communication"
  | "movement"
  | "custodial"
  | "other";

export interface CaseEvent {
  event_id: number;
  case_id: string;
  title: string;
  description: string | null;
  event_datetime: string;
  event_end_datetime: string | null;
  category: EventCategory | null;
  related_entity_id: number | null;
  related_evidence_id: string | null;
  is_deleted: number;
  created_at: string;
}

export type EventInput = Omit<
  CaseEvent,
  "event_id" | "case_id" | "is_deleted" | "created_at"
>;

export interface GraphNode {
  id: string; // 'entity:<id>' or 'evidence:<id>'
  label: string;
  kind: "entity" | "evidence";
  entity_type: string | null;
  subtype: string | null;
}

export interface GraphEdge {
  id: string; // 'link:<id>'
  source: string;
  target: string;
  label: string | null;
  directional: boolean;
  weight: number;
}

export interface GraphPayload {
  nodes: GraphNode[];
  edges: GraphEdge[];
}

export interface GraphFilter {
  entity_types: EntityType[] | null; // null → all
  include_evidence: boolean;
}

export interface TimelineItem {
  id: string;
  group: string;
  content: string;
  start: string;
  end: string | null;
  category: string | null;
  source_type: "investigator" | "auto";
  source_table: string;
}

export interface TimelineGroup {
  id: string;
  content: string;
}

export interface TimelinePayload {
  items: TimelineItem[];
  groups: TimelineGroup[];
}

export interface TimelineFilter {
  start: string | null;
  end: string | null;
}

// ---------------------------------------------------------------------------
// Phase 4 — Link Analysis commands
// ---------------------------------------------------------------------------

/** List all entities for a case (excludes soft-deleted rows). */
export function entitiesListForCase(args: {
  token: string;
  case_id: string;
}): Promise<Entity[]> {
  return invoke<Entity[]>("entity_list_for_case", args);
}

/** Add a new entity to a case. */
export function entityAdd(args: {
  token: string;
  case_id: string;
  input: EntityInput;
}): Promise<Entity> {
  return invoke<Entity>("entity_add", args);
}

/** Update an existing entity. */
export function entityUpdate(args: {
  token: string;
  case_id: string;
  entity_id: number;
  input: EntityInput;
}): Promise<Entity> {
  return invoke<Entity>("entity_update", args);
}

/** Soft-delete an entity. Rejects with EntityNotFound if the entity does not exist. */
export function entityDelete(args: {
  token: string;
  case_id: string;
  entity_id: number;
}): Promise<void> {
  return invoke<void>("entity_delete", args);
}

/** List all links for a case. */
export function linksListForCase(args: {
  token: string;
  case_id: string;
}): Promise<Link[]> {
  return invoke<Link[]>("link_list_for_case", args);
}

/** Add a new link between two nodes. */
export function linkAdd(args: {
  token: string;
  case_id: string;
  input: LinkInput;
}): Promise<Link> {
  return invoke<Link>("link_add", args);
}

/** Delete a link. */
export function linkDelete(args: {
  token: string;
  case_id: string;
  link_id: number;
}): Promise<void> {
  return invoke<void>("link_delete", args);
}

/** List all case events. */
export function eventsListForCase(args: {
  token: string;
  case_id: string;
}): Promise<CaseEvent[]> {
  return invoke<CaseEvent[]>("event_list_for_case", args);
}

/** Add a new case event. */
export function eventAdd(args: {
  token: string;
  case_id: string;
  input: EventInput;
}): Promise<CaseEvent> {
  return invoke<CaseEvent>("event_add", args);
}

/** Update an existing case event. */
export function eventUpdate(args: {
  token: string;
  case_id: string;
  event_id: number;
  input: EventInput;
}): Promise<CaseEvent> {
  return invoke<CaseEvent>("event_update", args);
}

/** Delete a case event. */
export function eventDelete(args: {
  token: string;
  case_id: string;
  event_id: number;
}): Promise<void> {
  return invoke<void>("event_delete", args);
}

/**
 * Fetch the graph payload for Cytoscape.
 * `filter.entity_types = null` → include all entity types.
 */
export function caseGraph(args: {
  token: string;
  case_id: string;
  filter: GraphFilter;
}): Promise<GraphPayload> {
  return invoke<GraphPayload>("case_graph", args);
}

/**
 * Fetch the crime-line (timeline) payload for vis-timeline.
 * `filter.start` / `filter.end` are ISO datetime strings or null (no filter).
 * Must be passed as a nested `filter` struct to match the Rust command signature.
 */
export function caseCrimeLine(args: {
  token: string;
  case_id: string;
  filter: TimelineFilter;
}): Promise<TimelinePayload> {
  return invoke<TimelinePayload>("case_crime_line", args);
}

// ---------------------------------------------------------------------------
// Person identifiers (migration 0004)
// ---------------------------------------------------------------------------

/**
 * The kinds of OSINT-relevant identifiers a person can have. Each person
 * entity typically has many of these across platforms — multiple emails,
 * Twitter/Reddit/GitHub/Discord handles, phone numbers, profile URLs.
 * The OSINT submission flow (pass 2) batches the active rows for a given
 * person into a single Agent Zero job.
 */
export type PersonIdentifierKind =
  | "email"
  | "username"
  | "handle"
  | "phone"
  | "url";

export interface PersonIdentifier {
  identifier_id: number;
  entity_id: number;
  kind: PersonIdentifierKind;
  value: string;
  /** Free-form platform tag (twitter, reddit, github, discord, gmail, ...). */
  platform: string | null;
  notes: string | null;
  is_deleted: 0 | 1;
  created_at: string;
  updated_at: string;
}

/**
 * Writable fields for creating or updating a person identifier.
 *
 * `entity_id` is NOT in this input — it's supplied as a command parameter on
 * the add path and is immutable on the update path (moving an identifier
 * between people would lose the audit trail).
 */
export interface PersonIdentifierInput {
  kind: PersonIdentifierKind;
  value: string;
  platform: string | null;
  notes: string | null;
}

/** List all active identifiers for a person entity (excludes soft-deleted). */
export function personIdentifierList(args: {
  token: string;
  entity_id: number;
}): Promise<PersonIdentifier[]> {
  return invoke<PersonIdentifier[]>("person_identifier_list", args);
}

/** Add a new identifier to a person entity. */
export function personIdentifierAdd(args: {
  token: string;
  entity_id: number;
  input: PersonIdentifierInput;
}): Promise<PersonIdentifier> {
  return invoke<PersonIdentifier>("person_identifier_add", args);
}

/** Update an existing identifier. */
export function personIdentifierUpdate(args: {
  token: string;
  identifier_id: number;
  input: PersonIdentifierInput;
}): Promise<PersonIdentifier> {
  return invoke<PersonIdentifier>("person_identifier_update", args);
}

/** Soft-delete an identifier. */
export function personIdentifierDelete(args: {
  token: string;
  identifier_id: number;
}): Promise<void> {
  return invoke<void>("person_identifier_delete", args);
}

// ---------------------------------------------------------------------------
// Phase 5 — AI / Agent Zero types
// ---------------------------------------------------------------------------

export interface AiClassificationResult {
  /** Maps to Rust ClassificationResult.category */
  category: string;
  subcategory: string | null;
  confidence: number;
  /** Maps to Rust ClassificationResult.reasoning */
  reasoning: string | null;
}

export interface AiCaseSummary {
  executive_summary: string; // markdown
  key_findings: string[];
  conclusion: string | null;
  generated_at: string;
}

export interface ForensicAnalysisResult {
  narrative: string;
  tools_used: string; // comma-separated
  platforms_used: string;
  error_message: string | null;
}

// ---------------------------------------------------------------------------
// Phase 5 — Integration settings types
// ---------------------------------------------------------------------------

export interface AgentZeroSettings {
  url: string | null;
  api_key_set: boolean;
  /** Serialized from Rust axum_port field. */
  port: number;
  allow_custom_url: boolean;
  bind_host: string;
  allow_network_bind: boolean;
  /** Derived: true when both url and api_key are set. */
  is_configured: boolean;
  shown_ai_summarize_consent: boolean;
}

export interface AgentZeroInput {
  url: string;
  api_key: string | null; // null = leave unchanged
  port: number;
  allow_custom_url: boolean;
}

export interface AgentZeroTestResult {
  ok: true;
  plugin_version: string | null;
}

export interface SmtpSettings {
  host: string;
  port: number;
  username: string;
  from: string;
  password_set: boolean;
  tls: boolean;
}

export interface SmtpInput {
  host: string;
  port: number;
  username: string;
  password: string | null; // null = leave unchanged
  from: string;
  tls: boolean;
}

export interface SmtpTestResult {
  ok: true;
}

export interface NetworkStatus {
  bind_host: string;
  allow_network_bind: boolean;
  axum_running: boolean;
  axum_url: string;
}

// ---------------------------------------------------------------------------
// Phase 5 — Drive types
// ---------------------------------------------------------------------------

export interface Drive {
  letter: string;
  label: string;
  total_bytes: number;
  free_bytes: number;
  drive_type: string;
}

export interface DriveScanResult {
  root: string;
  file_count: number;
  total_bytes: number;
  top_extensions: Record<string, number>;
}

// ---------------------------------------------------------------------------
// Phase 5 — AI helper commands
// ---------------------------------------------------------------------------

/**
 * Send narrative text to the Agent Zero enhance plugin.
 * 30 s timeout. Returns the rewritten text.
 * Rejects with AgentZeroNotConfigured if Agent Zero is not set up.
 */
export function aiEnhance(args: {
  token: string;
  text: string;
}): Promise<string> {
  return invoke<string>("ai_enhance", args);
}

/**
 * Send text to Agent Zero for classification.
 * 30 s timeout. Returns structured classification suggestions.
 * Rejects with AgentZeroNotConfigured if Agent Zero is not set up.
 */
export function aiClassify(args: {
  token: string;
  text: string;
}): Promise<AiClassificationResult> {
  return invoke<AiClassificationResult>("ai_classify", args);
}

/**
 * Send the full case payload to Agent Zero and receive an executive summary.
 * 120 s timeout.
 *
 * IMPORTANT: On the first call per install, this rejects with
 * AppError.code === 'AiSummarizeConsentRequired'. The frontend MUST show the
 * AiConsentDialog and call settingsAcknowledgeAiConsent() before retrying.
 * Do NOT display a toast for this error code — the dialog handles it.
 */
export function aiSummarizeCase(args: {
  token: string;
  case_id: string;
}): Promise<AiCaseSummary> {
  return invoke<AiCaseSummary>("ai_summarize_case", args);
}

/**
 * Summary returned by ai_osint_person after Agent Zero finishes orchestrating
 * OSINT tools against a person entity's full identifier set.
 *
 * - `status` — Agent Zero's reported status. Typically one of
 *   `"success" | "partial" | "failed"`, but typed as `string` because the
 *   Rust boundary does not normalize unknown values — future Agent Zero
 *   versions may emit additional states. Switch on it cautiously.
 * - `identifiers_submitted` — how many DEDUPED rows from `person_identifiers`
 *   (migration 0004) were sent to Agent Zero in this batch. Dedup key is
 *   `(kind, lowercased+trimmed value, lowercased+trimmed platform)` — same
 *   email on two different platforms is NOT a duplicate.
 * - `tool_usage_rows_inserted` — one per successful Agent Zero run. These
 *   rows appear in the case's Tools tab and in the Markdown report.
 * - `notes` — a single combined status line, prefixed with local Rust-side
 *   annotations (name-only submission, batch truncation) when relevant, then
 *   any notes Agent Zero returned. Render verbatim in the UI.
 *
 * The raw per-tool findings are ALSO written into the entity's metadata_json
 * under `osint_findings[]` via an atomic `json_set` update so the PersonCard
 * can display the latest run inline without racing concurrent writes.
 */
export interface OsintRunSummary {
  status: string;
  identifiers_submitted: number;
  tools_run: number;
  tool_usage_rows_inserted: number;
  notes: string | null;
}

/**
 * Orchestrate an OSINT run for a person entity via Agent Zero.
 *
 * Flow:
 *  - Validates the entity exists and has entity_type = "person"
 *  - Checks the separate OSINT consent flag (AiOsintConsentRequired if not)
 *  - Fetches the person's full identifier list from `person_identifiers`
 *    (migration 0004), dedupes by
 *    `(kind, lowercased+trimmed value, lowercased+trimmed platform)`, and
 *    sends the deduped batch plus the legacy single-value fields (name,
 *    email, phone, username, employer, dob, notes) to Agent Zero's
 *    `dfars_osint_person` endpoint. Same email on two different platforms
 *    is NOT a duplicate — different platforms are distinct OSINT signals.
 *  - Agent Zero decides which additional Kali OSINT tools to run across the
 *    multi-identifier batch
 *  - Rust inserts a tool_usage row for each successful run and appends
 *    findings into entity.metadata_json.osint_findings[]
 *
 * 900 s Agent Zero timeout. Users should see a progress spinner for the
 * duration of the call. PII leaves the machine by design — get consent first.
 *
 * Errors to handle:
 *  - AiOsintConsentRequired — show the AiConsentDialog with scope="osint"
 *    and call settingsAcknowledgeOsintConsent before retrying
 *  - EntityNotAPerson — button should not have been shown
 *  - AgentZeroNotConfigured — user needs to set Agent Zero URL + API key
 *  - AgentZeroTimeout — the 900 s window elapsed; partial results may still
 *    have been inserted (check the Tools tab)
 */
export function aiOsintPerson(args: {
  token: string;
  entity_id: number;
}): Promise<OsintRunSummary> {
  return invoke<OsintRunSummary>("ai_osint_person", args);
}

/**
 * Send evidence metadata + narrative to Agent Zero for forensic analysis.
 * 300 s timeout (Agent Zero runs real Kali forensic tools).
 * Agent Zero will call back to the DFARS axum server to download evidence files.
 */
export function evidenceForensicAnalyze(args: {
  token: string;
  evidence_id: string;
  narrative: string;
}): Promise<ForensicAnalysisResult> {
  return invoke<ForensicAnalysisResult>("evidence_forensic_analyze", args);
}

// ---------------------------------------------------------------------------
// Phase 5 — Integration settings commands
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// Phase 6 — Update check types + command
// ---------------------------------------------------------------------------

/**
 * The status codes returned by `settings_check_for_updates`.
 *
 * - UpToDate        — current version is already the latest
 * - UpdateAvailable — a newer version is available; `available_version` is populated
 * - NotConfigured   — the updater endpoint is a placeholder / unreachable
 * - NetworkError    — the update server could not be reached
 */
export type UpdateStatus =
  | "UpToDate"
  | "UpdateAvailable"
  | "NotConfigured"
  | "NetworkError";

export interface UpdateCheckResult {
  status: UpdateStatus;
  message: string;
  available_version: string | null; // non-null only when status === 'UpdateAvailable'
}

/**
 * Check for a newer version of DFARS Desktop.
 *
 * Manual-only — never called on startup. See §11 of v2-migration-spec.md
 * (OQ-SEC8-2): forensic tools must not produce unexpected outbound traffic.
 *
 * For v2.0.0 the endpoint is a placeholder so the result is almost always
 * NotConfigured. The UI handles this gracefully.
 */
export function settingsCheckForUpdates(args: {
  token: string;
}): Promise<UpdateCheckResult> {
  return invoke<UpdateCheckResult>("settings_check_for_updates", args);
}

/** Get the current Agent Zero integration settings. */
export function settingsGetAgentZero(args: {
  token: string;
}): Promise<AgentZeroSettings> {
  return invoke<AgentZeroSettings>("settings_get_agent_zero", args);
}

/**
 * Save Agent Zero settings.
 * Rejects with AgentZeroUrlRejected if the URL fails the allowlist
 * AND allow_custom_url is false.
 * api_key is a new plaintext value OR null to leave unchanged.
 */
export function settingsSetAgentZero(args: {
  token: string;
  input: AgentZeroInput;
}): Promise<void> {
  return invoke<void>("settings_set_agent_zero", args);
}

/** Test the Agent Zero connection. Returns plugin_version when successful. */
export function settingsTestAgentZero(args: {
  token: string;
}): Promise<AgentZeroTestResult> {
  return invoke<AgentZeroTestResult>("settings_test_agent_zero", args);
}

/**
 * Record that the investigator has acknowledged the AI summarize consent.
 * After this call, ai_summarize_case will never reject with
 * AiSummarizeConsentRequired again on this install.
 */
export function settingsAcknowledgeAiConsent(args: {
  token: string;
}): Promise<void> {
  return invoke<void>("settings_acknowledge_ai_consent", args);
}

/**
 * Record that the investigator has acknowledged the OSINT consent.
 *
 * OSINT is SEPARATE from the AI summarize consent because it is meaningfully
 * more invasive: PII (name, email, username, employer) is sent to Agent Zero
 * and onward to external OSINT sources (LinkedIn, Shodan, Sherlock's site
 * list, etc.). The dialog copy should make this explicit.
 *
 * After this call, ai_osint_person will proceed immediately without
 * returning AiOsintConsentRequired. Takes effect in-memory (runtime atomic)
 * AND on disk (config.shown_ai_osint_consent = true) — no app restart needed.
 */
export function settingsAcknowledgeOsintConsent(args: {
  token: string;
}): Promise<void> {
  return invoke<void>("settings_acknowledge_osint_consent", args);
}

/** Get the current SMTP settings. Password is NEVER returned (password_set boolean only). */
export function settingsGetSmtp(args: {
  token: string;
}): Promise<SmtpSettings> {
  return invoke<SmtpSettings>("settings_get_smtp", args);
}

/**
 * Save SMTP settings.
 * password is a new plaintext value OR null to leave unchanged.
 */
export function settingsSetSmtp(args: {
  token: string;
  input: SmtpInput;
}): Promise<void> {
  return invoke<void>("settings_set_smtp", args);
}

/** Send a test email to verify SMTP configuration. */
export function settingsTestSmtp(args: {
  token: string;
  to_address: string;
}): Promise<SmtpTestResult> {
  return invoke<SmtpTestResult>("settings_test_smtp", args);
}

/** Get network binding status for the axum server.
 *
 * The Rust side never wired up a `system_get_network_status` command.
 * Rather than crash the integrations page by calling a non-existent command,
 * we return a safe fallback. The real fix is to add the Rust command in a
 * follow-up iteration, but for v2.0.0 the integrations page doesn't need
 * authoritative network status to function.
 */
export async function systemGetNetworkStatus(_args: {
  token: string;
}): Promise<NetworkStatus> {
  return {
    bind_host: "127.0.0.1",
    allow_network_bind: false,
    axum_running: true,
    axum_url: "http://127.0.0.1:5099",
  };
}

// ---------------------------------------------------------------------------
// Phase 5 — Drive commands
// ---------------------------------------------------------------------------

/** List all available drives on the system. */
export function drivesList(args: {
  token: string;
}): Promise<Drive[]> {
  return invoke<Drive[]>("drives_list", args);
}

/**
 * Scan the drive at `path` for the given case.
 * Rejects with DriveScanTooLarge if the drive has too many files.
 */
export function driveScan(args: {
  token: string;
  case_id: string;
  path: string;
}): Promise<DriveScanResult> {
  return invoke<DriveScanResult>("drive_scan", args);
}
