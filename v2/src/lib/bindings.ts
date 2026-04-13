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
  | "ValidationError"
  | "Db"
  | "Crypto"
  | "Keyring"
  | "Io"
  | "Internal";

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
