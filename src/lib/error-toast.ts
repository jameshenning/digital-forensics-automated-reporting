/**
 * Maps AppError.code to human-readable toast messages.
 *
 * Used by every form submit handler.  Import `toastError` and call it
 * inside the catch block of any Tauri command invocation.
 */

import { toast } from "sonner";
import type { AppError, AppErrorCode } from "@/lib/bindings";

const ERROR_MESSAGES: Record<AppErrorCode, string> = {
  Unauthorized: "Your session has expired. Please sign in again.",
  InvalidCredentials: "Incorrect username or password.",
  AccountLocked:
    "This account is temporarily locked due to too many failed attempts.",
  MfaRequired: "Multi-factor authentication is required.",
  InvalidMfaCode:
    "That code was not recognised. Check your authenticator app and try again.",
  NoRecoveryCodesRemaining:
    "All recovery codes have been used. Contact your administrator.",
  UserAlreadyExists:
    "An account already exists. Please sign in instead.",
  UserNotFound: "User not found.",
  PasswordPolicy:
    "Password does not meet the policy requirements (minimum 12 characters).",
  CaseNotFound: "Case not found. It may have been deleted.",
  CaseAlreadyExists:
    "A case with that ID already exists. Choose a different Case ID.",
  CaseHasEvidence:
    "This case cannot be deleted because it has linked evidence items. " +
    "Removing evidence is not supported in Phase 2 — handle evidence items first.",
  EvidenceNotFound: "Evidence item not found. It may have been deleted.",
  EvidenceAlreadyExists:
    "An evidence item with that ID already exists on this case. Choose a different Evidence ID.",
  EvidenceHasDependents:
    "This evidence item has custody events, hashes, or tool records and cannot be deleted. " +
    "Remove them first.",
  CustodyNotFound: "Custody event not found. It may have been deleted.",
  HashNotFound: "Hash verification record not found.",
  ValidationError:
    "One or more fields contain invalid values. Please review the form and correct any errors.",
  Db: "A database error occurred. Please try again.",
  Crypto:
    "A cryptographic error occurred. Your encryption key may be unavailable.",
  Keyring: "Could not access the Windows Credential Manager.",
  Io: "A file I/O error occurred.",
  Internal: "An unexpected internal error occurred.",
  // Phase 3b — evidence file + report error codes
  EvidenceFileNotFound:
    "Evidence file not found. It may have been deleted or purged.",
  EvidenceFileTooLarge:
    "File exceeds the 50 GiB upload limit. Use a smaller file or increase the limit in settings.",
  InvalidFilename:
    "The filename contains invalid characters, a path separator, or exceeds 200 characters. Rename the file and try again.",
  PathTraversalBlocked:
    "Upload rejected: the resolved file path is outside the permitted storage root. This may indicate a security issue.",
  OneDriveSyncWarning:
    "See dialog.", // The blocking OneDriveWarningDialog handles this — toast is supplemental only
  HashMismatchOnDownload:
    "INTEGRITY FAILURE: This file does not match its original SHA-256 hash. " +
    "Do not rely on it as evidence until a source reacquisition is performed.",
  // Persons — photo upload (migration 0002)
  PersonPhotoTooLarge:
    "Photo exceeds the 10 MiB limit. Please pick a smaller image.",
  PersonPhotoNotAnImage:
    "The selected file is not a recognized image (JPEG, PNG, GIF, WebP, BMP, or TIFF). Pick a different file.",
  EntityNotAPerson:
    "This entity is not a person, so a photo cannot be attached. Photos are only supported on person entities.",
  AiOsintConsentRequired:
    "See dialog.", // The AiConsentDialog with scope='osint' handles this — toast is supplemental only
  ReportGenerationFailed:
    "Report generation failed. Check that all required case data is present and try again.",
  // Phase 4 — link analysis error codes
  EntityNotFound:
    "Entity not found. It may have been deleted.",
  EntityCycle:
    "This parent assignment would create a circular parent-child cycle in the entity hierarchy. " +
    "An entity cannot be its own ancestor. Choose a different parent entity.",
  LinkNotFound:
    "Link not found. It may have been deleted.",
  LinkEndpointMissing:
    "One or both link endpoints no longer exist. Check that the source and target entities or evidence items are still present.",
  EventNotFound:
    "Case event not found. It may have been deleted.",
  // Phase 5 — AI + integration + drive error codes
  NetworkBindRefused:
    "The DFARS internal server could not bind to the requested address. " +
    "Another process may be using the port. Check Settings > Integrations for guidance.",
  AgentZeroUrlRejected:
    "The Agent Zero URL is not in the allowed list (localhost, 127.0.0.1, host.docker.internal). " +
    "Enable 'Allow custom URL' in Settings > Integrations to override.",
  AgentZeroNotConfigured:
    "Agent Zero is not configured. Go to Settings > Integrations to set up your Agent Zero URL and API key.",
  AgentZeroTimeout:
    "Agent Zero did not respond in time. Check that the Agent Zero container is running and try again.",
  AgentZeroServerError:
    "Agent Zero returned an error response. Check the Agent Zero container logs for details.",
  PayloadTooLarge:
    "The response from Agent Zero was too large to process. This is unexpected — check Agent Zero for misconfigured output.",
  AiSummarizeConsentRequired:
    // NOT shown as a toast — triggers the AiConsentDialog instead.
    // This string is a fallback only if toastError is somehow called directly.
    "Consent required before sending case data to Agent Zero. See the consent dialog.",
  SmtpConnectFailed:
    "Could not connect to the SMTP server. Check the host, port, and TLS settings in Settings > Integrations.",
  SmtpSendFailed:
    "The SMTP server accepted the connection but rejected the message. Check your username, password, and 'from' address.",
  DriveScanTooLarge:
    "The drive has too many files to scan in a single operation. Try scanning a specific subdirectory instead.",
};

/**
 * Show an error toast for an AppError.
 * If `err` is not shaped like an AppError, shows a generic message.
 */
/**
 * Returns a sentinel value instead of toasting for error codes that must be
 * handled by a dedicated dialog rather than a toast notification.
 *
 * Currently: 'AiSummarizeConsentRequired' — the caller must show the
 * AiConsentDialog instead.
 */
export const DIALOG_HANDLED_CODES = new Set<AppErrorCode>([
  "AiSummarizeConsentRequired",
]);

export function toastError(err: unknown): void {
  const appErr = err as Partial<AppError>;

  if (appErr?.code && appErr.code in ERROR_MESSAGES) {
    // AiSummarizeConsentRequired must NOT show a toast — the dialog handles it.
    if (appErr.code === "AiSummarizeConsentRequired") return;

    let msg = ERROR_MESSAGES[appErr.code];

    // Augment the lockout message with the countdown if available
    if (appErr.code === "AccountLocked" && appErr.seconds_remaining) {
      const mins = Math.floor(appErr.seconds_remaining / 60);
      const secs = appErr.seconds_remaining % 60;
      msg = mins > 0
        ? `Account locked for ${mins}m ${secs}s. Please try again later.`
        : `Account locked for ${secs}s. Please try again later.`;
    }

    // Augment Agent Zero timeout with the duration if available
    if (appErr.code === "AgentZeroTimeout" && appErr.seconds_remaining) {
      msg = `Agent Zero did not respond within ${appErr.seconds_remaining} seconds. Check that the Agent Zero container is running and try again.`;
    }

    // Augment drive scan error with file count if available
    if (appErr.code === "DriveScanTooLarge" && appErr.seconds_remaining) {
      msg = `The drive has ${appErr.seconds_remaining}+ files, which is too many to scan in one operation. Try a specific subdirectory.`;
    }

    toast.error(msg);
  } else {
    const detail =
      typeof appErr?.message === "string" ? appErr.message : String(err);
    toast.error(`Error: ${detail}`);
  }
}

/** Show a success toast. */
export function toastSuccess(message: string): void {
  toast.success(message);
}
