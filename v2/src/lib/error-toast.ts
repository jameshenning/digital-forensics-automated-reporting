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
  Db: "A database error occurred. Please try again.",
  Crypto:
    "A cryptographic error occurred. Your encryption key may be unavailable.",
  Keyring: "Could not access the Windows Credential Manager.",
  Io: "A file I/O error occurred.",
  Internal: "An unexpected internal error occurred.",
};

/**
 * Show an error toast for an AppError.
 * If `err` is not shaped like an AppError, shows a generic message.
 */
export function toastError(err: unknown): void {
  const appErr = err as Partial<AppError>;

  if (appErr?.code && appErr.code in ERROR_MESSAGES) {
    let msg = ERROR_MESSAGES[appErr.code];

    // Augment the lockout message with the countdown if available
    if (appErr.code === "AccountLocked" && appErr.seconds_remaining) {
      const mins = Math.floor(appErr.seconds_remaining / 60);
      const secs = appErr.seconds_remaining % 60;
      msg = mins > 0
        ? `Account locked for ${mins}m ${secs}s. Please try again later.`
        : `Account locked for ${secs}s. Please try again later.`;
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
