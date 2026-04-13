/**
 * Tests for `toastError` / error-toast.ts mapping.
 *
 * Deliverable 12: every AppError.code must map to a non-empty human message.
 * The `toast` function from "sonner" is mocked — we verify the mapped message
 * is passed through, not that the DOM shows a toast.
 */
import { describe, it, expect, vi, beforeEach } from "vitest";

// Mock sonner before importing the module under test.
vi.mock("sonner", () => ({
  toast: {
    error: vi.fn(),
    success: vi.fn(),
  },
}));

import { toast } from "sonner";
import { toastError, toastSuccess } from "@/lib/error-toast";
import type { AppErrorCode } from "@/lib/bindings";

const ERROR_CODES: AppErrorCode[] = [
  "Unauthorized",
  "InvalidCredentials",
  "AccountLocked",
  "MfaRequired",
  "InvalidMfaCode",
  "NoRecoveryCodesRemaining",
  "UserAlreadyExists",
  "UserNotFound",
  "PasswordPolicy",
  "Db",
  "Crypto",
  "Keyring",
  "Io",
  "Internal",
];

describe("toastError", () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it.each(ERROR_CODES)(
    "maps code '%s' to a non-empty human-readable message",
    (code) => {
      toastError({ code, message: "raw backend detail" });
      expect(toast.error).toHaveBeenCalledOnce();
      const calledWith = vi.mocked(toast.error).mock.calls[0][0] as string;
      expect(typeof calledWith).toBe("string");
      expect(calledWith.length).toBeGreaterThan(0);
      // Must not leak the raw internal error code as the user-facing message.
      expect(calledWith).not.toBe(code);
    }
  );

  it("augments AccountLocked message with countdown when seconds_remaining is present", () => {
    toastError({ code: "AccountLocked", message: "", seconds_remaining: 125 });
    const msg = vi.mocked(toast.error).mock.calls[0][0] as string;
    // 125s = 2m 5s — the message should mention minutes or seconds.
    expect(msg).toMatch(/\d+/); // at minimum some number appears
    expect(msg.toLowerCase()).toMatch(/lock|minute|second/);
  });

  it("augments AccountLocked message for sub-60s remaining", () => {
    toastError({ code: "AccountLocked", message: "", seconds_remaining: 45 });
    const msg = vi.mocked(toast.error).mock.calls[0][0] as string;
    expect(msg).toMatch(/45/); // 45 seconds should appear in the message
  });

  it("falls back to a generic message for unknown error shape", () => {
    toastError({ unknown: "field", arbitrary: true });
    expect(toast.error).toHaveBeenCalledOnce();
    const msg = vi.mocked(toast.error).mock.calls[0][0] as string;
    expect(msg.length).toBeGreaterThan(0);
  });

  it("handles null gracefully", () => {
    toastError(null);
    expect(toast.error).toHaveBeenCalledOnce();
  });

  it("handles a plain string error", () => {
    toastError("something exploded");
    expect(toast.error).toHaveBeenCalledOnce();
  });
});

describe("toastSuccess", () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it("passes the message to toast.success", () => {
    toastSuccess("Operation completed.");
    expect(toast.success).toHaveBeenCalledWith("Operation completed.");
  });
});
