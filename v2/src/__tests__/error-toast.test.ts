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
  "CaseNotFound",
  "CaseAlreadyExists",
  "CaseHasEvidence",
  "EvidenceNotFound",
  "EvidenceAlreadyExists",
  "EvidenceHasDependents",
  "CustodyNotFound",
  "HashNotFound",
  "ValidationError",
  "Db",
  "Crypto",
  "Keyring",
  "Io",
  "Internal",
  // Phase 3b additions
  "EvidenceFileNotFound",
  "EvidenceFileTooLarge",
  "InvalidFilename",
  "PathTraversalBlocked",
  "OneDriveSyncWarning",
  "HashMismatchOnDownload",
  "ReportGenerationFailed",
  // Phase 4 additions
  "EntityNotFound",
  "EntityCycle",
  "LinkNotFound",
  "LinkEndpointMissing",
  "EventNotFound",
  // Phase 5 additions (excluding AiSummarizeConsentRequired — handled by dialog, not toast)
  "NetworkBindRefused",
  "AgentZeroUrlRejected",
  "AgentZeroNotConfigured",
  "AgentZeroTimeout",
  "AgentZeroServerError",
  "PayloadTooLarge",
  "SmtpConnectFailed",
  "SmtpSendFailed",
  "DriveScanTooLarge",
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

// ---------------------------------------------------------------------------
// Case-specific error code messages (Phase 2 additions)
// ---------------------------------------------------------------------------

describe("case error codes — message content", () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it("CaseNotFound message mentions 'not found'", () => {
    toastError({ code: "CaseNotFound", message: "" });
    const msg = vi.mocked(toast.error).mock.calls[0][0] as string;
    expect(msg.toLowerCase()).toMatch(/not found/);
  });

  it("CaseAlreadyExists message mentions 'already exists' or 'ID'", () => {
    toastError({ code: "CaseAlreadyExists", message: "" });
    const msg = vi.mocked(toast.error).mock.calls[0][0] as string;
    expect(msg.toLowerCase()).toMatch(/already exists|case id/i);
  });

  it("CaseHasEvidence message explicitly mentions evidence destruction", () => {
    toastError({ code: "CaseHasEvidence", message: "" });
    const msg = vi.mocked(toast.error).mock.calls[0][0] as string;
    // Must not silently say "an error occurred" — must explain the evidence constraint
    expect(msg.toLowerCase()).toMatch(/evidence/);
    expect(msg.toLowerCase()).toMatch(/cannot be deleted|evidence items/i);
  });

  it("CaseHasEvidence message is longer than 50 characters (substantive)", () => {
    toastError({ code: "CaseHasEvidence", message: "" });
    const msg = vi.mocked(toast.error).mock.calls[0][0] as string;
    expect(msg.length).toBeGreaterThan(50);
  });

  it("ValidationError message mentions 'invalid' or 'values'", () => {
    toastError({ code: "ValidationError", message: "" });
    const msg = vi.mocked(toast.error).mock.calls[0][0] as string;
    expect(msg.toLowerCase()).toMatch(/invalid|values|fields/);
  });
});

// ---------------------------------------------------------------------------
// Phase 3a evidence error code messages
// ---------------------------------------------------------------------------

describe("evidence error codes — message content", () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it("EvidenceNotFound message mentions 'not found'", () => {
    toastError({ code: "EvidenceNotFound", message: "" });
    const msg = vi.mocked(toast.error).mock.calls[0][0] as string;
    expect(msg.toLowerCase()).toMatch(/not found/);
  });

  it("EvidenceAlreadyExists message mentions 'already exists' or 'Evidence ID'", () => {
    toastError({ code: "EvidenceAlreadyExists", message: "" });
    const msg = vi.mocked(toast.error).mock.calls[0][0] as string;
    expect(msg.toLowerCase()).toMatch(/already exists|evidence id/i);
  });

  it("EvidenceHasDependents message names the dependents explicitly", () => {
    toastError({ code: "EvidenceHasDependents", message: "" });
    const msg = vi.mocked(toast.error).mock.calls[0][0] as string;
    // Must name what the dependents are, not just say "cannot be deleted"
    expect(msg.toLowerCase()).toMatch(/custody|hash|tool/);
  });

  it("EvidenceHasDependents message instructs user to remove them first", () => {
    toastError({ code: "EvidenceHasDependents", message: "" });
    const msg = vi.mocked(toast.error).mock.calls[0][0] as string;
    expect(msg.toLowerCase()).toMatch(/remove|first|delete/);
  });

  it("EvidenceHasDependents message is longer than 50 characters (substantive)", () => {
    toastError({ code: "EvidenceHasDependents", message: "" });
    const msg = vi.mocked(toast.error).mock.calls[0][0] as string;
    expect(msg.length).toBeGreaterThan(50);
  });

  it("CustodyNotFound message mentions 'not found'", () => {
    toastError({ code: "CustodyNotFound", message: "" });
    const msg = vi.mocked(toast.error).mock.calls[0][0] as string;
    expect(msg.toLowerCase()).toMatch(/not found/);
  });

  it("HashNotFound message mentions 'not found' or 'hash'", () => {
    toastError({ code: "HashNotFound", message: "" });
    const msg = vi.mocked(toast.error).mock.calls[0][0] as string;
    expect(msg.toLowerCase()).toMatch(/not found|hash/);
  });
});

// ---------------------------------------------------------------------------
// Phase 3b error code messages
// ---------------------------------------------------------------------------

describe("Phase 3b file + report error codes — message content", () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it("EvidenceFileNotFound message mentions 'not found'", () => {
    toastError({ code: "EvidenceFileNotFound", message: "" });
    const msg = vi.mocked(toast.error).mock.calls[0][0] as string;
    expect(msg.toLowerCase()).toMatch(/not found/);
  });

  it("EvidenceFileTooLarge message mentions the size limit", () => {
    toastError({ code: "EvidenceFileTooLarge", message: "" });
    const msg = vi.mocked(toast.error).mock.calls[0][0] as string;
    expect(msg.toLowerCase()).toMatch(/50|limit/);
  });

  it("InvalidFilename message instructs to rename", () => {
    toastError({ code: "InvalidFilename", message: "" });
    const msg = vi.mocked(toast.error).mock.calls[0][0] as string;
    expect(msg.toLowerCase()).toMatch(/invalid|character|rename/);
  });

  it("PathTraversalBlocked message is longer than 40 chars and mentions security", () => {
    toastError({ code: "PathTraversalBlocked", message: "" });
    const msg = vi.mocked(toast.error).mock.calls[0][0] as string;
    expect(msg.length).toBeGreaterThan(40);
    expect(msg.toLowerCase()).toMatch(/path|security|storage/);
  });

  it("OneDriveSyncWarning toast message directs to dialog", () => {
    toastError({ code: "OneDriveSyncWarning", message: "" });
    const msg = vi.mocked(toast.error).mock.calls[0][0] as string;
    // Per spec: OneDriveSyncWarning is handled via a dedicated dialog; toast just says 'See dialog.'
    expect(msg.toLowerCase()).toMatch(/dialog/);
  });

  it("HashMismatchOnDownload message is forceful and mentions SHA-256", () => {
    toastError({ code: "HashMismatchOnDownload", message: "" });
    const msg = vi.mocked(toast.error).mock.calls[0][0] as string;
    // SEC-3: must say "INTEGRITY FAILURE" and mention SHA-256 and reacquisition
    expect(msg).toMatch(/INTEGRITY FAILURE/);
    expect(msg).toMatch(/SHA-256/);
    expect(msg.toLowerCase()).toMatch(/reacquisition/);
  });

  it("HashMismatchOnDownload message is longer than 100 characters (substantive)", () => {
    toastError({ code: "HashMismatchOnDownload", message: "" });
    const msg = vi.mocked(toast.error).mock.calls[0][0] as string;
    expect(msg.length).toBeGreaterThan(100);
  });

  it("ReportGenerationFailed message mentions report generation", () => {
    toastError({ code: "ReportGenerationFailed", message: "" });
    const msg = vi.mocked(toast.error).mock.calls[0][0] as string;
    expect(msg.toLowerCase()).toMatch(/report/);
  });
});

// ---------------------------------------------------------------------------
// Phase 4 link-analysis error code messages
// ---------------------------------------------------------------------------

describe("Phase 4 link-analysis error codes — message content", () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it("EntityNotFound message mentions 'not found'", () => {
    toastError({ code: "EntityNotFound", message: "" });
    const msg = vi.mocked(toast.error).mock.calls[0][0] as string;
    expect(msg.toLowerCase()).toMatch(/not found/);
  });

  it("EntityCycle message explicitly explains parent-child cycle", () => {
    toastError({ code: "EntityCycle", message: "" });
    const msg = vi.mocked(toast.error).mock.calls[0][0] as string;
    expect(msg.toLowerCase()).toMatch(/cycle|circular|ancestor/);
    expect(msg.toLowerCase()).toMatch(/parent/);
    expect(msg.length).toBeGreaterThan(60);
  });

  it("LinkNotFound message mentions 'not found'", () => {
    toastError({ code: "LinkNotFound", message: "" });
    const msg = vi.mocked(toast.error).mock.calls[0][0] as string;
    expect(msg.toLowerCase()).toMatch(/not found/);
  });

  it("LinkEndpointMissing message mentions 'endpoint' or 'source'/'target'", () => {
    toastError({ code: "LinkEndpointMissing", message: "" });
    const msg = vi.mocked(toast.error).mock.calls[0][0] as string;
    expect(msg.toLowerCase()).toMatch(/endpoint|source|target/);
  });

  it("EventNotFound message mentions 'not found'", () => {
    toastError({ code: "EventNotFound", message: "" });
    const msg = vi.mocked(toast.error).mock.calls[0][0] as string;
    expect(msg.toLowerCase()).toMatch(/not found/);
  });
});

// ---------------------------------------------------------------------------
// Phase 5 AI + integration + drive error code messages
// ---------------------------------------------------------------------------

describe("Phase 5 AI/integration/drive error codes — message content", () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it("NetworkBindRefused message mentions 'bind' or 'port'", () => {
    toastError({ code: "NetworkBindRefused", message: "" });
    const msg = vi.mocked(toast.error).mock.calls[0][0] as string;
    expect(msg.toLowerCase()).toMatch(/bind|port|server/);
  });

  it("AgentZeroUrlRejected message mentions 'allowlist' or 'localhost'", () => {
    toastError({ code: "AgentZeroUrlRejected", message: "" });
    const msg = vi.mocked(toast.error).mock.calls[0][0] as string;
    expect(msg.toLowerCase()).toMatch(/localhost|allowlist|127\.0\.0\.1/i);
  });

  it("AgentZeroNotConfigured message instructs user to go to Settings", () => {
    toastError({ code: "AgentZeroNotConfigured", message: "" });
    const msg = vi.mocked(toast.error).mock.calls[0][0] as string;
    expect(msg.toLowerCase()).toMatch(/settings|configure/);
  });

  it("AgentZeroTimeout message mentions 'respond' or 'container'", () => {
    toastError({ code: "AgentZeroTimeout", message: "" });
    const msg = vi.mocked(toast.error).mock.calls[0][0] as string;
    expect(msg.toLowerCase()).toMatch(/respond|container|running/);
  });

  it("AgentZeroServerError message mentions 'error' or 'logs'", () => {
    toastError({ code: "AgentZeroServerError", message: "" });
    const msg = vi.mocked(toast.error).mock.calls[0][0] as string;
    expect(msg.toLowerCase()).toMatch(/error|logs|response/);
  });

  it("PayloadTooLarge message mentions 'too large' or 'response'", () => {
    toastError({ code: "PayloadTooLarge", message: "" });
    const msg = vi.mocked(toast.error).mock.calls[0][0] as string;
    expect(msg.toLowerCase()).toMatch(/large|response|agent zero/i);
  });

  it("AiSummarizeConsentRequired does NOT call toast.error (dialog-handled)", () => {
    toastError({ code: "AiSummarizeConsentRequired", message: "" });
    expect(toast.error).not.toHaveBeenCalled();
  });

  it("SmtpConnectFailed message mentions 'SMTP' or 'connect'", () => {
    toastError({ code: "SmtpConnectFailed", message: "" });
    const msg = vi.mocked(toast.error).mock.calls[0][0] as string;
    expect(msg.toLowerCase()).toMatch(/smtp|connect|host/);
  });

  it("SmtpSendFailed message mentions 'password' or 'rejected'", () => {
    toastError({ code: "SmtpSendFailed", message: "" });
    const msg = vi.mocked(toast.error).mock.calls[0][0] as string;
    expect(msg.toLowerCase()).toMatch(/reject|password|username|from/);
  });

  it("DriveScanTooLarge message mentions 'files' or 'scan'", () => {
    toastError({ code: "DriveScanTooLarge", message: "" });
    const msg = vi.mocked(toast.error).mock.calls[0][0] as string;
    expect(msg.toLowerCase()).toMatch(/file|scan|drive/);
  });
});
