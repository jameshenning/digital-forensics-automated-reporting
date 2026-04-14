/**
 * Tests for evidence file command wrappers in bindings.ts.
 *
 * Mocks `@tauri-apps/api/core` invoke to verify each command passes
 * the correct argument shape to the Tauri IPC layer.
 *
 * Does NOT log file paths to the console — paths may be sensitive.
 */
import { describe, it, expect, vi, beforeEach } from "vitest";

// Mock the Tauri invoke function before importing bindings.
vi.mock("@tauri-apps/api/core", () => ({
  invoke: vi.fn(),
}));

import { invoke } from "@tauri-apps/api/core";
import {
  evidenceFilesUpload,
  evidenceFilesList,
  evidenceFilesDownload,
  evidenceFilesSoftDelete,
  evidenceFilesPurge,
  settingsAcknowledgeOneDriveRisk,
  caseReportPreview,
  caseReportGenerate,
  type EvidenceFile,
  type EvidenceFileDownload,
} from "@/lib/bindings";

const mockInvoke = vi.mocked(invoke);

const MOCK_TOKEN = "sess_test_token_abc123";

const MOCK_EVIDENCE_FILE: EvidenceFile = {
  file_id: 42,
  evidence_id: "EV-001",
  original_filename: "disk_image.img",
  stored_path: "C:\\evidence\\EV-001\\42_disk_image.img",
  sha256: "a".repeat(64),
  size_bytes: 1073741824,
  mime_type: "application/octet-stream",
  metadata_json: null,
  is_deleted: 0,
  uploaded_at: "2026-04-12T10:00:00",
};

const MOCK_DOWNLOAD: EvidenceFileDownload = {
  path: "C:\\evidence\\EV-001\\42_disk_image.img",
  hash_verified: true,
  is_executable: false,
  original_filename: "disk_image.img",
};

describe("evidenceFilesUpload", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    mockInvoke.mockResolvedValue(MOCK_EVIDENCE_FILE);
  });

  it("calls invoke with 'evidence_files_upload' and correct args", async () => {
    await evidenceFilesUpload({
      token: MOCK_TOKEN,
      evidence_id: "EV-001",
      source_path: "D:\\ForensicImages\\disk.img",
    });

    expect(mockInvoke).toHaveBeenCalledWith("evidence_files_upload", {
      token: MOCK_TOKEN,
      evidence_id: "EV-001",
      source_path: "D:\\ForensicImages\\disk.img",
    });
  });

  it("returns an EvidenceFile on success", async () => {
    const result = await evidenceFilesUpload({
      token: MOCK_TOKEN,
      evidence_id: "EV-001",
      source_path: "D:\\file.pdf",
    });
    expect(result.file_id).toBe(42);
    expect(result.sha256).toHaveLength(64);
    expect(result.is_deleted).toBe(0);
  });
});

describe("evidenceFilesList", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    mockInvoke.mockResolvedValue([MOCK_EVIDENCE_FILE]);
  });

  it("calls invoke with 'evidence_files_list' and evidence_id", async () => {
    await evidenceFilesList({ token: MOCK_TOKEN, evidence_id: "EV-001" });
    expect(mockInvoke).toHaveBeenCalledWith("evidence_files_list", {
      token: MOCK_TOKEN,
      evidence_id: "EV-001",
    });
  });

  it("returns an array of EvidenceFile", async () => {
    const results = await evidenceFilesList({
      token: MOCK_TOKEN,
      evidence_id: "EV-001",
    });
    expect(Array.isArray(results)).toBe(true);
    expect(results[0]?.file_id).toBe(42);
  });
});

describe("evidenceFilesDownload", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    mockInvoke.mockResolvedValue(MOCK_DOWNLOAD);
  });

  it("calls invoke with 'evidence_files_download' and file_id", async () => {
    await evidenceFilesDownload({ token: MOCK_TOKEN, file_id: 42 });
    expect(mockInvoke).toHaveBeenCalledWith("evidence_files_download", {
      token: MOCK_TOKEN,
      file_id: 42,
    });
  });

  it("returns EvidenceFileDownload with hash_verified and is_executable fields", async () => {
    const result = await evidenceFilesDownload({
      token: MOCK_TOKEN,
      file_id: 42,
    });
    expect(typeof result.hash_verified).toBe("boolean");
    expect(typeof result.is_executable).toBe("boolean");
    expect(typeof result.original_filename).toBe("string");
  });

  it("returns hash_verified=false shape for tampered file", async () => {
    const tampered: EvidenceFileDownload = {
      ...MOCK_DOWNLOAD,
      hash_verified: false,
    };
    mockInvoke.mockResolvedValue(tampered);
    const result = await evidenceFilesDownload({
      token: MOCK_TOKEN,
      file_id: 42,
    });
    expect(result.hash_verified).toBe(false);
  });

  it("returns is_executable=true shape for an executable file", async () => {
    const exec: EvidenceFileDownload = {
      ...MOCK_DOWNLOAD,
      is_executable: true,
    };
    mockInvoke.mockResolvedValue(exec);
    const result = await evidenceFilesDownload({
      token: MOCK_TOKEN,
      file_id: 99,
    });
    expect(result.is_executable).toBe(true);
  });
});

describe("evidenceFilesSoftDelete", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    mockInvoke.mockResolvedValue(undefined);
  });

  it("calls invoke with 'evidence_files_soft_delete' and file_id", async () => {
    await evidenceFilesSoftDelete({ token: MOCK_TOKEN, file_id: 42 });
    expect(mockInvoke).toHaveBeenCalledWith("evidence_files_soft_delete", {
      token: MOCK_TOKEN,
      file_id: 42,
    });
  });
});

describe("evidenceFilesPurge", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    mockInvoke.mockResolvedValue(undefined);
  });

  it("calls invoke with 'evidence_files_purge', file_id, and justification", async () => {
    await evidenceFilesPurge({
      token: MOCK_TOKEN,
      file_id: 42,
      justification: "File identified as test artifact, not relevant to case.",
    });
    expect(mockInvoke).toHaveBeenCalledWith("evidence_files_purge", {
      token: MOCK_TOKEN,
      file_id: 42,
      justification: "File identified as test artifact, not relevant to case.",
    });
  });

  it("passes justification string through unchanged", async () => {
    const longJustification = "This is a long justification string that exceeds the minimum.";
    await evidenceFilesPurge({
      token: MOCK_TOKEN,
      file_id: 1,
      justification: longJustification,
    });
    const callArgs = mockInvoke.mock.calls[0]?.[1] as Record<string, unknown>;
    expect(callArgs?.justification).toBe(longJustification);
  });
});

describe("settingsAcknowledgeOneDriveRisk", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    mockInvoke.mockResolvedValue(undefined);
  });

  it("calls invoke with 'settings_acknowledge_onedrive_risk'", async () => {
    await settingsAcknowledgeOneDriveRisk({ token: MOCK_TOKEN });
    expect(mockInvoke).toHaveBeenCalledWith(
      "settings_acknowledge_onedrive_risk",
      { token: MOCK_TOKEN },
    );
  });
});

describe("caseReportPreview", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    mockInvoke.mockResolvedValue("# Case Report\n\nSample markdown.");
  });

  it("calls invoke with 'case_report_preview' and case_id", async () => {
    await caseReportPreview({ token: MOCK_TOKEN, case_id: "CASE-001" });
    expect(mockInvoke).toHaveBeenCalledWith("case_report_preview", {
      token: MOCK_TOKEN,
      case_id: "CASE-001",
    });
  });

  it("returns a string", async () => {
    const result = await caseReportPreview({
      token: MOCK_TOKEN,
      case_id: "CASE-001",
    });
    expect(typeof result).toBe("string");
  });
});

describe("caseReportGenerate", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    mockInvoke.mockResolvedValue("C:\\Reports\\CASE-001_report.md");
  });

  it("calls invoke with 'case_report_generate' and format=Markdown", async () => {
    await caseReportGenerate({
      token: MOCK_TOKEN,
      case_id: "CASE-001",
      format: "Markdown",
    });
    expect(mockInvoke).toHaveBeenCalledWith("case_report_generate", {
      token: MOCK_TOKEN,
      case_id: "CASE-001",
      format: "Markdown",
    });
  });

  it("calls invoke with format=Html", async () => {
    await caseReportGenerate({
      token: MOCK_TOKEN,
      case_id: "CASE-001",
      format: "Html",
    });
    const callArgs = mockInvoke.mock.calls[0]?.[1] as Record<string, unknown>;
    expect(callArgs?.format).toBe("Html");
  });

  it("returns the output file path as a string", async () => {
    const result = await caseReportGenerate({
      token: MOCK_TOKEN,
      case_id: "CASE-001",
      format: "Markdown",
    });
    expect(typeof result).toBe("string");
    expect(result.length).toBeGreaterThan(0);
  });
});
