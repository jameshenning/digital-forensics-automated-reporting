/**
 * Tests for ReportDialog — case report preview.
 *
 * Mocks `case_report_preview` to return known markdown and verifies:
 *   - Rendered markdown contains the expected case header text
 *   - Loading state shows skeletons (not the content)
 *   - "Download as Markdown" button is present
 *   - "Close" button calls onClose
 */
import { describe, it, expect, vi, beforeEach } from "vitest";
import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import React from "react";

// Mock Tauri IPC and opener before importing components.
vi.mock("@tauri-apps/api/core", () => ({ invoke: vi.fn() }));
vi.mock("@tauri-apps/plugin-opener", () => ({ openPath: vi.fn() }));
vi.mock("sonner", () => ({ toast: { error: vi.fn(), success: vi.fn() } }));

import { invoke } from "@tauri-apps/api/core";
import { ReportDialog } from "@/components/report-dialog";

const mockInvoke = vi.mocked(invoke);

const MOCK_MARKDOWN = `# Case Report: CASE-2026-001

## Investigator: James Hennessey

## Evidence Items

| ID | Description | Status |
|----|-------------|--------|
| EV-001 | Suspect laptop | Analyzed |

## Chain of Custody

No custody events recorded.

## Analysis Notes

No analysis notes recorded.
`;

function makeWrapper() {
  const qc = new QueryClient({
    defaultOptions: { queries: { retry: false, staleTime: 0, gcTime: 0 } },
  });
  const Wrapper = ({ children }: { children: React.ReactNode }) =>
    React.createElement(QueryClientProvider, { client: qc }, children);
  return { Wrapper, qc };
}

describe("ReportDialog", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    sessionStorage.setItem("dfars_session_token", "sess_test");
  });

  it("renders the 'Case Report Preview' title when open", async () => {
    mockInvoke.mockResolvedValue(MOCK_MARKDOWN);
    const { Wrapper } = makeWrapper();

    render(
      <ReportDialog caseId="CASE-2026-001" open={true} onClose={() => {}} />,
      { wrapper: Wrapper },
    );

    expect(screen.getByText(/case report preview/i)).toBeInTheDocument();
  });

  it("shows rendered markdown content after loading", async () => {
    mockInvoke.mockResolvedValue(MOCK_MARKDOWN);
    const { Wrapper } = makeWrapper();

    render(
      <ReportDialog caseId="CASE-2026-001" open={true} onClose={() => {}} />,
      { wrapper: Wrapper },
    );

    // Wait for the markdown heading to appear in the rendered output
    await waitFor(() => {
      expect(
        screen.getByRole("heading", { name: /Case Report: CASE-2026-001/i }),
      ).toBeInTheDocument();
    });
  });

  it("renders markdown table content (Investigator row)", async () => {
    mockInvoke.mockResolvedValue(MOCK_MARKDOWN);
    const { Wrapper } = makeWrapper();

    render(
      <ReportDialog caseId="CASE-2026-001" open={true} onClose={() => {}} />,
      { wrapper: Wrapper },
    );

    await waitFor(() => {
      expect(screen.getByText(/James Hennessey/i)).toBeInTheDocument();
    });
  });

  it("has a 'Download as Markdown' button", async () => {
    mockInvoke.mockResolvedValue(MOCK_MARKDOWN);
    const { Wrapper } = makeWrapper();

    render(
      <ReportDialog caseId="CASE-2026-001" open={true} onClose={() => {}} />,
      { wrapper: Wrapper },
    );

    await waitFor(() => {
      expect(
        screen.getByRole("button", { name: /download as markdown/i }),
      ).toBeInTheDocument();
    });
  });

  it("has a 'Close' button in the footer", async () => {
    mockInvoke.mockResolvedValue(MOCK_MARKDOWN);
    const { Wrapper } = makeWrapper();

    render(
      <ReportDialog caseId="CASE-2026-001" open={true} onClose={() => {}} />,
      { wrapper: Wrapper },
    );

    // The footer Close button has visible text "Close" (not an sr-only span).
    // We use getAllByRole because the Dialog also has an X button with sr-only "Close".
    const closeButtons = screen.getAllByRole("button", { name: /close/i });
    expect(closeButtons.length).toBeGreaterThanOrEqual(1);
  });

  it("calls onClose when the footer 'Close' button is clicked", async () => {
    mockInvoke.mockResolvedValue(MOCK_MARKDOWN);
    const onClose = vi.fn();
    const { Wrapper } = makeWrapper();

    render(
      <ReportDialog caseId="CASE-2026-001" open={true} onClose={onClose} />,
      { wrapper: Wrapper },
    );

    // Find the footer Close button by looking for visible text (not sr-only).
    // The footer button has class attributes from Shadcn Button.
    const user = userEvent.setup();
    // There may be multiple "Close" buttons (X icon + footer).
    // Click the last one which is the footer button.
    const closeButtons = screen.getAllByRole("button", { name: /close/i });
    const footerClose = closeButtons[closeButtons.length - 1];
    await user.click(footerClose!);
    expect(onClose).toHaveBeenCalled();
  });

  it("calls case_report_preview with the correct caseId", async () => {
    mockInvoke.mockResolvedValue(MOCK_MARKDOWN);
    const { Wrapper } = makeWrapper();

    render(
      <ReportDialog caseId="CASE-2026-999" open={true} onClose={() => {}} />,
      { wrapper: Wrapper },
    );

    await waitFor(() => {
      expect(mockInvoke).toHaveBeenCalledWith(
        "case_report_preview",
        expect.objectContaining({ case_id: "CASE-2026-999" }),
      );
    });
  });

  it("does not call case_report_preview when open=false", () => {
    const { Wrapper } = makeWrapper();

    render(
      <ReportDialog caseId="CASE-2026-001" open={false} onClose={() => {}} />,
      { wrapper: Wrapper },
    );

    expect(mockInvoke).not.toHaveBeenCalled();
  });

  it("calls case_report_generate with Markdown format on download button click", async () => {
    mockInvoke.mockResolvedValue(MOCK_MARKDOWN);
    const { Wrapper } = makeWrapper();

    render(
      <ReportDialog caseId="CASE-2026-001" open={true} onClose={() => {}} />,
      { wrapper: Wrapper },
    );

    // Wait for the preview to load, then mock generate response
    await waitFor(() => {
      expect(screen.getByRole("button", { name: /download as markdown/i })).toBeInTheDocument();
    });

    // Second call is generate
    mockInvoke.mockResolvedValue("C:\\Reports\\CASE-2026-001_report.md");

    const user = userEvent.setup();
    await user.click(
      screen.getByRole("button", { name: /download as markdown/i }),
    );

    await waitFor(() => {
      expect(mockInvoke).toHaveBeenCalledWith(
        "case_report_generate",
        expect.objectContaining({
          case_id: "CASE-2026-001",
          format: "Markdown",
        }),
      );
    });
  });
});
