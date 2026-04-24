/**
 * Component tests for AnalysisReviewDialog.
 *
 * Verifies:
 *  - Dialog renders the note finding in the header.
 *  - Submit calls `analysis_mark_reviewed` with the right shape and
 *    appends `:00` to the datetime-local value.
 *  - Empty review_notes is sent as null (matches the existing
 *    "empty string → null" coercion pattern).
 */

import { describe, it, expect, vi, beforeEach } from "vitest";
import { render, screen, waitFor, fireEvent } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import React from "react";

vi.mock("@tauri-apps/api/core", () => ({
  invoke: vi.fn(),
}));

import { invoke } from "@tauri-apps/api/core";

const MOCK_TOKEN = "sess_review_test";
beforeEach(() => {
  sessionStorage.setItem("dfars_session_token", MOCK_TOKEN);
  vi.clearAllMocks();
  vi.mocked(invoke).mockResolvedValue({
    review_id: 1,
    note_id: 42,
    reviewed_by: "Dr. Peer",
    reviewed_at: "2026-04-22T10:00:00",
    review_notes: null,
    created_at: "2026-04-22T10:00:01",
  });
});

function makeWrapper() {
  const queryClient = new QueryClient({
    defaultOptions: { queries: { retry: false, refetchOnWindowFocus: false } },
  });
  const Wrapper = ({ children }: { children: React.ReactNode }) =>
    React.createElement(QueryClientProvider, { client: queryClient }, children);
  return { Wrapper };
}

describe("AnalysisReviewDialog", () => {
  it("renders the note finding in the header", async () => {
    const { AnalysisReviewDialog } = await import(
      "@/components/analysis-review-dialog"
    );
    const { Wrapper } = makeWrapper();

    render(
      React.createElement(Wrapper, null,
        React.createElement(AnalysisReviewDialog, {
          noteId: 42,
          noteFinding: "Suspicious file timestamp",
          open: true,
          onOpenChange: () => {},
        })
      )
    );

    expect(screen.getByText(/Suspicious file timestamp/i)).toBeInTheDocument();
    expect(screen.getByText(/Record peer review/i)).toBeInTheDocument();
  });

  it("submits with reviewed_at appended to HH:MM:SS and review_notes coerced to null when empty", async () => {
    const onClose = vi.fn();
    const { AnalysisReviewDialog } = await import(
      "@/components/analysis-review-dialog"
    );
    const { Wrapper } = makeWrapper();

    render(
      React.createElement(Wrapper, null,
        React.createElement(AnalysisReviewDialog, {
          noteId: 42,
          noteFinding: "x",
          open: true,
          onOpenChange: onClose,
        })
      )
    );

    const reviewerInput = screen.getByLabelText(/Reviewer/i);
    const dateInput = screen.getByLabelText(/Date\/time/i);
    fireEvent.change(reviewerInput, { target: { value: "Dr. Peer" } });
    fireEvent.change(dateInput, { target: { value: "2026-04-22T10:00" } });

    const submit = screen.getByRole("button", { name: /Record review/i });
    fireEvent.click(submit);

    await waitFor(() => expect(invoke).toHaveBeenCalled());
    const [cmd, args] = vi.mocked(invoke).mock.calls[0] as [string, Record<string, unknown>];
    expect(cmd).toBe("analysis_mark_reviewed");
    expect(args.note_id).toBe(42);
    const input = args.input as Record<string, unknown>;
    expect(input.reviewed_by).toBe("Dr. Peer");
    expect(input.reviewed_at).toBe("2026-04-22T10:00:00");
    expect(input.review_notes).toBeNull();
  });
});
