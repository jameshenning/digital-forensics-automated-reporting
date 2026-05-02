/**
 * Tests for AuditPanel component.
 */

import { describe, it, expect, vi, beforeEach } from "vitest";
import { render, screen, waitFor, fireEvent } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import React from "react";

vi.mock("@tauri-apps/api/core", () => ({ invoke: vi.fn() }));

import { invoke } from "@tauri-apps/api/core";
import { AuditPanel } from "@/components/audit-panel";
import type { AuditEntry } from "@/lib/bindings";

function makeWrapper() {
  const queryClient = new QueryClient({
    defaultOptions: {
      queries: { retry: false, refetchOnWindowFocus: false },
    },
  });
  const Wrapper = ({ children }: { children: React.ReactNode }) => (
    React.createElement(QueryClientProvider, { client: queryClient }, children)
  );
  return { Wrapper, queryClient };
}

const MOCK_ENTRIES: AuditEntry[] = [
  {
    entry_id: 1,
    case_id: "CASE-001",
    timestamp: "2026-04-20T10:00:00Z",
    actor: "jsmith",
    action: "CASE_CREATED",
    details: "Name=\"Alpha\" Investigator=\"jsmith\" Priority=High",
    prev_hash: "0000",
    entry_hash: "abcd1234",
  },
  {
    entry_id: 2,
    case_id: "CASE-001",
    timestamp: "2026-04-21T14:30:00Z",
    actor: "jsmith",
    action: "CASE_UPDATED",
    details: "Status changed to Closed",
    prev_hash: "abcd1234",
    entry_hash: "efgh5678",
  },
];

describe("AuditPanel", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    sessionStorage.setItem("dfars_session_token", "sess_test");
  });

  it("renders empty state when no audit entries", async () => {
    vi.mocked(invoke).mockResolvedValueOnce([]);
    const { Wrapper } = makeWrapper();
    render(<AuditPanel caseId="CASE-001" />, { wrapper: Wrapper });

    await waitFor(() => {
      expect(screen.getByText("No audit entries recorded")).toBeInTheDocument();
    });
  });

  it("renders audit entries with actions and actors", async () => {
    vi.mocked(invoke).mockResolvedValueOnce(MOCK_ENTRIES);
    const { Wrapper } = makeWrapper();
    render(<AuditPanel caseId="CASE-001" />, { wrapper: Wrapper });

    await waitFor(() => {
      expect(screen.getByText("Case created")).toBeInTheDocument();
    });

    expect(screen.getByText("Case updated")).toBeInTheDocument();
    expect(screen.getAllByText(/jsmith/).length).toBeGreaterThanOrEqual(2);
  });

  it("shows hash details when 'Show hashes' is clicked", async () => {
    vi.mocked(invoke).mockResolvedValueOnce(MOCK_ENTRIES);
    const { Wrapper } = makeWrapper();
    render(<AuditPanel caseId="CASE-001" />, { wrapper: Wrapper });

    await waitFor(() => {
      expect(screen.getByText("Case created")).toBeInTheDocument();
    });

    const toggle = screen.getAllByText("Show hashes")[0];
    fireEvent.click(toggle);

    await waitFor(() => {
      expect(screen.getByText("abcd1234")).toBeInTheDocument();
      expect(screen.getByText("0000")).toBeInTheDocument();
    });
  });

  it("calls verify chain when button clicked", async () => {
    vi.mocked(invoke)
      .mockResolvedValueOnce(MOCK_ENTRIES)
      .mockResolvedValueOnce(true);
    const { Wrapper } = makeWrapper();
    render(<AuditPanel caseId="CASE-001" />, { wrapper: Wrapper });

    await waitFor(() => {
      expect(screen.getByText("Verify Chain")).toBeInTheDocument();
    });

    fireEvent.click(screen.getByText("Verify Chain"));

    await waitFor(() => {
      expect(invoke).toHaveBeenCalledWith(
        "audit_verify_chain",
        expect.objectContaining({ case_id: "CASE-001" })
      );
    });
  });
});
