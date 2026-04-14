/**
 * Tests for the casesList binding wired through TanStack Query.
 *
 * Mirrors the pattern from session.test.tsx:
 *   - Mock @tauri-apps/api/core invoke
 *   - Render a hook with QueryClientProvider
 *   - Assert loading → data → error flows
 */

import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { renderHook, waitFor } from "@testing-library/react";
import { QueryClient, QueryClientProvider, useQuery } from "@tanstack/react-query";
import React from "react";

// ── Mock Tauri IPC before any import of bindings.ts ──────────────────────────
vi.mock("@tauri-apps/api/core", () => ({
  invoke: vi.fn(),
}));

import { invoke } from "@tauri-apps/api/core";
import { casesList } from "@/lib/bindings";
import { queryKeys } from "@/lib/query";
import type { CaseSummary } from "@/lib/bindings";

const MOCK_CASES: CaseSummary[] = [
  {
    case_id: "CASE-2026-0001",
    case_name: "Drone Investigation Alpha",
    investigator: "jsmith",
    start_date: "2026-01-15",
    status: "Active",
    priority: "High",
    evidence_count: 3,
    created_at: "2026-01-15T09:00:00Z",
  },
  {
    case_id: "CASE-2026-0002",
    case_name: "Mobile Device Beta",
    investigator: "jdoe",
    start_date: "2026-02-10",
    status: "Pending",
    priority: "Medium",
    evidence_count: 0,
    created_at: "2026-02-10T14:30:00Z",
  },
];

// ── Test wrapper ──────────────────────────────────────────────────────────────

function makeWrapper() {
  const queryClient = new QueryClient({
    defaultOptions: {
      queries: { retry: false, refetchOnWindowFocus: false },
    },
  });
  const Wrapper = ({ children }: { children: React.ReactNode }) =>
    React.createElement(QueryClientProvider, { client: queryClient }, children);
  return { Wrapper, queryClient };
}

// ── Hook under test: wraps casesList in useQuery ──────────────────────────────

function useCasesListQuery(token: string) {
  return useQuery({
    queryKey: queryKeys.cases.list(100, 0),
    queryFn: () => casesList({ token, limit: 100, offset: 0 }),
    enabled: !!token,
  });
}

// ── Tests ─────────────────────────────────────────────────────────────────────

describe("useCasesListQuery", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    sessionStorage.clear();
  });

  afterEach(() => {
    sessionStorage.clear();
  });

  it("starts in loading state when token is present", async () => {
    // Delay resolution so we can observe the loading state
    vi.mocked(invoke).mockImplementation(
      () => new Promise((resolve) => setTimeout(() => resolve(MOCK_CASES), 100))
    );

    const { Wrapper } = makeWrapper();
    const { result } = renderHook(
      () => useCasesListQuery("sess_validtoken"),
      { wrapper: Wrapper }
    );

    // Initially loading
    expect(result.current.isLoading).toBe(true);
    expect(result.current.data).toBeUndefined();
  });

  it("returns cases data on successful invoke", async () => {
    vi.mocked(invoke).mockResolvedValueOnce(MOCK_CASES);

    const { Wrapper } = makeWrapper();
    const { result } = renderHook(
      () => useCasesListQuery("sess_validtoken"),
      { wrapper: Wrapper }
    );

    await waitFor(() => expect(result.current.isSuccess).toBe(true));

    expect(invoke).toHaveBeenCalledWith(
      "cases_list",
      expect.objectContaining({ token: "sess_validtoken", limit: 100, offset: 0 })
    );
    expect(result.current.data).toEqual(MOCK_CASES);
    expect(result.current.data).toHaveLength(2);
  });

  it("returns empty array when backend returns no cases", async () => {
    vi.mocked(invoke).mockResolvedValueOnce([]);

    const { Wrapper } = makeWrapper();
    const { result } = renderHook(
      () => useCasesListQuery("sess_validtoken"),
      { wrapper: Wrapper }
    );

    await waitFor(() => expect(result.current.isSuccess).toBe(true));

    expect(result.current.data).toEqual([]);
  });

  it("enters error state when invoke rejects", async () => {
    const mockError = { code: "Db", message: "database error" };
    vi.mocked(invoke).mockRejectedValueOnce(mockError);

    const { Wrapper } = makeWrapper();
    const { result } = renderHook(
      () => useCasesListQuery("sess_validtoken"),
      { wrapper: Wrapper }
    );

    await waitFor(() => expect(result.current.isError).toBe(true));

    expect(result.current.data).toBeUndefined();
    expect(result.current.error).toEqual(mockError);
  });

  it("does NOT call invoke when token is empty string", async () => {
    const { Wrapper } = makeWrapper();
    const { result } = renderHook(
      () => useCasesListQuery(""),
      { wrapper: Wrapper }
    );

    // Since enabled: false (empty token), query stays idle
    await waitFor(() => {
      expect(result.current.isLoading).toBe(false);
    });

    expect(invoke).not.toHaveBeenCalled();
    expect(result.current.data).toBeUndefined();
  });

  it("returns case data with correct shape", async () => {
    vi.mocked(invoke).mockResolvedValueOnce(MOCK_CASES);

    const { Wrapper } = makeWrapper();
    const { result } = renderHook(
      () => useCasesListQuery("sess_validtoken"),
      { wrapper: Wrapper }
    );

    await waitFor(() => expect(result.current.isSuccess).toBe(true));

    const first = result.current.data![0];
    expect(first.case_id).toBe("CASE-2026-0001");
    expect(first.status).toBe("Active");
    expect(first.priority).toBe("High");
    expect(first.evidence_count).toBe(3);
  });
});

// ── Query key structure ───────────────────────────────────────────────────────

describe("queryKeys.cases", () => {
  it("all key is ['cases']", () => {
    expect(queryKeys.cases.all).toEqual(["cases"]);
  });

  it("list key includes limit and offset", () => {
    expect(queryKeys.cases.list(100, 0)).toEqual(["cases", "list", 100, 0]);
    expect(queryKeys.cases.list(50, 50)).toEqual(["cases", "list", 50, 50]);
  });

  it("detail key includes caseId", () => {
    expect(queryKeys.cases.detail("CASE-001")).toEqual([
      "cases",
      "detail",
      "CASE-001",
    ]);
  });

  it("list key prefix is a subset of all key", () => {
    // Invalidating queryKeys.cases.all should cover list queries
    const listKey = queryKeys.cases.list(100, 0);
    expect(listKey[0]).toBe(queryKeys.cases.all[0]);
  });
});
