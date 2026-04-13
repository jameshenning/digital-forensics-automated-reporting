/**
 * Tests for `useSession()` hook — `src/lib/session.ts`
 *
 * Deliverable 11: verify the hook's core contracts:
 *   - No token in sessionStorage → hook returns null session, no IPC call.
 *   - Token present → hook calls `auth_current_user` and returns the result.
 *   - IPC failure → hook clears the token and returns null (not an error).
 *   - `clear()` removes the token and resets the query cache.
 *
 * @tauri-apps/api/core `invoke` is mocked via vi.mock so no Tauri runtime needed.
 */
import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { renderHook, waitFor } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import React from "react";

// ── Mock @tauri-apps/api/core before any import of bindings.ts ───────────────
vi.mock("@tauri-apps/api/core", () => ({
  invoke: vi.fn(),
}));

import { invoke } from "@tauri-apps/api/core";
import { useSession, getToken, setToken, clearToken } from "@/lib/session";
import type { SessionInfo } from "@/lib/bindings";

const MOCK_SESSION: SessionInfo = {
  token: "sess_mocktokenvalue",
  username: "testuser",
  mfa_enabled: false,
};

// ── Wrapper: fresh QueryClient per test ──────────────────────────────────────
function makeWrapper() {
  const queryClient = new QueryClient({
    defaultOptions: {
      queries: {
        // Disable retries in tests so failures are instant.
        retry: false,
        // Disable background refetch.
        refetchOnWindowFocus: false,
      },
    },
  });
  const Wrapper = ({ children }: { children: React.ReactNode }) => (
    React.createElement(QueryClientProvider, { client: queryClient }, children)
  );
  return { Wrapper, queryClient };
}

describe("useSession", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    sessionStorage.clear();
  });

  afterEach(() => {
    sessionStorage.clear();
  });

  it("returns null session and does NOT call invoke when no token is stored", async () => {
    // Guarantee no token.
    sessionStorage.clear();
    const { Wrapper } = makeWrapper();

    const { result } = renderHook(() => useSession(), { wrapper: Wrapper });

    // loading is false immediately because `enabled: false` when no token.
    await waitFor(() => {
      expect(result.current.loading).toBe(false);
    });

    expect(result.current.session).toBeNull();
    expect(invoke).not.toHaveBeenCalled();
  });

  it("calls auth_current_user and returns session when a token is stored", async () => {
    setToken("sess_validtoken");
    vi.mocked(invoke).mockResolvedValueOnce(MOCK_SESSION);

    const { Wrapper } = makeWrapper();
    const { result } = renderHook(() => useSession(), { wrapper: Wrapper });

    await waitFor(() => {
      expect(result.current.loading).toBe(false);
    });

    expect(invoke).toHaveBeenCalledWith(
      "auth_current_user",
      expect.objectContaining({ token: "sess_validtoken" })
    );
    expect(result.current.session).toEqual(MOCK_SESSION);
  });

  it("clears the token and returns null when auth_current_user rejects", async () => {
    setToken("sess_expiredtoken");
    vi.mocked(invoke).mockRejectedValueOnce({
      code: "Unauthorized",
      message: "session expired",
    });

    const { Wrapper } = makeWrapper();
    const { result } = renderHook(() => useSession(), { wrapper: Wrapper });

    await waitFor(() => {
      expect(result.current.loading).toBe(false);
    });

    expect(result.current.session).toBeNull();
    // Token must be cleared after the failure.
    expect(getToken()).toBeNull();
  });

  it("clear() removes token from sessionStorage and sets session to null", async () => {
    setToken("sess_cleartesttoken");
    vi.mocked(invoke).mockResolvedValueOnce(MOCK_SESSION);

    const { Wrapper } = makeWrapper();
    const { result } = renderHook(() => useSession(), { wrapper: Wrapper });

    await waitFor(() => {
      expect(result.current.session).toEqual(MOCK_SESSION);
    });

    result.current.clear();

    await waitFor(() => {
      expect(result.current.session).toBeNull();
    });

    expect(getToken()).toBeNull();
  });
});

// ── Storage helpers ──────────────────────────────────────────────────────────

describe("session storage helpers", () => {
  beforeEach(() => sessionStorage.clear());
  afterEach(() => sessionStorage.clear());

  it("getToken returns null when nothing stored", () => {
    expect(getToken()).toBeNull();
  });

  it("setToken / getToken round-trip", () => {
    setToken("sess_abc123");
    expect(getToken()).toBe("sess_abc123");
  });

  it("clearToken removes the stored value", () => {
    setToken("sess_abc123");
    clearToken();
    expect(getToken()).toBeNull();
  });
});
