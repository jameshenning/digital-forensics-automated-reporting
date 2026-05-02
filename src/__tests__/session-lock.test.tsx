/**
 * Tests for SessionLockProvider and useSessionLock hook.
 */

import { describe, it, expect, vi } from "vitest";
import { render, screen } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import React from "react";

vi.mock("@tauri-apps/api/core", () => ({ invoke: vi.fn() }));

import { SessionLockProvider, useSessionLock } from "@/components/session-lock-provider";

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

function TestConsumer() {
  const { lock } = useSessionLock();
  return (
    <button onClick={lock} data-testid="lock-btn">
      Lock
    </button>
  );
}

describe("SessionLockProvider", () => {
  it("throws when useSessionLock is used outside provider", () => {
    const consoleSpy = vi.spyOn(console, "error").mockImplementation(() => {});
    expect(() => render(<TestConsumer />)).toThrow(
      "useSessionLock must be used inside SessionLockProvider"
    );
    consoleSpy.mockRestore();
  });

  it("renders children and exposes lock function", () => {
    const { Wrapper } = makeWrapper();
    render(
      <SessionLockProvider>
        <TestConsumer />
      </SessionLockProvider>,
      { wrapper: Wrapper }
    );
    expect(screen.getByTestId("lock-btn")).toBeInTheDocument();
  });
});
