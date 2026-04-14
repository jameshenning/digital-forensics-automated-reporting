/**
 * Tests for AIButton component.
 *
 * Verifies:
 *   - enhance happy path — calls ai_enhance and fires onResult
 *   - disabled when text is empty
 *   - shows tooltip text when Agent Zero is not configured
 *   - spinner appears while mutation is pending
 *   - does NOT toast for AgentZeroNotConfigured (swallowed)
 */

import { describe, it, expect, vi, beforeEach } from "vitest";
import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import React from "react";

vi.mock("@tauri-apps/api/core", () => ({ invoke: vi.fn() }));
vi.mock("sonner", () => ({ toast: { error: vi.fn(), success: vi.fn() } }));

import { invoke } from "@tauri-apps/api/core";
import { toast } from "sonner";
import { AIButton } from "@/components/ai-button";

const mockInvoke = vi.mocked(invoke);
const mockToastError = vi.mocked(toast.error);

function makeWrapper() {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  const Wrapper = ({ children }: { children: React.ReactNode }) =>
    React.createElement(QueryClientProvider, { client: qc }, children);
  return { Wrapper };
}

describe("AIButton — enhance action", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    sessionStorage.setItem("dfars_session_token", "sess_test");
  });

  it("calls ai_enhance and fires onResult with the returned text", async () => {
    mockInvoke.mockResolvedValue("Polished narrative text");
    const onResult = vi.fn();
    const { Wrapper } = makeWrapper();

    render(
      <AIButton action="enhance" text="original text" onResult={onResult}>
        Polish
      </AIButton>,
      { wrapper: Wrapper },
    );

    const user = userEvent.setup();
    // Button's accessible name comes from aria-label, not children text
    await user.click(screen.getByRole("button", { name: /enhance with ai/i }));

    await waitFor(() => {
      expect(mockInvoke).toHaveBeenCalledWith(
        "ai_enhance",
        expect.objectContaining({ token: "sess_test", text: "original text" }),
      );
    });

    await waitFor(() => {
      expect(onResult).toHaveBeenCalledWith("Polished narrative text");
    });
  });

  it("is disabled when text is empty", () => {
    const { Wrapper } = makeWrapper();
    render(
      <AIButton action="enhance" text="" onResult={() => {}}>
        Polish
      </AIButton>,
      { wrapper: Wrapper },
    );
    // When text is empty, aria-label changes to "Enter some text first to use AI"
    expect(screen.getByRole("button", { name: /enter some text/i })).toBeDisabled();
  });

  it("is disabled when text is only whitespace", () => {
    const { Wrapper } = makeWrapper();
    render(
      <AIButton action="enhance" text="   " onResult={() => {}}>
        Polish
      </AIButton>,
      { wrapper: Wrapper },
    );
    expect(screen.getByRole("button", { name: /enter some text/i })).toBeDisabled();
  });

  it("shows tooltip hint when Agent Zero is not configured", async () => {
    const { Wrapper } = makeWrapper();
    render(
      <AIButton
        action="enhance"
        text="some text"
        onResult={() => {}}
        agentZeroConfigured={false}
      >
        Polish
      </AIButton>,
      { wrapper: Wrapper },
    );

    // Button wrapped in a tooltip span should be present
    const wrapper = document.querySelector("span[tabindex]");
    expect(wrapper).toBeInTheDocument();

    // The button inside should be disabled
    const btn = screen.getByRole("button");
    expect(btn).toBeDisabled();
  });

  it("does NOT toast for AgentZeroNotConfigured error", async () => {
    mockInvoke.mockRejectedValue({ code: "AgentZeroNotConfigured", message: "not configured" });
    const { Wrapper } = makeWrapper();

    render(
      <AIButton action="enhance" text="some text" onResult={() => {}}>
        Polish
      </AIButton>,
      { wrapper: Wrapper },
    );

    const user = userEvent.setup();
    await user.click(screen.getByRole("button"));

    await waitFor(() => {
      expect(mockInvoke).toHaveBeenCalled();
    });

    // Toast.error must NOT have been called for this specific code
    expect(mockToastError).not.toHaveBeenCalled();
  });

  it("toasts on a generic error", async () => {
    mockInvoke.mockRejectedValue({ code: "Internal", message: "server exploded" });
    const { Wrapper } = makeWrapper();

    render(
      <AIButton action="enhance" text="some text" onResult={() => {}}>
        Polish
      </AIButton>,
      { wrapper: Wrapper },
    );

    const user = userEvent.setup();
    await user.click(screen.getByRole("button"));

    await waitFor(() => {
      expect(mockToastError).toHaveBeenCalled();
    });
  });

  it("shows 'Working...' text while pending", async () => {
    // Never resolve — stays pending
    mockInvoke.mockReturnValue(new Promise(() => {}));
    const { Wrapper } = makeWrapper();

    render(
      <AIButton action="enhance" text="some text" onResult={() => {}}>
        Polish
      </AIButton>,
      { wrapper: Wrapper },
    );

    const user = userEvent.setup();
    // Click by aria-label (before mutation changes state)
    await user.click(screen.getByRole("button", { name: /enhance with ai/i }));

    await waitFor(() => {
      expect(screen.getByText(/working\.\.\./i)).toBeInTheDocument();
    });
  });
});
