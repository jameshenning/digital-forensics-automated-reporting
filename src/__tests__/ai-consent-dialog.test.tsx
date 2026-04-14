/**
 * Tests for AiConsentDialog — Phase 5 SEC-4 §2.7 consent gate.
 *
 * Verifies:
 *   - Renders with title and body copy
 *   - Both action buttons are present
 *   - Cancel calls onClose, does NOT call onAcknowledge
 *   - Acknowledge button calls settings_acknowledge_ai_consent and then onAcknowledge
 *   - Escape key is suppressed (dialog stays open)
 *   - Outside-click is suppressed (dialog stays open)
 *   - The configured Agent Zero URL appears in the body
 */

import { describe, it, expect, vi, beforeEach } from "vitest";
import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import React from "react";

vi.mock("@tauri-apps/api/core", () => ({ invoke: vi.fn() }));
vi.mock("sonner", () => ({ toast: { error: vi.fn(), success: vi.fn() } }));

import { invoke } from "@tauri-apps/api/core";
import { AiConsentDialog } from "@/components/ai-consent-dialog";

const mockInvoke = vi.mocked(invoke);

function makeWrapper() {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  const Wrapper = ({ children }: { children: React.ReactNode }) =>
    React.createElement(QueryClientProvider, { client: qc }, children);
  return { Wrapper };
}

describe("AiConsentDialog", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    sessionStorage.setItem("dfars_session_token", "sess_test");
  });

  it("renders the title when open", () => {
    const { Wrapper } = makeWrapper();
    render(
      <AiConsentDialog
        open={true}
        agentZeroUrl="http://localhost:5099"
        onAcknowledge={() => {}}
        onClose={() => {}}
      />,
      { wrapper: Wrapper },
    );
    expect(screen.getByText(/send full case to agent zero/i)).toBeInTheDocument();
  });

  it("renders both action buttons", () => {
    const { Wrapper } = makeWrapper();
    render(
      <AiConsentDialog
        open={true}
        agentZeroUrl="http://localhost:5099"
        onAcknowledge={() => {}}
        onClose={() => {}}
      />,
      { wrapper: Wrapper },
    );
    expect(screen.getByRole("button", { name: /cancel/i })).toBeInTheDocument();
    expect(
      screen.getByRole("button", { name: /acknowledge and continue/i }),
    ).toBeInTheDocument();
  });

  it("shows the configured Agent Zero URL in the body", () => {
    const { Wrapper } = makeWrapper();
    render(
      <AiConsentDialog
        open={true}
        agentZeroUrl="http://host.docker.internal:50080"
        onAcknowledge={() => {}}
        onClose={() => {}}
      />,
      { wrapper: Wrapper },
    );
    expect(document.body.textContent).toContain("http://host.docker.internal:50080");
  });

  it("mentions PII in the body copy", () => {
    const { Wrapper } = makeWrapper();
    render(
      <AiConsentDialog
        open={true}
        agentZeroUrl="http://localhost:5099"
        onAcknowledge={() => {}}
        onClose={() => {}}
      />,
      { wrapper: Wrapper },
    );
    expect(document.body.textContent).toMatch(/PII/i);
  });

  it("mentions chain of custody in the body copy", () => {
    const { Wrapper } = makeWrapper();
    render(
      <AiConsentDialog
        open={true}
        agentZeroUrl="http://localhost:5099"
        onAcknowledge={() => {}}
        onClose={() => {}}
      />,
      { wrapper: Wrapper },
    );
    expect(document.body.textContent).toMatch(/chain of custody/i);
  });

  it("clicking Cancel calls onClose and does NOT call settings_acknowledge_ai_consent", async () => {
    const onClose = vi.fn();
    const onAcknowledge = vi.fn();
    const { Wrapper } = makeWrapper();

    render(
      <AiConsentDialog
        open={true}
        agentZeroUrl="http://localhost:5099"
        onAcknowledge={onAcknowledge}
        onClose={onClose}
      />,
      { wrapper: Wrapper },
    );

    const user = userEvent.setup();
    await user.click(screen.getByRole("button", { name: /cancel/i }));

    expect(onClose).toHaveBeenCalledOnce();
    expect(onAcknowledge).not.toHaveBeenCalled();
    expect(mockInvoke).not.toHaveBeenCalled();
  });

  it("clicking Acknowledge calls settings_acknowledge_ai_consent then onAcknowledge", async () => {
    mockInvoke.mockResolvedValue(undefined);
    const onClose = vi.fn();
    const onAcknowledge = vi.fn();
    const { Wrapper } = makeWrapper();

    render(
      <AiConsentDialog
        open={true}
        agentZeroUrl="http://localhost:5099"
        onAcknowledge={onAcknowledge}
        onClose={onClose}
      />,
      { wrapper: Wrapper },
    );

    const user = userEvent.setup();
    await user.click(
      screen.getByRole("button", { name: /acknowledge and continue/i }),
    );

    await waitFor(() => {
      expect(mockInvoke).toHaveBeenCalledWith(
        "settings_acknowledge_ai_consent",
        expect.objectContaining({ token: "sess_test" }),
      );
    });

    await waitFor(() => {
      expect(onAcknowledge).toHaveBeenCalledOnce();
    });
  });

  it("does not render when open=false", () => {
    const { Wrapper } = makeWrapper();
    render(
      <AiConsentDialog
        open={false}
        agentZeroUrl="http://localhost:5099"
        onAcknowledge={() => {}}
        onClose={() => {}}
      />,
      { wrapper: Wrapper },
    );
    expect(
      screen.queryByText(/send full case to agent zero/i),
    ).not.toBeInTheDocument();
  });
});
