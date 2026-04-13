/**
 * Tests for OneDriveWarningDialog — SEC-3 MUST-DO 5.
 *
 * Verifies:
 *   - All three buttons are present (configure drive, acknowledge, cancel)
 *   - Clicking "acknowledge" triggers settingsAcknowledgeOneDriveRisk mutation
 *   - Clicking "Configure a forensic drive" invokes onConfigureDrive
 *   - Clicking "Cancel upload" invokes onClose
 */
import { describe, it, expect, vi, beforeEach } from "vitest";
import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import React from "react";

// Mock Tauri invoke and sonner before importing components.
vi.mock("@tauri-apps/api/core", () => ({ invoke: vi.fn() }));
vi.mock("sonner", () => ({ toast: { error: vi.fn(), success: vi.fn() } }));

import { invoke } from "@tauri-apps/api/core";
import { OneDriveWarningDialog } from "@/components/onedrive-warning-dialog";

const mockInvoke = vi.mocked(invoke);

function makeWrapper() {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  const Wrapper = ({ children }: { children: React.ReactNode }) =>
    React.createElement(QueryClientProvider, { client: qc }, children);
  return { Wrapper, qc };
}

describe("OneDriveWarningDialog", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    // Set a fake token in sessionStorage for the mutation.
    sessionStorage.setItem("dfars_session_token", "sess_test");
  });

  it("renders all three action buttons when open", () => {
    const { Wrapper } = makeWrapper();
    render(
      <OneDriveWarningDialog
        open={true}
        onClose={() => {}}
        onAcknowledge={() => {}}
        onConfigureDrive={() => {}}
      />,
      { wrapper: Wrapper },
    );

    expect(
      screen.getByRole("button", { name: /configure a forensic drive/i }),
    ).toBeInTheDocument();

    expect(
      screen.getByRole("button", { name: /i understand the risk/i }),
    ).toBeInTheDocument();

    expect(
      screen.getByRole("button", { name: /cancel upload/i }),
    ).toBeInTheDocument();
  });

  it("shows the OneDrive warning title", () => {
    const { Wrapper } = makeWrapper();
    render(
      <OneDriveWarningDialog
        open={true}
        onClose={() => {}}
        onAcknowledge={() => {}}
        onConfigureDrive={() => {}}
      />,
      { wrapper: Wrapper },
    );
    expect(
      screen.getByText(/evidence storage is on a cloud-synced folder/i),
    ).toBeInTheDocument();
  });

  it("mentions OneDrive and Microsoft in the body", () => {
    const { Wrapper } = makeWrapper();
    render(
      <OneDriveWarningDialog
        open={true}
        onClose={() => {}}
        onAcknowledge={() => {}}
        onConfigureDrive={() => {}}
      />,
      { wrapper: Wrapper },
    );
    // Text may be split across child elements — use container query
    expect(document.body.textContent).toMatch(/OneDrive/);
    expect(document.body.textContent).toMatch(/Microsoft/);
  });

  it("calls onConfigureDrive and onClose when 'Configure a forensic drive' is clicked", async () => {
    const onConfigureDrive = vi.fn();
    const onClose = vi.fn();
    const { Wrapper } = makeWrapper();

    render(
      <OneDriveWarningDialog
        open={true}
        onClose={onClose}
        onAcknowledge={() => {}}
        onConfigureDrive={onConfigureDrive}
      />,
      { wrapper: Wrapper },
    );

    const user = userEvent.setup();
    await user.click(
      screen.getByRole("button", { name: /configure a forensic drive/i }),
    );

    expect(onConfigureDrive).toHaveBeenCalledOnce();
    expect(onClose).toHaveBeenCalledOnce();
  });

  it("calls settingsAcknowledgeOneDriveRisk and then onAcknowledge on 'I understand'", async () => {
    mockInvoke.mockResolvedValue(undefined);
    const onAcknowledge = vi.fn();
    const onClose = vi.fn();
    const { Wrapper } = makeWrapper();

    render(
      <OneDriveWarningDialog
        open={true}
        onClose={onClose}
        onAcknowledge={onAcknowledge}
        onConfigureDrive={() => {}}
      />,
      { wrapper: Wrapper },
    );

    const user = userEvent.setup();
    await user.click(
      screen.getByRole("button", { name: /i understand the risk/i }),
    );

    await waitFor(() => {
      expect(mockInvoke).toHaveBeenCalledWith(
        "settings_acknowledge_onedrive_risk",
        expect.objectContaining({ token: "sess_test" }),
      );
    });

    await waitFor(() => {
      expect(onAcknowledge).toHaveBeenCalledOnce();
      expect(onClose).toHaveBeenCalledOnce();
    });
  });

  it("calls onClose when 'Cancel upload' is clicked", async () => {
    const onClose = vi.fn();
    const { Wrapper } = makeWrapper();

    render(
      <OneDriveWarningDialog
        open={true}
        onClose={onClose}
        onAcknowledge={() => {}}
        onConfigureDrive={() => {}}
      />,
      { wrapper: Wrapper },
    );

    const user = userEvent.setup();
    await user.click(screen.getByRole("button", { name: /cancel upload/i }));

    expect(onClose).toHaveBeenCalledOnce();
  });

  it("does not render dialog content when open=false", () => {
    const { Wrapper } = makeWrapper();
    render(
      <OneDriveWarningDialog
        open={false}
        onClose={() => {}}
        onAcknowledge={() => {}}
        onConfigureDrive={() => {}}
      />,
      { wrapper: Wrapper },
    );
    // The title should not appear when closed.
    expect(
      screen.queryByText(/evidence storage is on a cloud-synced folder/i),
    ).not.toBeInTheDocument();
  });
});
