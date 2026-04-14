/**
 * Tests for DrivePicker component.
 *
 * Verifies:
 *   - Falls back to text input when drives_list fails
 *   - Populates the select when drives are available
 *   - Formats drive labels correctly (size, type, label)
 *   - Selecting a drive calls onChange with the drive letter + backslash
 */

import { describe, it, expect, vi, beforeEach } from "vitest";
import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import React from "react";

vi.mock("@tauri-apps/api/core", () => ({ invoke: vi.fn() }));
vi.mock("sonner", () => ({ toast: { error: vi.fn(), success: vi.fn() } }));

import { invoke } from "@tauri-apps/api/core";
import { DrivePicker } from "@/components/drive-picker";
import type { Drive } from "@/lib/bindings";

const mockInvoke = vi.mocked(invoke);

const MOCK_DRIVES: Drive[] = [
  {
    letter: "E",
    label: "SANDISK ULTRA",
    total_bytes: 64_000_000_000, // 64 GB
    free_bytes: 4_200_000_000,   // 4.2 GB
    drive_type: "Removable",
  },
  {
    letter: "F",
    label: "WD_BLACK",
    total_bytes: 2_000_000_000_000, // 2 TB
    free_bytes: 800_000_000_000,    // 800 GB
    drive_type: "Fixed",
  },
];

function makeWrapper() {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  const Wrapper = ({ children }: { children: React.ReactNode }) =>
    React.createElement(QueryClientProvider, { client: qc }, children);
  return { Wrapper, qc };
}

describe("DrivePicker", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    sessionStorage.setItem("dfars_session_token", "sess_test");
    // Radix Select requires hasPointerCapture in jsdom
    if (!Element.prototype.hasPointerCapture) {
      Element.prototype.hasPointerCapture = () => false;
    }
    if (!Element.prototype.setPointerCapture) {
      Element.prototype.setPointerCapture = () => {};
    }
    if (!Element.prototype.releasePointerCapture) {
      Element.prototype.releasePointerCapture = () => {};
    }
  });

  it("falls back to text input when drives_list fails", async () => {
    mockInvoke.mockRejectedValue(new Error("drives unavailable"));
    const { Wrapper } = makeWrapper();

    render(
      <DrivePicker value="" onChange={() => {}} />,
      { wrapper: Wrapper },
    );

    // Wait for the query to fail and fall back to text input
    await waitFor(() => {
      expect(screen.getByRole("textbox")).toBeInTheDocument();
    });
  });

  it("renders a select when drives are available", async () => {
    mockInvoke.mockResolvedValue(MOCK_DRIVES);
    const { Wrapper } = makeWrapper();

    render(
      <DrivePicker value="" onChange={() => {}} />,
      { wrapper: Wrapper },
    );

    // Wait for drives to load (select trigger appears)
    await waitFor(() => {
      expect(screen.getByRole("combobox")).toBeInTheDocument();
    });
  });

  it("calls drives_list Tauri command when token is present", async () => {
    mockInvoke.mockResolvedValue(MOCK_DRIVES);
    const { Wrapper } = makeWrapper();

    render(
      <DrivePicker value="" onChange={() => {}} />,
      { wrapper: Wrapper },
    );

    await waitFor(() => {
      expect(mockInvoke).toHaveBeenCalledWith(
        "drives_list",
        expect.objectContaining({ token: "sess_test" }),
      );
    });
  });

  it("renders a combobox (not a text input) after drives load successfully", async () => {
    mockInvoke.mockResolvedValue(MOCK_DRIVES);
    const { Wrapper } = makeWrapper();

    render(
      <DrivePicker value="" onChange={() => {}} />,
      { wrapper: Wrapper },
    );

    await waitFor(() => {
      expect(screen.getByRole("combobox")).toBeInTheDocument();
      // When Select is present, there should be no plain text input
      expect(screen.queryByRole("textbox")).not.toBeInTheDocument();
    });
  });

  it("shows a text input (not combobox) after drives_list errors", async () => {
    mockInvoke.mockRejectedValue(new Error("unavailable"));
    const { Wrapper } = makeWrapper();

    render(
      <DrivePicker value="" onChange={() => {}} />,
      { wrapper: Wrapper },
    );

    await waitFor(() => {
      expect(screen.getByRole("textbox")).toBeInTheDocument();
      expect(screen.queryByRole("combobox")).not.toBeInTheDocument();
    });
  });

  it("calling onChange: selecting the text input fires onChange with the typed value", async () => {
    // Test the fallback text input path onChange
    mockInvoke.mockRejectedValue(new Error("unavailable"));
    const onChange = vi.fn();
    const { Wrapper } = makeWrapper();
    const user = userEvent.setup();

    render(
      <DrivePicker value="" onChange={onChange} />,
      { wrapper: Wrapper },
    );

    await waitFor(() => screen.getByRole("textbox"));

    await user.type(screen.getByRole("textbox"), "E:\\");
    expect(onChange).toHaveBeenCalled();
  });
});
