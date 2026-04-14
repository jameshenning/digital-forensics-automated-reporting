/**
 * Tests for CrimeLineCanvas component.
 *
 * Strategy: mock case_crime_line, mock vis-timeline (jsdom can't render it),
 * render inside QueryClientProvider, assert mount + empty state behaviour.
 */

import { describe, it, expect, vi, beforeEach } from "vitest";
import { render, screen, waitFor } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import React from "react";

// ── Mock Tauri invoke ─────────────────────────────────────────────────────────
vi.mock("@tauri-apps/api/core", () => ({
  invoke: vi.fn(),
}));

// ── Mock vis-timeline/standalone ──────────────────────────────────────────────
vi.mock("vis-timeline/standalone", () => ({
  Timeline: vi.fn(() => ({ destroy: vi.fn() })),
  DataSet: vi.fn(() => ({})),
}));

vi.mock("vis-timeline/styles/vis-timeline-graph2d.min.css", () => ({}));

// ── Mock cytoscape (imported transitively) ────────────────────────────────────
vi.mock("cytoscape", () => ({
  default: vi.fn(() => ({ on: vi.fn(), destroy: vi.fn() })),
}));

import { invoke } from "@tauri-apps/api/core";
import type { TimelinePayload } from "@/lib/bindings";

const MOCK_TOKEN = "sess_crimelinetest";
beforeEach(() => {
  sessionStorage.setItem("dfars_session_token", MOCK_TOKEN);
  vi.clearAllMocks();
});

const MOCK_TIMELINE: TimelinePayload = {
  items: [
    {
      id: "event:1",
      group: "events",
      content: "Suspect observed",
      start: "2026-03-15T14:30:00",
      end: null,
      category: "observation",
      source_type: "investigator",
      source_table: "case_events",
    },
    {
      id: "auto:evidence:EV-001",
      group: "evidence",
      content: "EV-001 collected",
      start: "2026-03-10T10:00:00",
      end: null,
      category: null,
      source_type: "auto",
      source_table: "evidence",
    },
  ],
  groups: [
    { id: "events", content: "Events" },
    { id: "evidence", content: "Evidence" },
  ],
};

function makeWrapper() {
  const queryClient = new QueryClient({
    defaultOptions: { queries: { retry: false, refetchOnWindowFocus: false } },
  });
  const Wrapper = ({ children }: { children: React.ReactNode }) =>
    React.createElement(QueryClientProvider, { client: queryClient }, children);
  return { Wrapper };
}

describe("CrimeLineCanvas", () => {
  it("mounts without throwing when data has items", async () => {
    vi.mocked(invoke).mockResolvedValue(MOCK_TIMELINE);

    const { CrimeLineCanvas } = await import("@/components/crime-line-canvas");
    const { Wrapper } = makeWrapper();

    render(
      React.createElement(Wrapper, null,
        React.createElement(CrimeLineCanvas, {
          caseId: "CASE-001",
          filter: { start: null, end: null },
        })
      )
    );

    await waitFor(() => {
      expect(invoke).toHaveBeenCalledWith(
        "case_crime_line",
        expect.objectContaining({ case_id: "CASE-001" })
      );
    });

    // Empty state must NOT appear — we have items
    expect(
      screen.queryByText(/No timeline data yet/i)
    ).not.toBeInTheDocument();
  });

  it("shows empty state when timeline returns 0 items", async () => {
    vi.mocked(invoke).mockResolvedValue({ items: [], groups: [] });

    const { CrimeLineCanvas } = await import("@/components/crime-line-canvas");
    const { Wrapper } = makeWrapper();

    render(
      React.createElement(Wrapper, null,
        React.createElement(CrimeLineCanvas, {
          caseId: "CASE-002",
          filter: { start: null, end: null },
        })
      )
    );

    await waitFor(() => {
      expect(screen.getByText(/No timeline data yet/i)).toBeInTheDocument();
    });
  });
});
