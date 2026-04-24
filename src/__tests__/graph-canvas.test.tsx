/**
 * Tests for GraphCanvas component.
 *
 * Strategy: mock case_graph to return 3 nodes + 2 edges, mock cytoscape
 * (it doesn't work in jsdom), render the component inside a QueryClientProvider,
 * and assert:
 *  - The component mounts without throwing
 *  - The wrapper div is in the DOM
 *  - The empty-state text is NOT shown (we have data)
 */

import { describe, it, expect, vi, beforeEach } from "vitest";
import { render, screen, waitFor } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import React from "react";

// ── Mock Tauri invoke before any bindings import ──────────────────────────────
vi.mock("@tauri-apps/api/core", () => ({
  invoke: vi.fn(),
}));

// ── Mock cytoscape — it can't run in jsdom ────────────────────────────────────
vi.mock("cytoscape", () => ({
  default: vi.fn(() => ({
    on: vi.fn(),
    destroy: vi.fn(),
  })),
}));

// ── Mock vis-timeline/standalone — it also can't run in jsdom ─────────────────
vi.mock("vis-timeline/standalone", () => ({
  Timeline: vi.fn(() => ({ destroy: vi.fn() })),
  DataSet: vi.fn(() => ({})),
}));

vi.mock("vis-timeline/styles/vis-timeline-graph2d.min.css", () => ({}));

import { invoke } from "@tauri-apps/api/core";
import type { GraphPayload } from "@/lib/bindings";

// Seed a token so the query is enabled
const MOCK_TOKEN = "sess_graphtest";
beforeEach(() => {
  sessionStorage.setItem("dfars_session_token", MOCK_TOKEN);
  vi.clearAllMocks();
});

const MOCK_GRAPH: GraphPayload = {
  nodes: [
    { id: "entity:1", label: "Alice Smith", kind: "entity", entity_type: "person", subtype: "suspect" },
    { id: "entity:2", label: "Acme Corp", kind: "entity", entity_type: "business", subtype: null },
    { id: "evidence:EV-001", label: "EV-001", kind: "evidence", entity_type: null, subtype: null },
  ],
  edges: [
    { id: "link:1", source: "entity:1", target: "entity:2", label: "works for", directional: true, weight: 1 },
    { id: "link:2", source: "entity:2", target: "evidence:EV-001", label: null, directional: false, weight: 1 },
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

describe("GraphCanvas", () => {
  it("mounts without throwing and renders the container div", async () => {
    vi.mocked(invoke).mockResolvedValue(MOCK_GRAPH);

    // Import here so mocks are already in place
    const { GraphCanvas } = await import("@/components/graph-canvas");
    const { Wrapper } = makeWrapper();

    render(
      React.createElement(Wrapper, null,
        React.createElement(GraphCanvas, {
          caseId: "CASE-001",
          filter: { entity_types: null, include_evidence: true, include_identifiers: false, only_shared_identifiers: false },
        })
      )
    );

    // Wait for the query to resolve
    await waitFor(() => {
      expect(invoke).toHaveBeenCalledWith(
        "case_graph",
        expect.objectContaining({ case_id: "CASE-001" })
      );
    });

    // The empty state text must NOT appear — we have 3 nodes
    expect(
      screen.queryByText(/No entities or evidence match/i)
    ).not.toBeInTheDocument();
  });

  it("shows empty state when graph returns 0 nodes", async () => {
    vi.mocked(invoke).mockResolvedValue({ nodes: [], edges: [] });

    const { GraphCanvas } = await import("@/components/graph-canvas");
    const { Wrapper } = makeWrapper();

    render(
      React.createElement(Wrapper, null,
        React.createElement(GraphCanvas, {
          caseId: "CASE-002",
          filter: { entity_types: null, include_evidence: false, include_identifiers: false, only_shared_identifiers: false },
        })
      )
    );

    await waitFor(() => {
      expect(
        screen.getByText(/No entities or evidence match/i)
      ).toBeInTheDocument();
    });
  });
});
