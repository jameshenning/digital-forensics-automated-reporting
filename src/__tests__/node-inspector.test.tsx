/**
 * Tests for NodeInspector — verifies the four render paths
 * (entity / evidence / identifier / not_found) and the closed
 * state. Mocks `node_inspector` invoke at the boundary.
 */

import { describe, it, expect, vi, beforeEach } from "vitest";
import { render, screen, waitFor } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import React from "react";

vi.mock("@tauri-apps/api/core", () => ({
  invoke: vi.fn(),
}));

import { invoke } from "@tauri-apps/api/core";
import type { InspectorPayload } from "@/lib/bindings";

const MOCK_TOKEN = "sess_inspector_test";
beforeEach(() => {
  sessionStorage.setItem("dfars_session_token", MOCK_TOKEN);
  vi.clearAllMocks();
});

function makeWrapper() {
  const queryClient = new QueryClient({
    defaultOptions: { queries: { retry: false, refetchOnWindowFocus: false } },
  });
  const Wrapper = ({ children }: { children: React.ReactNode }) =>
    React.createElement(QueryClientProvider, { client: queryClient }, children);
  return { Wrapper };
}

const ENTITY_PAYLOAD: InspectorPayload = {
  kind: "entity",
  entity_id: 42,
  entity_type: "person",
  display_name: "Alice Test",
  subtype: "suspect",
  photo_path: null,
  email: null,
  phone: null,
  username: null,
  employer: null,
  dob: null,
  notes: null,
  identifiers: [
    {
      identifier_id: 1,
      kind: "email",
      value: "alice@example.com",
      platform: null,
      notes: null,
      discovered_via_tool: null,
    },
  ],
  linked_entity_count: 3,
  linked_evidence_count: 1,
};

const EVIDENCE_PAYLOAD: InspectorPayload = {
  kind: "evidence",
  evidence: {
    evidence_id: "EV-INSP-1",
    case_id: "CASE-1",
    description: "Laptop seized at scene",
    collected_by: "Officer A",
    collection_datetime: "2026-04-12T14:30:00",
    location: "Warehouse 4",
    status: "Collected",
    evidence_type: "device",
    make_model: null,
    serial_number: null,
    storage_location: null,
  },
  linked_entity_count: 2,
  hash_verification_count: 1,
  latest_custody: {
    action: "Transferred",
    from_party: "Officer A",
    to_party: "Lab Tech",
    custody_datetime: "2026-04-13T10:00:00",
    location: "Lab",
  },
};

const IDENTIFIER_PAYLOAD: InspectorPayload = {
  kind: "identifier",
  identifier_kind: "email",
  value: "shared@example.com",
  platform: null,
  notes: null,
  discovered_via_tool: "sherlock",
  owners: [
    { entity_id: 1, display_name: "Alice", entity_type: "person" },
    { entity_id: 2, display_name: "Acme", entity_type: "business" },
  ],
};

describe("NodeInspector", () => {
  it("renders nothing when nodeId is null (sheet closed)", async () => {
    const { NodeInspector } = await import("@/components/node-inspector");
    const { Wrapper } = makeWrapper();

    render(
      React.createElement(Wrapper, null,
        React.createElement(NodeInspector, {
          caseId: "CASE-1",
          nodeId: null,
          onClose: () => {},
        })
      )
    );

    expect(invoke).not.toHaveBeenCalled();
  });

  it("renders entity body with link counts and identifiers", async () => {
    vi.mocked(invoke).mockResolvedValue(ENTITY_PAYLOAD);

    const { NodeInspector } = await import("@/components/node-inspector");
    const { Wrapper } = makeWrapper();

    render(
      React.createElement(Wrapper, null,
        React.createElement(NodeInspector, {
          caseId: "CASE-1",
          nodeId: "entity:42",
          onClose: () => {},
        })
      )
    );

    await waitFor(() =>
      expect(screen.getAllByText(/Alice Test/).length).toBeGreaterThan(0)
    );
    expect(screen.getByText("alice@example.com")).toBeInTheDocument();
    expect(screen.getByText("3")).toBeInTheDocument(); // linked entities count
    expect(screen.getByText("1")).toBeInTheDocument(); // linked evidence count
  });

  it("renders evidence body with latest custody", async () => {
    vi.mocked(invoke).mockResolvedValue(EVIDENCE_PAYLOAD);

    const { NodeInspector } = await import("@/components/node-inspector");
    const { Wrapper } = makeWrapper();

    render(
      React.createElement(Wrapper, null,
        React.createElement(NodeInspector, {
          caseId: "CASE-1",
          nodeId: "evidence:EV-INSP-1",
          onClose: () => {},
        })
      )
    );

    await waitFor(() =>
      expect(screen.getAllByText(/EV-INSP-1/).length).toBeGreaterThan(0)
    );
    expect(screen.getByText(/Laptop seized at scene/)).toBeInTheDocument();
    expect(screen.getByText(/Lab Tech/)).toBeInTheDocument();
  });

  it("renders identifier body with shared-by badge for ≥2 owners", async () => {
    vi.mocked(invoke).mockResolvedValue(IDENTIFIER_PAYLOAD);

    const { NodeInspector } = await import("@/components/node-inspector");
    const { Wrapper } = makeWrapper();

    render(
      React.createElement(Wrapper, null,
        React.createElement(NodeInspector, {
          caseId: "CASE-1",
          nodeId: "identifier:1",
          onClose: () => {},
        })
      )
    );

    await waitFor(() =>
      expect(screen.getAllByText(/shared@example.com/).length).toBeGreaterThan(0)
    );
    expect(screen.getByText(/shared by 2/i)).toBeInTheDocument();
    expect(screen.getByText("Alice")).toBeInTheDocument();
    expect(screen.getByText("Acme")).toBeInTheDocument();
  });

  it("renders not_found gracefully for stale nodes", async () => {
    vi.mocked(invoke).mockResolvedValue({ kind: "not_found" });

    const { NodeInspector } = await import("@/components/node-inspector");
    const { Wrapper } = makeWrapper();

    render(
      React.createElement(Wrapper, null,
        React.createElement(NodeInspector, {
          caseId: "CASE-1",
          nodeId: "entity:99999",
          onClose: () => {},
        })
      )
    );

    await waitFor(() =>
      expect(screen.getByText(/no longer available/i)).toBeInTheDocument()
    );
  });
});
