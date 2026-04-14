/**
 * GraphCanvas — Cytoscape.js network graph for link analysis.
 *
 * Props:
 *   caseId       — the case being visualized
 *   filter       — GraphFilter (entity_types, include_evidence)
 *   onNodeClick? — called with the node id string when a node is clicked
 *
 * Filter controls live ABOVE this component in the parent route.
 * This component is pure: it owns the Cytoscape lifecycle only.
 *
 * Cleanup: cy.destroy() in the useEffect cleanup — mandatory to avoid leaks.
 */

import React from "react";
import { useQuery } from "@tanstack/react-query";
import cytoscape from "cytoscape";

import { caseGraph } from "@/lib/bindings";
import type { GraphFilter } from "@/lib/bindings";
import { getToken } from "@/lib/session";
import { queryKeys } from "@/lib/query";
import { entityTypeColor } from "@/lib/link-analysis-enums";

interface GraphCanvasProps {
  caseId: string;
  filter: GraphFilter;
  onNodeClick?: (nodeId: string) => void;
}

/** Hex color for a node based on its kind + entity_type */
function nodeHex(kind: string, entity_type: string | null): string {
  if (kind === "evidence") return entityTypeColor("evidence").hex;
  if (
    entity_type &&
    [
      "person",
      "business",
      "phone",
      "email",
      "alias",
      "address",
      "account",
      "vehicle",
    ].includes(entity_type)
  ) {
    return entityTypeColor(
      entity_type as Parameters<typeof entityTypeColor>[0]
    ).hex;
  }
  return "#888";
}

export function GraphCanvas({ caseId, filter, onNodeClick }: GraphCanvasProps) {
  const token = getToken() ?? "";
  const containerRef = React.useRef<HTMLDivElement>(null);
  const cyRef = React.useRef<cytoscape.Core | null>(null);

  const { data, isLoading, isError } = useQuery({
    queryKey: queryKeys.graph.forCase(caseId, filter),
    queryFn: () => caseGraph({ token, case_id: caseId, filter }),
    enabled: !!token,
  });

  // Build / rebuild Cytoscape instance when data changes
  React.useEffect(() => {
    // Always clean up the previous instance first
    if (cyRef.current) {
      cyRef.current.destroy();
      cyRef.current = null;
    }

    if (!containerRef.current || !data || data.nodes.length === 0) return;

    const elements: cytoscape.ElementDefinition[] = [
      ...data.nodes.map((n) => ({
        data: {
          id: n.id,
          label: n.label,
          kind: n.kind,
          entity_type: n.entity_type ?? "",
          nodeColor: nodeHex(n.kind, n.entity_type),
        },
        classes: [n.kind, n.entity_type ?? ""].filter(Boolean).join(" "),
      })),
      ...data.edges.map((e) => ({
        data: {
          id: e.id,
          source: e.source,
          target: e.target,
          label: e.label ?? "",
          weight: e.weight,
        },
        classes: e.directional ? "directed" : "undirected",
      })),
    ];

    const cy = cytoscape({
      container: containerRef.current,
      elements,
      style: [
        {
          selector: "node",
          style: {
            "background-color": "data(nodeColor)",
            label: "data(label)",
            color: "#e9ecef",
            "font-size": 12,
            "text-valign": "center",
            "text-halign": "center",
            "text-outline-color": "#12151a",
            "text-outline-width": 2,
            width: 42,
            height: 42,
          },
        },
        {
          selector: "node[kind='evidence']",
          style: {
            shape: "rectangle" as cytoscape.Css.NodeShape,
            width: 50,
            height: 30,
            "font-size": 10,
          },
        },
        {
          selector: "edge",
          style: {
            width: 1.5,
            "line-color": "#7a8597",
            "target-arrow-color": "#7a8597",
            "target-arrow-shape": "none",
            "curve-style": "bezier",
            label: "data(label)",
            color: "#adb5bd",
            "font-size": 10,
            "text-background-color": "#12151a",
            "text-background-opacity": 0.8,
            "text-background-padding": "2px",
          },
        },
        {
          selector: "edge.directed",
          style: {
            "target-arrow-shape": "triangle",
          },
        },
        {
          selector: "node:selected",
          style: {
            "border-width": 3,
            "border-color": "#60a5fa",
          },
        },
      ],
      layout: {
        name: "cose",
        padding: 30,
        animate: true,
        nodeRepulsion: () => 4500,
        idealEdgeLength: () => 100,
        nodeOverlap: 20,
        fit: true,
      } as cytoscape.LayoutOptions,
    });

    if (onNodeClick) {
      cy.on("tap", "node", (evt) => {
        onNodeClick((evt.target as cytoscape.NodeSingular).id());
      });
    }

    cyRef.current = cy;

    return () => {
      cy.destroy();
      cyRef.current = null;
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [data, onNodeClick]);

  const isEmpty = data && data.nodes.length === 0;

  return (
    <div className="relative" style={{ height: "calc(100vh - 280px)", minHeight: "480px" }}>
      {isLoading && (
        <div className="absolute inset-0 flex items-center justify-center text-sm text-muted-foreground z-10">
          Loading graph…
        </div>
      )}
      {isError && (
        <div className="absolute inset-0 flex items-center justify-center text-sm text-destructive z-10">
          Failed to load graph. Check your connection and try again.
        </div>
      )}
      {isEmpty && !isLoading && (
        <div className="absolute inset-0 flex flex-col items-center justify-center text-center gap-3 z-10 p-8">
          <p className="text-muted-foreground text-sm max-w-sm">
            No entities or evidence match the current filter. Add entities and
            links on the Manage panel, or adjust the type filter above.
          </p>
        </div>
      )}
      <div
        ref={containerRef}
        className="w-full h-full rounded-md border bg-[#12151a]"
        style={{ display: isEmpty || isLoading || isError ? "none" : "block" }}
      />
    </div>
  );
}
