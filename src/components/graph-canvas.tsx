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
import type { GraphFilter, GraphPayload } from "@/lib/bindings";
import { getToken } from "@/lib/session";
import { queryKeys } from "@/lib/query";
import { entityTypeColor, identifierKindHex } from "@/lib/link-analysis-enums";
import {
  computeNeighborhood,
  computeShortestPath,
  edgeKey,
  pathEdgeKeys,
  type GraphFocus,
} from "@/lib/graph-focus";

interface GraphCanvasProps {
  caseId: string;
  filter: GraphFilter;
  onNodeClick?: (nodeId: string) => void;
  /** When non-null, dim the graph except for the path/neighborhood
   *  highlighted by the focus descriptor. Computed against the current
   *  graph data — if the focus references a node not in the data
   *  (e.g., user filtered it out after setting focus), no highlight is
   *  applied and nothing is dimmed (graceful degradation). */
  focus?: GraphFocus | null;
}

/**
 * Apply path/neighborhood focus to a live cytoscape instance.
 * Idempotent — clears prior `dimmed`/`highlighted` classes before
 * re-applying. Safe to call with `focus = null` to fully reset.
 *
 * Uses the pure helpers from `@/lib/graph-focus` rather than
 * cytoscape's built-in `aStar`/`openNeighborhood` so the behavior
 * is unit-tested at the algorithm level (see graph-focus.test.ts).
 */
function applyFocusHighlight(
  cy: cytoscape.Core,
  focus: GraphFocus | null,
  data: GraphPayload,
): void {
  cy.elements().removeClass("dimmed highlighted");
  if (!focus) return;

  let highlightedNodes = new Set<string>();
  let highlightedEdgeKeys = new Set<string>();

  if (focus.kind === "path") {
    if (!focus.target) return; // pending — user has set source but not target yet
    const path = computeShortestPath(data.edges, focus.source, focus.target);
    if (!path) return; // disconnected — banner explains, don't dim everything
    highlightedNodes = new Set(path);
    highlightedEdgeKeys = pathEdgeKeys(path);
  } else if (focus.kind === "neighborhood") {
    highlightedNodes = computeNeighborhood(data.edges, focus.center, focus.hops);
    // For neighborhood, every edge whose BOTH endpoints survive is highlighted.
    for (const e of data.edges) {
      if (highlightedNodes.has(e.source) && highlightedNodes.has(e.target)) {
        highlightedEdgeKeys.add(edgeKey(e.source, e.target));
      }
    }
  }

  cy.nodes().forEach((n) => {
    n.addClass(highlightedNodes.has(n.id()) ? "highlighted" : "dimmed");
  });
  cy.edges().forEach((e) => {
    const src = e.data("source") as string;
    const tgt = e.data("target") as string;
    e.addClass(
      highlightedEdgeKeys.has(edgeKey(src, tgt)) ? "highlighted" : "dimmed",
    );
  });
}

/** Hex color for a node based on its kind + entity_type. Identifier
 *  nodes carry the identifier kind in `entity_type` (email/phone/etc.)
 *  and pick from the identifier palette. */
function nodeHex(kind: string, entity_type: string | null): string {
  if (kind === "evidence") return entityTypeColor("evidence").hex;
  if (kind === "identifier" && entity_type) {
    return identifierKindHex(entity_type);
  }
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

export function GraphCanvas({ caseId, filter, onNodeClick, focus }: GraphCanvasProps) {
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
      ...data.edges.map((e) => {
        // has_identifier edges (id starts with "has:") are visually
        // softer than user-authored entity_links — same data class
        // (the entity owns the identifier), but lower informational
        // weight than an investigator-asserted link.
        const isHasEdge = e.id.startsWith("has:");
        const edgeClasses = [
          e.directional ? "directed" : "undirected",
          isHasEdge ? "has-identifier" : "",
        ]
          .filter(Boolean)
          .join(" ");
        return {
          data: {
            id: e.id,
            source: e.source,
            target: e.target,
            label: e.label ?? "",
            weight: e.weight,
          },
          classes: edgeClasses,
        };
      }),
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
          selector: "node[kind='identifier']",
          style: {
            shape: "diamond" as cytoscape.Css.NodeShape,
            width: 30,
            height: 30,
            "font-size": 9,
            "text-max-width": "120px",
            "text-wrap": "ellipsis",
            "border-width": 1,
            "border-color": "#1f2937",
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
          selector: "edge.has-identifier",
          style: {
            "line-color": "#4b5563",
            "line-style": "dashed" as cytoscape.Css.LineStyle,
            width: 1,
            label: "", // platform shows in inspector (feature #2), not on canvas
          },
        },
        // Focus mode (feature #3): "dimmed" pushes everything off-path
        // to background opacity; "highlighted" amber-rings the
        // surviving nodes/edges so the path or neighborhood pops.
        {
          selector: ".dimmed",
          style: {
            opacity: 0.18,
            "text-opacity": 0.18,
          },
        },
        {
          selector: "node.highlighted",
          style: {
            "border-width": 3,
            "border-color": "#fbbf24",
          },
        },
        {
          selector: "edge.highlighted",
          style: {
            "line-color": "#fbbf24",
            "target-arrow-color": "#fbbf24",
            width: 3,
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

  // Apply focus highlighting whenever focus or the underlying data
  // changes. Runs SECOND in declaration order, so when data changes
  // and the build effect re-creates the cy instance above, this
  // effect re-applies the existing focus on the new instance.
  React.useEffect(() => {
    const cy = cyRef.current;
    if (!cy || !data) return;
    applyFocusHighlight(cy, focus ?? null, data);
  }, [focus, data]);

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
