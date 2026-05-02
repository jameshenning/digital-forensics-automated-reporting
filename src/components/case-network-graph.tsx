/**
 * CaseNetworkGraph — native React replacement for Grafana's "DFARS Network Graph" dashboard.
 *
 * Uses AntV G6 (via Graphin React wrapper) for high-quality network visualization.
 * Features: force-directed layout, zoom, pan, hover tooltips, node click inspector.
 */

import { useMemo, useState, useCallback, useEffect, lazy, Suspense } from "react";
import { useQuery } from "@tanstack/react-query";
import { Network } from "lucide-react";
// AntV Graphin disabled for debugging — dynamic import causes WebView crash
function Graphin({ options, onReady, style, id: _id }: { options?: any; onReady?: (graph: any) => void; style?: React.CSSProperties; id?: string }) {
  useEffect(() => {
    onReady?.({ on: () => {}, once: () => {}, fitView: () => {} });
  }, [onReady]);
  return (
    <div className="flex items-center justify-center h-full text-muted-foreground text-sm" style={style}>
      Graph placeholder (AntV G6 disabled for debugging)
      <br />
      Nodes: {options?.data?.nodes?.length ?? 0} | Edges: {options?.data?.edges?.length ?? 0}
    </div>
  );
}

import { caseDashboardGraph } from "@/lib/bindings";
import type { DashboardGraphPayload } from "@/lib/bindings";
import { getToken } from "@/lib/session";
import { queryKeys } from "@/lib/query";
import { Skeleton } from "@/components/ui/skeleton";
import {
  Sheet,
  SheetContent,
  SheetHeader,
  SheetTitle,
} from "@/components/ui/sheet";

// Lazy-load NodeInspector (heavy, only needed on click)
const NodeInspectorLazy = lazy(() =>
  import("@/components/node-inspector").then((m) => ({
    default: m.NodeInspector,
  }))
);


interface CaseNetworkGraphProps {
  caseId: string;
}

// ---------------------------------------------------------------------------
// Transform backend payload → G6 v5 data format
// ---------------------------------------------------------------------------

function toG6Data(payload: DashboardGraphPayload) {
  return {
    nodes: payload.nodes.map((n) => ({
      id: n.id,
      data: {
        label: n.title,
        subLabel: n.subtitle,
        color: n.color,
        mainStat: n.mainStat,
      },
    })),
    edges: payload.edges.map((e) => ({
      id: e.id,
      source: e.source,
      target: e.target,
      data: {
        label: e.mainStat,
      },
    })),
  };
}

// ---------------------------------------------------------------------------
// Color map from backend palette → G6 hex colors
// ---------------------------------------------------------------------------

const COLOR_HEX: Record<string, string> = {
  red: "#ef4444",
  blue: "#3b82f6",
  green: "#22c55e",
  purple: "#a855f7",
  orange: "#f97316",
  gray: "#6b7280",
  cyan: "#06b6d4",
  yellow: "#eab308",
};

function nodeFill(color: string): string {
  return COLOR_HEX[color] ?? color; // pass through if already hex
}

// ---------------------------------------------------------------------------
// Component
// ---------------------------------------------------------------------------

export function CaseNetworkGraph({ caseId }: CaseNetworkGraphProps) {
  const token = getToken() ?? "";
  const [selectedNodeId, setSelectedNodeId] = useState<string | null>(null);

  const { data, isLoading } = useQuery({
    queryKey: [...queryKeys.cases.detail(caseId), "dashboard", "graph"],
    queryFn: () => caseDashboardGraph({ token, case_id: caseId }),
    enabled: !!token,
  });

  const g6Data = useMemo(() => (data ? toG6Data(data) : { nodes: [], edges: [] }), [data]);

  const handleNodeClick = useCallback((evt: { target: { id: string } }) => {
    setSelectedNodeId(evt.target.id);
  }, []);

  if (isLoading) {
    return (
      <div className="rounded-lg border bg-[#12151a]" style={{ height: "60vh", minHeight: 400 }}>
        <Skeleton className="h-full w-full" />
      </div>
    );
  }

  return (
    <div className="space-y-2">
      <div className="flex items-center gap-2">
        <Network className="h-4 w-4 text-muted-foreground" />
        <h3 className="text-sm font-semibold">Entity Network Graph</h3>
      </div>

      <div className="rounded-lg border bg-[#12151a]" style={{ height: "60vh", minHeight: 400 }}>
        <Graphin
          id={`case-network-graph-${caseId}`}
          style={{ width: "100%", height: "100%" }}
          options={{
            data: g6Data,
            background: "#12151a",
            node: {
              type: "circle",
              style: {
                size: 24,
                fill: (d: { data?: { color?: string } }) => nodeFill(d.data?.color ?? "gray"),
                stroke: "#1f2937",
                lineWidth: 2,
                labelText: (d: { data?: { label?: string } }) => d.data?.label ?? "",
                labelFill: "#e5e7eb",
                labelFontSize: 11,
                labelBackground: true,
                labelBackgroundFill: "#12151a",
                labelBackgroundOpacity: 0.85,
                labelBackgroundPadding: [2, 4],
                iconText: (d: { data?: { subLabel?: string } }) =>
                  d.data?.subLabel?.charAt(0).toUpperCase() ?? "",
                iconFontSize: 10,
                iconFill: "#fff",
              },
              palette: undefined as unknown as undefined,
            },
            edge: {
              type: "line",
              style: {
                stroke: "#4b5563",
                lineWidth: 1.5,
                labelText: (d: { data?: { label?: string } }) => d.data?.label ?? "",
                labelFill: "#9ca3af",
                labelFontSize: 9,
                labelBackground: true,
                labelBackgroundFill: "#12151a",
                labelBackgroundOpacity: 0.8,
                endArrow: true,
                endArrowSize: 6,
              },
            },
            layout: {
              type: "force",
              preventOverlap: true,
              nodeSize: 40,
              linkDistance: 120,
              clustering: false,
            },
            behaviors: [
              "zoom-canvas",
              "drag-canvas",
              "drag-element",
              {
                type: "hover-activate",
                degree: 1,
                state: "highlight",
                inactiveState: "dim",
                onClick: handleNodeClick,
              } as unknown as string,
            ],
            animation: {
              duration: 300,
            },
            theme: "dark",
          }}
          onReady={(graph) => {
            // Bind click event for node selection
            graph.on("node:click", (evt: unknown) => {
              const e = evt as { target: { id: string } };
              setSelectedNodeId(e.target.id);
            });
            // Fit to view after layout stabilizes
            graph.once("afterlayout", () => {
              graph.fitView({} as never, false);
            });
          }}
        />
      </div>

      {/* Node inspector sheet */}
      <Sheet
        open={selectedNodeId !== null}
        onOpenChange={(open) => {
          if (!open) setSelectedNodeId(null);
        }}
      >
        <SheetContent className="sm:max-w-md overflow-y-auto">
          <SheetHeader>
            <SheetTitle className="text-base">Node Details</SheetTitle>
          </SheetHeader>
          <div className="mt-4">
            <Suspense fallback={<Skeleton className="h-32 w-full" />}>
              <NodeInspectorLazy
                caseId={caseId}
                nodeId={selectedNodeId}
                onClose={() => setSelectedNodeId(null)}
              />
            </Suspense>
          </div>
        </SheetContent>
      </Sheet>
    </div>
  );
}
