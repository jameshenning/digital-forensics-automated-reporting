/**
 * CrimeLineCanvas — vis-timeline crime-line for link analysis.
 *
 * Props:
 *   caseId  — the case being visualized
 *   filter  — TimelineFilter (start, end)
 *
 * Filter controls live ABOVE this component in the parent route.
 *
 * Cleanup: timeline.destroy() in the useEffect cleanup — mandatory.
 */

import React from "react";
import { useQuery } from "@tanstack/react-query";
import { Timeline } from "vis-timeline/standalone";
import { DataSet } from "vis-data";
import type { DataItem, TimelineGroup as VisGroup, TimelineOptions } from "vis-timeline";

import { caseCrimeLine } from "@/lib/bindings";
import type { TimelineFilter } from "@/lib/bindings";
import { getToken } from "@/lib/session";
import { queryKeys } from "@/lib/query";

// Import vis-timeline CSS
import "vis-timeline/styles/vis-timeline-graph2d.min.css";

// ---------------------------------------------------------------------------
// Category -> background color mapping (matches v1 link_analysis.html)
// ---------------------------------------------------------------------------

const CATEGORY_BG: Record<string, string> = {
  observation: "#0096c7",
  communication: "#20c997",
  movement: "#fd7e14",
  custodial: "#ffc107",
  other: "#6c757d",
  evidence: "#adb5bd",
  custody: "#d63384",
  hashes: "#6610f2",
  tools: "#dc3545",
  analysis: "#198754",
};

function itemStyle(
  category: string | null,
  sourceType: string
): string {
  const bg = category
    ? (CATEGORY_BG[category] ?? CATEGORY_BG.other)
    : sourceType === "investigator"
    ? CATEGORY_BG.observation
    : "#6c757d";
  const borderStyle = sourceType === "auto" ? "dashed" : "solid";
  return `background-color:${bg};border-style:${borderStyle};`;
}

interface CrimeLineCanvasProps {
  caseId: string;
  filter: TimelineFilter;
}

export function CrimeLineCanvas({ caseId, filter }: CrimeLineCanvasProps) {
  const token = getToken() ?? "";
  const containerRef = React.useRef<HTMLDivElement>(null);
  const timelineRef = React.useRef<Timeline | null>(null);

  const { data, isLoading, isError } = useQuery({
    queryKey: queryKeys.crimeLine.forCase(caseId, filter),
    queryFn: () =>
      caseCrimeLine({
        token,
        case_id: caseId,
        filter,
      }),
    enabled: !!token,
  });

  React.useEffect(() => {
    // Clean up the previous instance
    if (timelineRef.current) {
      timelineRef.current.destroy();
      timelineRef.current = null;
    }

    if (!containerRef.current || !data || data.items.length === 0) return;

    const items = new DataSet<DataItem>(
      data.items.map((item) => ({
        id: item.id,
        group: item.group,
        content: item.content,
        start: new Date(item.start),
        end: item.end ? new Date(item.end) : undefined,
        style: itemStyle(item.category, item.source_type),
        title: item.content,
      }))
    );

    const groups = new DataSet<VisGroup>(
      data.groups.map((g) => ({
        id: g.id,
        content: g.content,
      }))
    );

    const options: TimelineOptions = {
      stack: true,
      showCurrentTime: true,
      orientation: { axis: "bottom", item: "top" },
      margin: { item: 8, axis: 12 },
      zoomMin: 1000 * 60, // 1 minute
      zoomMax: 1000 * 60 * 60 * 24 * 365 * 5, // 5 years
      tooltip: { followMouse: true, overflowMethod: "flip" },
    };

    const timeline = new Timeline(containerRef.current, items, groups, options);
    timelineRef.current = timeline;

    return () => {
      timeline.destroy();
      timelineRef.current = null;
    };
  }, [data]);

  const isEmpty = data && data.items.length === 0;

  return (
    <div className="relative" style={{ height: "calc(100vh - 280px)", minHeight: "480px" }}>
      {isLoading && (
        <div className="absolute inset-0 flex items-center justify-center text-sm text-muted-foreground z-10">
          Loading crime line…
        </div>
      )}
      {isError && (
        <div className="absolute inset-0 flex items-center justify-center text-sm text-destructive z-10">
          Failed to load crime line. Check your connection and try again.
        </div>
      )}
      {isEmpty && !isLoading && (
        <div className="absolute inset-0 flex flex-col items-center justify-center text-center gap-3 z-10 p-8">
          <p className="text-muted-foreground text-sm max-w-sm">
            No timeline data yet. Add case events on the Manage panel, or widen
            the date range filter above.
          </p>
        </div>
      )}
      <div
        ref={containerRef}
        className="w-full h-full rounded-md border"
        style={{ display: isEmpty || isLoading || isError ? "none" : "block" }}
      />
    </div>
  );
}
