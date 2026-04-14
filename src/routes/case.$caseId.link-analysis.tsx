/**
 * /case/:caseId/link-analysis — full-viewport link analysis page (Phase 4).
 *
 * Layout:
 *   - Top header: back button + case name + "Manage" button (opens Sheet)
 *   - Shadcn Tabs: Network Graph | Crime Line
 *   - Graph tab: filter bar (entity types, include_evidence toggle, reset) + GraphCanvas
 *   - Crime Line tab: filter bar (start/end datetime, reset) + CrimeLineCanvas
 *
 * The Manage Sheet contains three stacked panels:
 *   EntitiesPanel, LinksPanel, EventsPanel
 */

import React, { lazy, Suspense } from "react";
import { createFileRoute, useNavigate } from "@tanstack/react-router";
import { useQuery } from "@tanstack/react-query";
import {
  ArrowLeft,
  Network,
  Clock,
  SlidersHorizontal,
  RotateCcw,
} from "lucide-react";

import { requireAuthBeforeLoad } from "@/lib/auth-guard";
import { caseGet } from "@/lib/bindings";
import type { GraphFilter, TimelineFilter } from "@/lib/bindings";
import { getToken } from "@/lib/session";
import { queryKeys } from "@/lib/query";
import { ENTITY_TYPES } from "@/lib/link-analysis-enums";
import { entityTypeColor } from "@/lib/link-analysis-enums";

import { Button } from "@/components/ui/button";
import { Skeleton } from "@/components/ui/skeleton";
import { Tabs, TabsList, TabsTrigger, TabsContent } from "@/components/ui/tabs";
import {
  Sheet,
  SheetContent,
  SheetHeader,
  SheetTitle,
  SheetTrigger,
} from "@/components/ui/sheet";
import { Switch } from "@/components/ui/switch";
import { Separator } from "@/components/ui/separator";

// Lazy-load the heavy canvas components (Cytoscape ~300 KB + vis-timeline ~600 KB).
// They are only needed on this route and account for ~900 KB of the bundle.
// Each is wrapped in a Suspense boundary with a skeleton fallback so the
// filter bar + tabs render immediately while the chunk loads.
const GraphCanvas = lazy(() =>
  import("@/components/graph-canvas").then((m) => ({ default: m.GraphCanvas }))
);
const CrimeLineCanvas = lazy(() =>
  import("@/components/crime-line-canvas").then((m) => ({
    default: m.CrimeLineCanvas,
  }))
);

import { EntitiesPanel } from "@/components/entities-panel";
import { LinksPanel } from "@/components/links-panel";
import { EventsPanel } from "@/components/events-panel";

// ---------------------------------------------------------------------------
// Suspense fallback skeletons
// ---------------------------------------------------------------------------

/** Full-height placeholder shown while the GraphCanvas chunk is loading. */
function GraphCanvasSkeleton() {
  return (
    <div className="flex flex-col gap-2 h-full min-h-[400px]">
      <Skeleton className="h-8 w-48 rounded-md" />
      <Skeleton className="flex-1 rounded-md" />
    </div>
  );
}

/** Full-height placeholder shown while the CrimeLineCanvas chunk is loading. */
function CrimeLineCanvasSkeleton() {
  return (
    <div className="flex flex-col gap-2 h-full min-h-[300px]">
      <Skeleton className="h-6 w-64 rounded-md" />
      <Skeleton className="flex-1 rounded-md" />
    </div>
  );
}

export const Route = createFileRoute("/case/$caseId/link-analysis")({
  beforeLoad: requireAuthBeforeLoad,
  component: LinkAnalysisPage,
});

// ---------------------------------------------------------------------------
// Default filter state
// ---------------------------------------------------------------------------

const DEFAULT_GRAPH_FILTER: GraphFilter = {
  entity_types: null, // all
  include_evidence: true,
};

const DEFAULT_TIMELINE_FILTER: TimelineFilter = {
  start: null,
  end: null,
};

// ---------------------------------------------------------------------------
// Page
// ---------------------------------------------------------------------------

function LinkAnalysisPage() {
  const { caseId } = Route.useParams();
  const navigate = useNavigate();
  const token = getToken() ?? "";

  // Fetch case name for the header
  const { data: caseData } = useQuery({
    queryKey: queryKeys.cases.detail(caseId),
    queryFn: () => caseGet({ token, case_id: caseId }),
    enabled: !!token,
  });

  const caseName = caseData?.case.case_name ?? caseId;

  // ---------------------------------------------------------------------------
  // Graph filter state
  // ---------------------------------------------------------------------------

  const [graphFilter, setGraphFilter] = React.useState<GraphFilter>(
    DEFAULT_GRAPH_FILTER
  );

  function toggleEntityType(type: (typeof ENTITY_TYPES)[number]) {
    setGraphFilter((prev) => {
      const current = prev.entity_types ?? [...ENTITY_TYPES];
      const next = current.includes(type)
        ? current.filter((t) => t !== type)
        : [...current, type];
      // If all types selected, normalize to null
      return {
        ...prev,
        entity_types:
          next.length === ENTITY_TYPES.length ? null : next.length === 0 ? [] : next,
      };
    });
  }

  function isTypeSelected(type: (typeof ENTITY_TYPES)[number]): boolean {
    return graphFilter.entity_types === null
      ? true
      : graphFilter.entity_types.includes(type);
  }

  function resetGraphFilter() {
    setGraphFilter(DEFAULT_GRAPH_FILTER);
  }

  // ---------------------------------------------------------------------------
  // Timeline filter state
  // ---------------------------------------------------------------------------

  const [timelineFilter, setTimelineFilter] = React.useState<TimelineFilter>(
    DEFAULT_TIMELINE_FILTER
  );

  function resetTimelineFilter() {
    setTimelineFilter(DEFAULT_TIMELINE_FILTER);
  }

  // ---------------------------------------------------------------------------
  // Render
  // ---------------------------------------------------------------------------

  return (
    <div className="min-h-screen bg-background flex flex-col">
      {/* Header */}
      <header className="border-b px-4 py-3 flex items-center justify-between gap-3 shrink-0">
        <div className="flex items-center gap-3 min-w-0">
          <Button
            variant="ghost"
            size="sm"
            className="-ml-2 shrink-0"
            onClick={() =>
              void navigate({
                to: "/case/$caseId",
                params: { caseId },
              })
            }
          >
            <ArrowLeft className="h-4 w-4 mr-1" />
            Back
          </Button>
          <div className="min-w-0">
            <h1 className="text-base font-semibold truncate">Link Analysis</h1>
            <p className="text-xs text-muted-foreground font-mono truncate">
              {caseId}
              {caseName !== caseId ? ` — ${caseName}` : ""}
            </p>
          </div>
        </div>

        {/* Manage sheet trigger */}
        <Sheet>
          <SheetTrigger asChild>
            <Button size="sm" variant="outline">
              <SlidersHorizontal className="h-4 w-4 mr-1" />
              Manage
            </Button>
          </SheetTrigger>
          <SheetContent side="right" className="w-full sm:max-w-lg overflow-y-auto">
            <SheetHeader>
              <SheetTitle>Manage Entities, Links, and Events</SheetTitle>
            </SheetHeader>
            <div className="mt-4 space-y-6">
              <section>
                <h2 className="text-sm font-semibold mb-2">Entities</h2>
                <EntitiesPanel caseId={caseId} />
              </section>
              <Separator />
              <section>
                <h2 className="text-sm font-semibold mb-2">Links</h2>
                <LinksPanel caseId={caseId} />
              </section>
              <Separator />
              <section>
                <h2 className="text-sm font-semibold mb-2">Events</h2>
                <EventsPanel caseId={caseId} />
              </section>
            </div>
          </SheetContent>
        </Sheet>
      </header>

      {/* Main content */}
      <main className="flex-1 px-4 py-4">
        <Tabs defaultValue="graph" className="h-full flex flex-col">
          <TabsList className="mb-3 shrink-0">
            <TabsTrigger value="graph">
              <Network className="h-4 w-4 mr-1.5" />
              Network Graph
            </TabsTrigger>
            <TabsTrigger value="crime-line">
              <Clock className="h-4 w-4 mr-1.5" />
              Crime Line
            </TabsTrigger>
          </TabsList>

          {/* ── Network Graph tab ── */}
          <TabsContent value="graph" className="flex-1">
            {/* Graph filter bar */}
            <div className="flex flex-wrap items-center gap-3 mb-3 p-3 rounded-md border bg-card">
              <span className="text-xs font-medium text-muted-foreground uppercase tracking-wide">
                Types:
              </span>
              {ENTITY_TYPES.map((type) => {
                const colors = entityTypeColor(type);
                const selected = isTypeSelected(type);
                return (
                  <button
                    key={type}
                    type="button"
                    onClick={() => toggleEntityType(type)}
                    className="inline-flex items-center rounded-full px-2.5 py-0.5 text-xs font-medium capitalize transition-opacity"
                    style={{
                      backgroundColor: selected ? colors.hex : undefined,
                      color: selected ? "#fff" : undefined,
                      opacity: selected ? 1 : 0.45,
                      border: `1px solid ${colors.hex}`,
                    }}
                    aria-pressed={selected}
                  >
                    {type}
                  </button>
                );
              })}
              <div className="flex items-center gap-2 ml-2">
                <Switch
                  id="include-evidence"
                  checked={graphFilter.include_evidence}
                  onCheckedChange={(checked) =>
                    setGraphFilter((prev) => ({
                      ...prev,
                      include_evidence: checked,
                    }))
                  }
                />
                <label
                  htmlFor="include-evidence"
                  className="text-xs text-muted-foreground cursor-pointer"
                >
                  Evidence nodes
                </label>
              </div>
              <Button
                size="sm"
                variant="ghost"
                className="ml-auto h-7"
                onClick={resetGraphFilter}
              >
                <RotateCcw className="h-3.5 w-3.5 mr-1" />
                Reset
              </Button>
            </div>
            <Suspense fallback={<GraphCanvasSkeleton />}>
              <GraphCanvas caseId={caseId} filter={graphFilter} />
            </Suspense>
          </TabsContent>

          {/* ── Crime Line tab ── */}
          <TabsContent value="crime-line" className="flex-1">
            {/* Crime line filter bar */}
            <div className="flex flex-wrap items-center gap-3 mb-3 p-3 rounded-md border bg-card">
              <span className="text-xs font-medium text-muted-foreground uppercase tracking-wide">
                Date range:
              </span>
              <div className="flex items-center gap-2">
                <label
                  htmlFor="crime-line-start"
                  className="text-xs text-muted-foreground"
                >
                  From
                </label>
                <input
                  id="crime-line-start"
                  type="datetime-local"
                  className="rounded-md border border-input bg-background px-2 py-1 text-xs"
                  value={timelineFilter.start ?? ""}
                  onChange={(e) =>
                    setTimelineFilter((prev) => ({
                      ...prev,
                      start: e.target.value || null,
                    }))
                  }
                />
              </div>
              <div className="flex items-center gap-2">
                <label
                  htmlFor="crime-line-end"
                  className="text-xs text-muted-foreground"
                >
                  To
                </label>
                <input
                  id="crime-line-end"
                  type="datetime-local"
                  className="rounded-md border border-input bg-background px-2 py-1 text-xs"
                  value={timelineFilter.end ?? ""}
                  onChange={(e) =>
                    setTimelineFilter((prev) => ({
                      ...prev,
                      end: e.target.value || null,
                    }))
                  }
                />
              </div>
              <Button
                size="sm"
                variant="ghost"
                className="ml-auto h-7"
                onClick={resetTimelineFilter}
              >
                <RotateCcw className="h-3.5 w-3.5 mr-1" />
                Reset
              </Button>
            </div>
            <Suspense fallback={<CrimeLineCanvasSkeleton />}>
              <CrimeLineCanvas caseId={caseId} filter={timelineFilter} />
            </Suspense>
          </TabsContent>
        </Tabs>
      </main>
    </div>
  );
}
