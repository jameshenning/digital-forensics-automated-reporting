/**
 * CaseStatsCharts — native React replacement for Grafana's "DFARS Case Statistics" dashboard.
 *
 * Three side-by-side bar charts (Entities, Evidence, Links) + a full-width timeline table.
 * Pure SVG bars (no external charting library) following the DashboardCharts pattern.
 */

import { useMemo } from "react";
import { useQuery } from "@tanstack/react-query";
import { BarChart3, Package, Link2, Clock } from "lucide-react";

import {
  caseDashboardEntityStats,
  caseDashboardEvidenceStats,
  caseDashboardLinkStats,
  caseDashboardTimeline,
} from "@/lib/bindings";
import { getToken } from "@/lib/session";
import { queryKeys } from "@/lib/query";
import { Skeleton } from "@/components/ui/skeleton";
import { Badge } from "@/components/ui/badge";

// ---------------------------------------------------------------------------
// Props
// ---------------------------------------------------------------------------

interface CaseStatsChartsProps {
  caseId: string;
}

// ---------------------------------------------------------------------------
// Color palettes
// ---------------------------------------------------------------------------

const ENTITY_COLORS: Record<string, string> = {
  person: "#3b82f6",      // blue-500
  business: "#f97316",    // orange-500
  vehicle: "#22c55e",     // green-500
  alias: "#a855f7",       // purple-500
  address: "#06b6d4",     // cyan-500
  phone: "#ef4444",       // red-500
  email: "#eab308",       // yellow-500
  account: "#ec4899",     // pink-500
};

const EVIDENCE_COLORS: Record<string, string> = {
  "Digital Device": "#3b82f6",
  Document: "#22c55e",
  "Physical Item": "#f97316",
  "Network Log": "#a855f7",
  "Financial Record": "#06b6d4",
  Unknown: "#6b7280",
};

const LINK_COLORS: Record<string, string> = {
  associated: "#3b82f6",
  family: "#22c55e",
  employed: "#f97316",
  communicated: "#a855f7",
  located: "#06b6d4",
  owns: "#ef4444",
};

// ---------------------------------------------------------------------------
// Main component
// ---------------------------------------------------------------------------

export function CaseStatsCharts({ caseId }: CaseStatsChartsProps) {
  const token = getToken() ?? "";

  const entitiesQuery = useQuery({
    queryKey: [...queryKeys.cases.detail(caseId), "dashboard", "entities"],
    queryFn: () => caseDashboardEntityStats({ token, case_id: caseId }),
    enabled: !!token,
  });

  const evidenceQuery = useQuery({
    queryKey: [...queryKeys.cases.detail(caseId), "dashboard", "evidence"],
    queryFn: () => caseDashboardEvidenceStats({ token, case_id: caseId }),
    enabled: !!token,
  });

  const linksQuery = useQuery({
    queryKey: [...queryKeys.cases.detail(caseId), "dashboard", "links"],
    queryFn: () => caseDashboardLinkStats({ token, case_id: caseId }),
    enabled: !!token,
  });

  const timelineQuery = useQuery({
    queryKey: [...queryKeys.cases.detail(caseId), "dashboard", "timeline"],
    queryFn: () => caseDashboardTimeline({ token, case_id: caseId }),
    enabled: !!token,
  });

  const isLoading =
    entitiesQuery.isLoading ||
    evidenceQuery.isLoading ||
    linksQuery.isLoading ||
    timelineQuery.isLoading;

  if (isLoading) {
    return <StatsSkeleton />;
  }

  return (
    <div className="space-y-4">
      {/* Three bar charts */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
        <BarChartCard
          title="Entities by Type"
          icon={<BarChart3 className="h-4 w-4 text-muted-foreground" />}
          data={entitiesQuery.data ?? []}
          colorMap={ENTITY_COLORS}
          getLabel={(r) => r.entity_type}
        />
        <BarChartCard
          title="Evidence by Type"
          icon={<Package className="h-4 w-4 text-muted-foreground" />}
          data={evidenceQuery.data ?? []}
          colorMap={EVIDENCE_COLORS}
          getLabel={(r) => r.evidence_type}
        />
        <BarChartCard
          title="Links by Label"
          icon={<Link2 className="h-4 w-4 text-muted-foreground" />}
          data={linksQuery.data ?? []}
          colorMap={LINK_COLORS}
          getLabel={(r) => r.link_label}
        />
      </div>

      {/* Timeline table */}
      <TimelineTable data={timelineQuery.data ?? []} />
    </div>
  );
}

// ---------------------------------------------------------------------------
// BarChartCard
// ---------------------------------------------------------------------------

function BarChartCard<T extends { count: number }>({
  title,
  icon,
  data,
  colorMap,
  getLabel,
}: {
  title: string;
  icon: React.ReactNode;
  data: T[];
  colorMap: Record<string, string>;
  getLabel: (row: T) => string;
}) {
  const max = useMemo(() => Math.max(1, ...data.map((d) => d.count)), [data]);

  return (
    <div className="rounded-lg border p-4 space-y-3">
      <div className="flex items-center gap-2">
        {icon}
        <h3 className="text-sm font-semibold">{title}</h3>
      </div>
      {data.length === 0 ? (
        <p className="text-xs text-muted-foreground">No data</p>
      ) : (
        <div className="space-y-2">
          {data.map((row, idx) => {
            const label = getLabel(row);
            const count = row.count;
            return (
              <div key={idx} className="w-full space-y-1">
                <div className="flex items-center justify-between text-xs">
                  <span className="font-medium">{label}</span>
                  <span className="text-muted-foreground">{count}</span>
                </div>
                <div className="h-2 w-full rounded-full bg-muted overflow-hidden">
                  <div
                    className="h-full rounded-full transition-all duration-500"
                    style={{
                      width: `${(count / max) * 100}%`,
                      backgroundColor: colorMap[label] ?? "#9ca3af",
                    }}
                  />
                </div>
              </div>
            );
          })}
        </div>
      )}
    </div>
  );
}

// ---------------------------------------------------------------------------
// TimelineTable
// ---------------------------------------------------------------------------

function TimelineTable({
  data,
}: {
  data: { time: number; title: string; category: string }[];
}) {
  const CATEGORY_BADGE: Record<string, string> = {
    observation: "bg-sky-600",
    communication: "bg-emerald-600",
    movement: "bg-orange-500",
    custodial: "bg-yellow-500",
    evidence: "bg-gray-500",
    custody: "bg-pink-600",
    hashes: "bg-violet-600",
    tools: "bg-red-500",
    analysis: "bg-green-600",
    other: "bg-gray-500",
  };

  return (
    <div className="rounded-lg border p-4 space-y-3">
      <div className="flex items-center gap-2">
        <Clock className="h-4 w-4 text-muted-foreground" />
        <h3 className="text-sm font-semibold">Case Timeline</h3>
      </div>
      {data.length === 0 ? (
        <p className="text-xs text-muted-foreground">No timeline events</p>
      ) : (
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b">
                <th className="text-left font-medium text-muted-foreground py-2 pr-4">
                  Time
                </th>
                <th className="text-left font-medium text-muted-foreground py-2 pr-4">
                  Event
                </th>
                <th className="text-left font-medium text-muted-foreground py-2">
                  Category
                </th>
              </tr>
            </thead>
            <tbody>
              {data.map((row, idx) => (
                <tr key={idx} className="border-b last:border-0">
                  <td className="py-2 pr-4 text-xs text-muted-foreground whitespace-nowrap">
                    {fmtTimestamp(row.time)}
                  </td>
                  <td className="py-2 pr-4">{row.title}</td>
                  <td className="py-2">
                    <Badge
                      variant="secondary"
                      className={`text-xs text-white ${
                        CATEGORY_BADGE[row.category.toLowerCase()] ?? "bg-gray-500"
                      }`}
                    >
                      {row.category}
                    </Badge>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function fmtTimestamp(ms: number): string {
  const d = new Date(ms);
  if (isNaN(d.getTime())) return "—";
  return d.toLocaleString(undefined, {
    year: "numeric",
    month: "short",
    day: "numeric",
    hour: "2-digit",
    minute: "2-digit",
  });
}

// ---------------------------------------------------------------------------
// Skeleton
// ---------------------------------------------------------------------------

function StatsSkeleton() {
  return (
    <div className="space-y-4">
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
        <div className="rounded-lg border p-4 space-y-3">
          <Skeleton className="h-4 w-32" />
          <Skeleton className="h-2 w-full" />
          <Skeleton className="h-2 w-full" />
          <Skeleton className="h-2 w-full" />
        </div>
        <div className="rounded-lg border p-4 space-y-3">
          <Skeleton className="h-4 w-32" />
          <Skeleton className="h-2 w-full" />
          <Skeleton className="h-2 w-full" />
          <Skeleton className="h-2 w-full" />
        </div>
        <div className="rounded-lg border p-4 space-y-3">
          <Skeleton className="h-4 w-32" />
          <Skeleton className="h-2 w-full" />
          <Skeleton className="h-2 w-full" />
          <Skeleton className="h-2 w-full" />
        </div>
      </div>
      <div className="rounded-lg border p-4 space-y-3">
        <Skeleton className="h-4 w-32" />
        <Skeleton className="h-8 w-full" />
        <Skeleton className="h-8 w-full" />
        <Skeleton className="h-8 w-full" />
      </div>
    </div>
  );
}
