/**
 * DashboardCharts — lightweight SVG visualizations for case statistics.
 *
 * No external charting library; pure SVG + React.  Keeps bundle size small
 * and avoids dependency churn.
 */

import { useMemo } from "react";
import { BarChart3, TrendingUp, AlertTriangle } from "lucide-react";
import type { CaseStats } from "@/lib/bindings";
import { Skeleton } from "@/components/ui/skeleton";

// ---------------------------------------------------------------------------
// Props
// ---------------------------------------------------------------------------

interface DashboardChartsProps {
  stats: CaseStats | undefined;
  isLoading: boolean;
  onStatusClick?: (status: string) => void;
  onPriorityClick?: (priority: string) => void;
}

// ---------------------------------------------------------------------------
// Color palette — centralized mapping from design-system semantic tokens.
// ---------------------------------------------------------------------------
// These hex values mirror the HSL tokens used in Tailwind so SVG fills
// stay consistent with the rest of the UI.  When the design system
// changes, update only this object.
//
// Semantic mapping:
//   success  → green  (hsl(142 71% 45%))  ≈ #22c55e
//   warning  → amber  (hsl(38 92% 50%))   ≈ #f59e0b
//   primary  → blue   (hsl(217 91% 60%))  ≈ #3b82f6
//   destructive → red (hsl(0 84% 60%))    ≈ #ef4444
//   muted-foreground → gray               ≈ #6b7280

const CHART_PALETTE = {
  status: {
    Active: "#22c55e",
    Pending: "#f59e0b",
    Closed: "#3b82f6",
    Archived: "#6b7280",
  },
  priority: {
    Critical: "#ef4444",
    High: "#f97316",
    Medium: "#f59e0b",
    Low: "#3b82f6",
  },
} as const;



// ---------------------------------------------------------------------------
// Main component
// ---------------------------------------------------------------------------

export function DashboardCharts({ stats, isLoading, onStatusClick, onPriorityClick }: DashboardChartsProps) {
  if (isLoading || !stats) {
    return <ChartsSkeleton />;
  }

  const hasData =
    stats.status_counts.length > 0 ||
    stats.priority_counts.length > 0 ||
    stats.monthly_counts.length > 0;

  if (!hasData) {
    return (
      <div className="rounded-lg border border-dashed p-6 text-center">
        <BarChart3 className="h-8 w-8 mx-auto text-muted-foreground/50 mb-2" />
        <p className="text-sm font-medium">No chart data available</p>
        <p className="text-xs text-muted-foreground mt-1">
          Create cases to see status, priority, and timeline visualizations.
        </p>
      </div>
    );
  }

  return (
    <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
      <StatusChart data={stats.status_counts} onBarClick={onStatusClick} />
      <PriorityChart data={stats.priority_counts} onBarClick={onPriorityClick} />
      <TimelineChart data={stats.monthly_counts} />
    </div>
  );
}

// ---------------------------------------------------------------------------
// StatusChart
// ---------------------------------------------------------------------------

function StatusChart({
  data,
  onBarClick,
}: {
  data: { status: string; count: number }[];
  onBarClick?: (status: string) => void;
}) {
  const max = useMemo(() => Math.max(1, ...data.map((d) => d.count)), [data]);

  return (
    <div className="rounded-lg border p-4 space-y-3">
      <div className="flex items-center gap-2">
        <BarChart3 className="h-4 w-4 text-muted-foreground" />
        <h3 className="text-sm font-semibold">Status Distribution</h3>
      </div>
      {data.length === 0 ? (
        <p className="text-xs text-muted-foreground">No data</p>
      ) : (
        <div className="space-y-2">
          {data.map((row) => (
            <button
              key={row.status}
              type="button"
              onClick={() => onBarClick?.(row.status)}
              className={`w-full text-left space-y-1 ${onBarClick ? "cursor-pointer hover:opacity-80 transition-opacity" : ""}`}
            >
              <div className="flex items-center justify-between text-xs">
                <span className="font-medium">{row.status}</span>
                <span className="text-muted-foreground">{row.count}</span>
              </div>
              <div className="h-2 w-full rounded-full bg-muted overflow-hidden">
                <div
                  className="h-full rounded-full transition-all duration-500"
                  style={{
                    width: `${(row.count / max) * 100}%`,
                    backgroundColor: CHART_PALETTE.status[row.status as keyof typeof CHART_PALETTE.status] ?? "#9ca3af",
                  }}
                />
              </div>
            </button>
          ))}
        </div>
      )}
    </div>
  );
}

// ---------------------------------------------------------------------------
// PriorityChart
// ---------------------------------------------------------------------------

function PriorityChart({
  data,
  onBarClick,
}: {
  data: { priority: string; count: number }[];
  onBarClick?: (priority: string) => void;
}) {
  const max = useMemo(() => Math.max(1, ...data.map((d) => d.count)), [data]);

  return (
    <div className="rounded-lg border p-4 space-y-3">
      <div className="flex items-center gap-2">
        <AlertTriangle className="h-4 w-4 text-muted-foreground" />
        <h3 className="text-sm font-semibold">Priority Distribution</h3>
      </div>
      {data.length === 0 ? (
        <p className="text-xs text-muted-foreground">No data</p>
      ) : (
        <div className="space-y-2">
          {data.map((row) => (
            <button
              key={row.priority}
              type="button"
              onClick={() => onBarClick?.(row.priority)}
              className={`w-full text-left space-y-1 ${onBarClick ? "cursor-pointer hover:opacity-80 transition-opacity" : ""}`}
            >
              <div className="flex items-center justify-between text-xs">
                <span className="font-medium">{row.priority}</span>
                <span className="text-muted-foreground">{row.count}</span>
              </div>
              <div className="h-2 w-full rounded-full bg-muted overflow-hidden">
                <div
                  className="h-full rounded-full transition-all duration-500"
                  style={{
                    width: `${(row.count / max) * 100}%`,
                    backgroundColor: CHART_PALETTE.priority[row.priority as keyof typeof CHART_PALETTE.priority] ?? "#9ca3af",
                  }}
                />
              </div>
            </button>
          ))}
        </div>
      )}
    </div>
  );
}

// ---------------------------------------------------------------------------
// TimelineChart — simple SVG line chart
// ---------------------------------------------------------------------------

function TimelineChart({ data }: { data: { month: string; count: number }[] }) {
  if (data.length === 0) {
    return (
      <div className="rounded-lg border p-4 space-y-3">
        <div className="flex items-center gap-2">
          <TrendingUp className="h-4 w-4 text-muted-foreground" />
          <h3 className="text-sm font-semibold">Cases Over Time</h3>
        </div>
        <p className="text-xs text-muted-foreground">No data</p>
      </div>
    );
  }

  const max = Math.max(1, ...data.map((d) => d.count));
  const width = 300;
  const height = 120;
  const padding = { top: 10, right: 10, bottom: 30, left: 30 };
  const chartWidth = width - padding.left - padding.right;
  const chartHeight = height - padding.top - padding.bottom;

  const xForIndex = (i: number) =>
    padding.left + (i / Math.max(1, data.length - 1)) * chartWidth;
  const yForCount = (c: number) =>
    padding.top + chartHeight - (c / max) * chartHeight;

  const pathD = data
    .map((d, i) => `${i === 0 ? "M" : "L"} ${xForIndex(i)} ${yForCount(d.count)}`)
    .join(" ");

  const areaD =
    pathD +
    ` L ${xForIndex(data.length - 1)} ${padding.top + chartHeight}` +
    ` L ${padding.left} ${padding.top + chartHeight} Z`;

  // Y-axis ticks (0, max)
  const yTicks = [0, Math.ceil(max / 2), max];

  // X-axis labels: show first, middle, last
  const xLabelIndices = [0, Math.floor((data.length - 1) / 2), data.length - 1];

  return (
    <div className="rounded-lg border p-4 space-y-3">
      <div className="flex items-center gap-2">
        <TrendingUp className="h-4 w-4 text-muted-foreground" />
        <h3 className="text-sm font-semibold">Cases Over Time</h3>
      </div>
      <svg
        viewBox={`0 0 ${width} ${height}`}
        className="w-full"
        style={{ maxHeight: 160 }}
        preserveAspectRatio="xMidYMid meet"
      >
        {/* Grid lines */}
        {yTicks.map((t) => (
          <line
            key={`grid-${t}`}
            x1={padding.left}
            y1={yForCount(t)}
            x2={width - padding.right}
            y2={yForCount(t)}
            stroke="currentColor"
            strokeOpacity={0.1}
            strokeWidth={1}
          />
        ))}

        {/* Area fill */}
        <path d={areaD} fill="currentColor" fillOpacity={0.1} />

        {/* Line */}
        <path
          d={pathD}
          fill="none"
          stroke="currentColor"
          strokeWidth={2}
          strokeLinecap="round"
          strokeLinejoin="round"
        />

        {/* Points */}
        {data.map((d, i) => (
          <circle
            key={i}
            cx={xForIndex(i)}
            cy={yForCount(d.count)}
            r={3}
            fill="currentColor"
          />
        ))}

        {/* Y-axis labels */}
        {yTicks.map((t) => (
          <text
            key={`yt-${t}`}
            x={padding.left - 6}
            y={yForCount(t)}
            textAnchor="end"
            dominantBaseline="middle"
            fontSize={9}
            fill="currentColor"
            fillOpacity={0.6}
          >
            {t}
          </text>
        ))}

        {/* X-axis labels */}
        {xLabelIndices.map((i) => (
          <text
            key={`xt-${i}`}
            x={xForIndex(i)}
            y={height - 4}
            textAnchor="middle"
            fontSize={9}
            fill="currentColor"
            fillOpacity={0.6}
          >
            {fmtMonthLabel(data[i].month)}
          </text>
        ))}
      </svg>
    </div>
  );
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function fmtMonthLabel(month: string): string {
  // month is "YYYY-MM"
  const [year, mon] = month.split("-");
  if (!year || !mon) return month;
  const d = new Date(`${year}-${mon}-01T00:00:00`);
  if (isNaN(d.getTime())) return month;
  return d.toLocaleDateString(undefined, { year: "2-digit", month: "short" });
}

// ---------------------------------------------------------------------------
// Skeleton
// ---------------------------------------------------------------------------

function ChartsSkeleton() {
  return (
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
        <Skeleton className="h-24 w-full" />
      </div>
    </div>
  );
}
