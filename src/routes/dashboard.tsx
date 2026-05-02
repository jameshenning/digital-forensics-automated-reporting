/**
 * Dashboard — Phase 2: case list with full CRUD entry points.
 *
 * Protected by requireAuthBeforeLoad.
 * Fetches CaseSummary[] via TanStack Query → casesList Tauri command.
 * Each case card navigates to /case/:caseId.
 */

import React from "react";
import { createFileRoute, Link, useNavigate } from "@tanstack/react-router";
import {
  LayoutDashboard,
  ShieldCheck,
  LogOut,
  Lock,
  PlusCircle,
  FolderOpen,
  RefreshCw,
  Search,
  X,
  ArrowUpDown,
  Briefcase,
  Activity,
  AlertTriangle,
  Database,
  FolderPlus,
  Pencil,
  Trash2,
  Share2,
  Clock,
  CircleDot,
  ChevronLeft,
  ChevronRight,
  Download,
} from "lucide-react";
import { useQuery, useQueryClient } from "@tanstack/react-query";

import { useSession } from "@/lib/session";
import { useSessionLock } from "@/components/session-lock-provider";
import { requireAuthBeforeLoad } from "@/lib/auth-guard";
import { authLogout, casesList, casesCount, casesStats, auditListRecent } from "@/lib/bindings";
import { getToken, clearToken } from "@/lib/session";
import { queryKeys } from "@/lib/query";
import { toastError } from "@/lib/error-toast";
import { useDebounce } from "@/lib/use-debounce";
import { statusBadgeClass, priorityBadgeClass } from "@/lib/case-enums";
import type { CaseSummary, AuditEntryWithCaseName, CaseStats } from "@/lib/bindings";

import { Button } from "@/components/ui/button";
import { Card, CardContent } from "@/components/ui/card";
import { Skeleton } from "@/components/ui/skeleton";
import { Alert, AlertTitle, AlertDescription } from "@/components/ui/alert";
import { DashboardCharts } from "@/components/dashboard-charts";
import { Input } from "@/components/ui/input";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";


export const Route = createFileRoute("/dashboard")({
  beforeLoad: requireAuthBeforeLoad,
  component: DashboardPage,
});

// ---------------------------------------------------------------------------
// Skeleton loading state — three placeholder case cards
// ---------------------------------------------------------------------------

function CaseCardSkeleton() {
  return (
    <div className="rounded-lg border p-4 space-y-3">
      <div className="flex items-start justify-between">
        <div className="space-y-2 flex-1">
          <Skeleton className="h-5 w-48" />
          <Skeleton className="h-3 w-32" />
        </div>
        <div className="flex gap-2">
          <Skeleton className="h-5 w-14 rounded-full" />
          <Skeleton className="h-5 w-14 rounded-full" />
        </div>
      </div>
      <div className="flex gap-4">
        <Skeleton className="h-3 w-24" />
        <Skeleton className="h-3 w-20" />
        <Skeleton className="h-3 w-16" />
      </div>
    </div>
  );
}

// ---------------------------------------------------------------------------
// Single case card
// ---------------------------------------------------------------------------

interface CaseCardProps {
  summary: CaseSummary;
  onClick: () => void;
  selected?: boolean;
  onToggleSelect?: (caseId: string) => void;
}

function CaseCard({ summary, onClick, selected, onToggleSelect }: CaseCardProps) {
  const startDateFormatted = new Date(summary.start_date).toLocaleDateString(
    undefined,
    { year: "numeric", month: "short", day: "numeric" }
  );
  const createdFormatted = new Date(summary.created_at).toLocaleDateString(
    undefined,
    { year: "numeric", month: "short", day: "numeric" }
  );

  function handleKeyDown(e: React.KeyboardEvent<HTMLDivElement>) {
    if (e.key === "Enter" || e.key === " ") {
      e.preventDefault();
      onClick();
    }
  }

  function handleCheckboxClick(e: React.MouseEvent) {
    e.stopPropagation();
    onToggleSelect?.(summary.case_id);
  }

  return (
    <div
      role="button"
      tabIndex={0}
      className={`rounded-lg border bg-card text-card-foreground shadow-sm p-4 cursor-pointer hover:border-primary/50 hover:bg-accent/10 transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-2 ${selected ? "border-primary bg-accent/5" : ""}`}
      onClick={onClick}
      onKeyDown={handleKeyDown}
      aria-label={`Open case ${summary.case_name}`}
    >
      {/* Top row: checkbox + name + status/priority badges */}
      <div className="flex items-start justify-between gap-3 mb-2">
        <div className="flex items-start gap-2 min-w-0 flex-1">
          {onToggleSelect && (
            <input
              type="checkbox"
              checked={selected}
              onClick={handleCheckboxClick}
              onChange={() => {}}
              className="mt-1 h-4 w-4 shrink-0"
              aria-label={`Select case ${summary.case_name}`}
            />
          )}
          <div className="min-w-0">
            <p className="font-semibold text-base leading-tight truncate">
              {summary.case_name}
            </p>
            <code className="text-xs text-muted-foreground font-mono">
              {summary.case_id}
            </code>
          </div>
        </div>
        <div className="flex gap-1.5 shrink-0">
          <span
            className={`inline-flex items-center rounded-full border px-2 py-0.5 text-xs font-medium ${statusBadgeClass(summary.status)}`}
          >
            {summary.status}
          </span>
          <span
            className={`inline-flex items-center rounded-full border px-2 py-0.5 text-xs font-medium ${priorityBadgeClass(summary.priority)}`}
          >
            {summary.priority}
          </span>
        </div>
      </div>

      {/* Meta row */}
      <div className="flex flex-wrap gap-x-4 gap-y-1 text-xs text-muted-foreground mt-2">
        <span>
          <span className="font-medium">Investigator:</span>{" "}
          {summary.investigator}
        </span>
        <span>
          <span className="font-medium">Started:</span> {startDateFormatted}
        </span>
        <span>
          <span className="font-medium">Evidence:</span>{" "}
          {summary.evidence_count}
        </span>
        <span>
          <span className="font-medium">Created:</span> {createdFormatted}
        </span>
      </div>
    </div>
  );
}

// ---------------------------------------------------------------------------
// Main page
// ---------------------------------------------------------------------------

type CaseStatus = CaseSummary["status"];
type CasePriority = CaseSummary["priority"];

const ALL_STATUSES: CaseStatus[] = ["Active", "Closed", "Pending", "Archived"];
const ALL_PRIORITIES: CasePriority[] = ["Low", "Medium", "High", "Critical"];

type SortField =
  | "case_name"
  | "start_date"
  | "created_at"
  | "priority"
  | "status"
  | "evidence_count"
  | "investigator";

const SORT_OPTIONS: { value: SortField; label: string }[] = [
  { value: "start_date", label: "Start date" },
  { value: "created_at", label: "Created" },
  { value: "case_name", label: "Name" },
  { value: "priority", label: "Priority" },
  { value: "status", label: "Status" },
  { value: "evidence_count", label: "Evidence" },
  { value: "investigator", label: "Investigator" },
];

const PRIORITY_WEIGHT: Record<CasePriority, number> = {
  Critical: 4,
  High: 3,
  Medium: 2,
  Low: 1,
};

export function compareCases(a: CaseSummary, b: CaseSummary, field: SortField, dir: "asc" | "desc"): number {
  let cmp = 0;
  switch (field) {
    case "case_name":
      cmp = a.case_name.localeCompare(b.case_name);
      break;
    case "investigator":
      cmp = a.investigator.localeCompare(b.investigator);
      break;
    case "status":
      cmp = a.status.localeCompare(b.status);
      break;
    case "priority":
      cmp = PRIORITY_WEIGHT[a.priority] - PRIORITY_WEIGHT[b.priority];
      break;
    case "evidence_count":
      cmp = a.evidence_count - b.evidence_count;
      break;
    case "start_date":
      cmp = new Date(a.start_date).getTime() - new Date(b.start_date).getTime();
      break;
    case "created_at":
      cmp = new Date(a.created_at).getTime() - new Date(b.created_at).getTime();
      break;
  }
  return dir === "asc" ? cmp : -cmp;
}

// ---------------------------------------------------------------------------
// Stats cards
// ---------------------------------------------------------------------------

interface StatsCardsProps {
  cases: CaseSummary[];
}

export function StatsCards({ cases }: StatsCardsProps) {
  const total = cases.length;
  const active = cases.filter((c) => c.status === "Active").length;
  const critical = cases.filter((c) => c.priority === "Critical").length;
  const evidence = cases.reduce((sum, c) => sum + c.evidence_count, 0);

  const items = [
    {
      label: "Total Cases",
      value: total,
      icon: Briefcase,
      tone: "text-foreground" as const,
    },
    {
      label: "Active",
      value: active,
      icon: Activity,
      tone: "text-success" as const,
    },
    {
      label: "Critical",
      value: critical,
      icon: AlertTriangle,
      tone: "text-destructive" as const,
    },
    {
      label: "Evidence Items",
      value: evidence,
      icon: Database,
      tone: "text-primary" as const,
    },
  ];

  return (
    <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 mb-6">
      {items.map((item) => (
        <Card key={item.label}>
          <CardContent className="p-4 flex items-center gap-3">
            <item.icon className={`h-5 w-5 ${item.tone}`} />
            <div>
              <p className="text-2xl font-bold leading-none">{item.value}</p>
              <p className="text-xs text-muted-foreground mt-1">{item.label}</p>
            </div>
          </CardContent>
        </Card>
      ))}
    </div>
  );
}

// ---------------------------------------------------------------------------
// Recent activity feed
// ---------------------------------------------------------------------------

export function activityIcon(action: string) {
  switch (action) {
    case "CASE_CREATED":
      return FolderPlus;
    case "CASE_UPDATED":
      return Pencil;
    case "CASE_DELETED":
      return Trash2;
    case "RECORD_SHARED":
      return Share2;
    default:
      return CircleDot;
  }
}

export function activityLabel(action: string): string {
  switch (action) {
    case "CASE_CREATED":
      return "Case created";
    case "CASE_UPDATED":
      return "Case updated";
    case "CASE_DELETED":
      return "Case deleted";
    case "RECORD_SHARED":
      return "Record shared";
    default:
      return action.replace(/_/g, " ").toLowerCase();
  }
}

export function fmtActivityTime(iso: string): string {
  const d = new Date(iso);
  if (isNaN(d.getTime())) return iso;
  return d.toLocaleString(undefined, {
    year: "numeric",
    month: "short",
    day: "numeric",
    hour: "2-digit",
    minute: "2-digit",
  });
}

function exportCasesToCsv(cases: CaseSummary[]): string {
  const headers = ["case_id", "case_name", "investigator", "start_date", "status", "priority", "evidence_count", "created_at"];
  const rows = cases.map((c) => [
    c.case_id,
    c.case_name,
    c.investigator,
    c.start_date,
    c.status,
    c.priority,
    String(c.evidence_count),
    c.created_at,
  ]);
  const escape = (s: string) => {
    if (s.includes(",") || s.includes('"') || s.includes("\n")) {
      return `"${s.replace(/"/g, '""')}"`;
    }
    return s;
  };
  return [headers.join(","), ...rows.map((r) => r.map(escape).join(","))].join("\n");
}

function downloadCsv(filename: string, content: string) {
  const blob = new Blob([content], { type: "text/csv;charset=utf-8;" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  URL.revokeObjectURL(url);
}

interface RecentActivityProps {
  token: string;
}

function RecentActivity({ token }: RecentActivityProps) {
  const {
    data: entries,
    isLoading,
    isError,
  } = useQuery({
    queryKey: ["audit", "recent"],
    queryFn: () => auditListRecent({ token, limit: 20 }),
    enabled: !!token,
  });

  if (isLoading) {
    return (
      <div className="space-y-2 mt-8">
        <h2 className="text-sm font-semibold text-muted-foreground uppercase tracking-wider mb-3">
          Recent Activity
        </h2>
        <Skeleton className="h-12 w-full" />
        <Skeleton className="h-12 w-full" />
        <Skeleton className="h-12 w-full" />
      </div>
    );
  }

  if (isError || !entries || entries.length === 0) {
    return null;
  }

  return (
    <div className="mt-8">
      <h2 className="text-sm font-semibold text-muted-foreground uppercase tracking-wider mb-3">
        Recent Activity
      </h2>
      <div className="space-y-2">
        {entries.map((entry) => (
          <ActivityRow key={entry.entry_id} entry={entry} />
        ))}
      </div>
    </div>
  );
}

function ActivityRow({ entry }: { entry: AuditEntryWithCaseName }) {
  const Icon = activityIcon(entry.action);
  const label = activityLabel(entry.action);
  return (
    <div className="flex items-start gap-3 rounded-md border p-3 text-sm">
      <div className="mt-0.5">
        <Icon className="h-4 w-4 text-muted-foreground" />
      </div>
      <div className="flex-1 min-w-0">
        <p className="font-medium">
          {label}
          {entry.case_name && (
            <span className="text-muted-foreground font-normal">
              {" "}
              ·{" "}
              <span className="truncate">{entry.case_name}</span>
            </span>
          )}
        </p>
        {entry.details && (
          <p className="text-xs text-muted-foreground truncate mt-0.5">
            {entry.details}
          </p>
        )}
      </div>
      <div className="flex items-center gap-1 text-xs text-muted-foreground shrink-0">
        <Clock className="h-3 w-3" />
        <span>{fmtActivityTime(entry.timestamp)}</span>
      </div>
    </div>
  );
}

function DashboardPage() {
  const { session } = useSession();
  const { lock } = useSessionLock();
  const navigate = useNavigate();
  const queryClient = useQueryClient();

  const token = getToken() ?? "";

  // Pagination state
  const PAGE_SIZE = 25;
  const [page, setPage] = React.useState(0);

  // Filter state
  const [search, setSearch] = React.useState("");
  const debouncedSearch = useDebounce(search, 300);
  const [statusFilter, setStatusFilter] = React.useState<CaseStatus | "all">("all");
  const [priorityFilter, setPriorityFilter] = React.useState<CasePriority | "all">("all");

  const {
    data: cases,
    isLoading,
    isError,
    error,
    refetch,
  } = useQuery({
    queryKey: [...queryKeys.cases.list(PAGE_SIZE, page * PAGE_SIZE), debouncedSearch.trim()],
    queryFn: () => casesList({
      token,
      limit: PAGE_SIZE,
      offset: page * PAGE_SIZE,
      search: debouncedSearch.trim() || undefined,
    }),
    enabled: !!token,
  });

  const { data: totalCases } = useQuery({
    queryKey: ["cases", "count"],
    queryFn: () => casesCount({ token }),
    enabled: !!token,
  });

  const { data: caseStats, isLoading: statsLoading } = useQuery<CaseStats>({
    queryKey: queryKeys.cases.stats,
    queryFn: () => casesStats({ token }),
    enabled: !!token,
  });

  // Sort state
  const [sortField, setSortField] = React.useState<SortField>("start_date");
  const [sortDirection, setSortDirection] = React.useState<"asc" | "desc">("desc");

  // Selection state
  const [selectedIds, setSelectedIds] = React.useState<Set<string>>(new Set());

  const hasFilters = search.trim().length > 0 || statusFilter !== "all" || priorityFilter !== "all";

  // Reset to page 0 and clear selection when filters change
  React.useEffect(() => {
    setPage(0);
    setSelectedIds(new Set());
  }, [debouncedSearch, statusFilter, priorityFilter]);

  function clearFilters() {
    setSearch("");
    setStatusFilter("all");
    setPriorityFilter("all");
    setPage(0);
    setSelectedIds(new Set());
  }

  function toggleSelect(caseId: string) {
    setSelectedIds((prev) => {
      const next = new Set(prev);
      if (next.has(caseId)) {
        next.delete(caseId);
      } else {
        next.add(caseId);
      }
      return next;
    });
  }

  function selectAllOnPage() {
    setSelectedIds(new Set(sortedCases.map((c) => c.case_id)));
  }

  function clearSelection() {
    setSelectedIds(new Set());
  }

  // Keyboard shortcuts
  const searchInputRef = React.useRef<HTMLInputElement>(null);

  React.useEffect(() => {
    function isTypingTarget(el: EventTarget | null): boolean {
      if (!(el instanceof HTMLElement)) return false;
      return (
        el.tagName === "INPUT" ||
        el.tagName === "TEXTAREA" ||
        el.isContentEditable
      );
    }

    function onKeyDown(e: KeyboardEvent) {
      if (e.key === "/" && !isTypingTarget(e.target)) {
        e.preventDefault();
        searchInputRef.current?.focus();
      }
      if (e.key === "Escape") {
        if (hasFilters) {
          clearFilters();
        }
      }
      if (e.key === "n" && !isTypingTarget(e.target)) {
        void navigate({ to: "/case/new" });
      }
    }

    document.addEventListener("keydown", onKeyDown);
    return () => document.removeEventListener("keydown", onKeyDown);
  }, [hasFilters, navigate]);

  const filteredCases = React.useMemo(() => {
    if (!cases) return [];
    return cases.filter((c) => {
      if (statusFilter !== "all" && c.status !== statusFilter) return false;
      if (priorityFilter !== "all" && c.priority !== priorityFilter) return false;
      return true;
    });
  }, [cases, statusFilter, priorityFilter]);

  const sortedCases = React.useMemo(() => {
    return [...filteredCases].sort((a, b) =>
      compareCases(a, b, sortField, sortDirection)
    );
  }, [filteredCases, sortField, sortDirection]);

  async function handleLogout() {
    const t = getToken();
    if (t) {
      try {
        await authLogout({ token: t });
      } catch {
        // Ignore — session may already be expired
      }
    }
    clearToken();
    queryClient.setQueryData(queryKeys.currentUser, null);
    void queryClient.invalidateQueries({ queryKey: queryKeys.currentUser });
    void navigate({ to: "/auth/login" });
  }

  function handleCaseClick(caseId: string) {
    void navigate({ to: "/case/$caseId", params: { caseId } });
  }

  // Render the main content area based on query state
  function renderContent() {
    if (isLoading) {
      return (
        <div className="space-y-3" aria-busy="true" aria-label="Loading cases">
          <CaseCardSkeleton />
          <CaseCardSkeleton />
          <CaseCardSkeleton />
        </div>
      );
    }

    if (isError) {
      return (
        <Alert variant="destructive">
          <AlertTitle>Failed to load cases</AlertTitle>
          <AlertDescription className="mt-2 space-y-3">
            <p>
              {error instanceof Object && "message" in error
                ? String((error as { message: unknown }).message)
                : "An unexpected error occurred."}
            </p>
            <Button
              variant="outline"
              size="sm"
              onClick={() => {
                toastError(error);
                void refetch();
              }}
            >
              <RefreshCw className="h-4 w-4 mr-2" />
              Retry
            </Button>
          </AlertDescription>
        </Alert>
      );
    }

    if (!cases || cases.length === 0) {
      return (
        <Card className="text-center py-12">
          <CardContent className="flex flex-col items-center gap-4">
            <FolderOpen className="h-12 w-12 text-muted-foreground/50" />
            <div>
              <p className="text-base font-medium">No cases yet</p>
              <p className="text-sm text-muted-foreground mt-1">
                Create your first case to get started.
              </p>
            </div>
            <Button asChild>
              <Link to="/case/new">
                <PlusCircle className="h-4 w-4 mr-2" />
                Create first case
              </Link>
            </Button>
          </CardContent>
        </Card>
      );
    }

    if (sortedCases.length === 0) {
      return (
        <Card className="text-center py-12">
          <CardContent className="flex flex-col items-center gap-4">
            <Search className="h-12 w-12 text-muted-foreground/50" />
            <div>
              <p className="text-base font-medium">No cases match</p>
              <p className="text-sm text-muted-foreground mt-1">
                Try adjusting your search or filters.
              </p>
            </div>
            {hasFilters && (
              <Button variant="outline" size="sm" onClick={clearFilters}>
                <X className="h-4 w-4 mr-2" />
                Clear filters
              </Button>
            )}
          </CardContent>
        </Card>
      );
    }

    const total = totalCases ?? 0;
    const startIdx = page * PAGE_SIZE + 1;
    const endIdx = Math.min((page + 1) * PAGE_SIZE, total);
    const hasPrev = page > 0;
    const hasNext = (page + 1) * PAGE_SIZE < total;

    const selectedCount = selectedIds.size;

    return (
      <div className="space-y-3">
        <div className="flex items-center justify-between">
          <p className="text-xs text-muted-foreground">
            Showing {startIdx}–{endIdx} of {total} case{total === 1 ? "" : "s"}
            {sortField !== "start_date" || sortDirection !== "desc"
              ? ` · sorted by ${SORT_OPTIONS.find((o) => o.value === sortField)?.label} (${sortDirection === "asc" ? "asc" : "desc"})`
              : ""}
          </p>
          <div className="flex items-center gap-2">
            <Button variant="ghost" size="sm" onClick={selectAllOnPage}>
              Select all
            </Button>
            {selectedCount > 0 && (
              <>
                <span className="text-xs text-muted-foreground">
                  {selectedCount} selected
                </span>
                <Button variant="outline" size="sm" onClick={clearSelection}>
                  Clear
                </Button>
                <Button
                  variant="outline"
                  size="sm"
                  onClick={() => {
                    const selectedCases = sortedCases.filter((c) =>
                      selectedIds.has(c.case_id)
                    );
                    const csv = exportCasesToCsv(selectedCases);
                    const timestamp = new Date().toISOString().slice(0, 10);
                    downloadCsv(`cases_selected_${timestamp}.csv`, csv);
                  }}
                >
                  <Download className="h-4 w-4 mr-1" />
                  Export {selectedCount}
                </Button>
              </>
            )}
          </div>
        </div>
        {sortedCases.map((summary) => (
          <CaseCard
            key={summary.case_id}
            summary={summary}
            onClick={() => handleCaseClick(summary.case_id)}
            selected={selectedIds.has(summary.case_id)}
            onToggleSelect={toggleSelect}
          />
        ))}
        {total > PAGE_SIZE && (
          <div className="flex items-center justify-between pt-2">
            <Button
              variant="outline"
              size="sm"
              onClick={() => setPage((p) => Math.max(0, p - 1))}
              disabled={!hasPrev}
            >
              <ChevronLeft className="h-4 w-4 mr-1" />
              Previous
            </Button>
            <span className="text-xs text-muted-foreground">
              Page {page + 1} of {Math.ceil(total / PAGE_SIZE)}
            </span>
            <Button
              variant="outline"
              size="sm"
              onClick={() => setPage((p) => p + 1)}
              disabled={!hasNext}
            >
              Next
              <ChevronRight className="h-4 w-4 ml-1" />
            </Button>
          </div>
        )}
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-background">
      {/* Header */}
      <header className="border-b">
        <div className="mx-auto max-w-5xl px-6 py-4 flex items-center justify-between">
          <div className="flex items-center gap-2">
            <LayoutDashboard className="h-5 w-5 text-primary" />
            <span className="text-lg font-semibold">DFARS Desktop</span>
          </div>
          <nav className="flex items-center gap-3">
            {session && (
              <span className="text-sm text-muted-foreground">
                {session.username}
              </span>
            )}
            <Button variant="ghost" size="sm" asChild>
              <Link to="/settings/security">
                <ShieldCheck className="h-4 w-4" />
                Settings
              </Link>
            </Button>
            <Button
              variant="outline"
              size="sm"
              onClick={() => lock()}
              title="Lock session"
            >
              <Lock className="h-4 w-4" />
              Lock
            </Button>
            <Button
              variant="outline"
              size="sm"
              onClick={() => void handleLogout()}
            >
              <LogOut className="h-4 w-4" />
              Log out
            </Button>
          </nav>
        </div>
      </header>

      {/* Main */}
      <main className="mx-auto max-w-5xl px-6 py-8">
        {/* Page title + actions */}
        <div className="flex items-center justify-between mb-6">
          <h1 className="text-xl font-semibold">Cases</h1>
          <Button asChild>
            <Link to="/case/new">
              <PlusCircle className="h-4 w-4 mr-2" />
              New Case
            </Link>
          </Button>
        </div>

        {/* Stats */}
        {cases && cases.length > 0 && <StatsCards cases={cases} />}

        {/* Charts */}
        {cases && cases.length > 0 && (
          <div className="mt-4">
            <DashboardCharts
              stats={caseStats}
              isLoading={statsLoading}
              onStatusClick={(s) => setStatusFilter(s as CaseStatus)}
              onPriorityClick={(p) => setPriorityFilter(p as CasePriority)}
            />
          </div>
        )}

        {/* Filters + Sort */}
        {cases && cases.length > 0 && (
          <div className="flex flex-wrap items-center gap-3 mb-6">
            <div className="relative flex-1 min-w-[200px]">
              <Search className="absolute left-2.5 top-1/2 -translate-y-1/2 h-4 w-4 text-muted-foreground" />
              <Input
                ref={searchInputRef}
                placeholder="Search cases…"
                value={search}
                onChange={(e) => setSearch(e.target.value)}
                className="pl-9"
              />
            </div>
            <Select
              value={statusFilter}
              onValueChange={(v) => setStatusFilter(v as CaseStatus | "all")}
            >
              <SelectTrigger className="w-36">
                <SelectValue placeholder="Status" />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="all">All statuses</SelectItem>
                {ALL_STATUSES.map((s) => (
                  <SelectItem key={s} value={s}>{s}</SelectItem>
                ))}
              </SelectContent>
            </Select>
            <Select
              value={priorityFilter}
              onValueChange={(v) => setPriorityFilter(v as CasePriority | "all")}
            >
              <SelectTrigger className="w-36">
                <SelectValue placeholder="Priority" />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="all">All priorities</SelectItem>
                {ALL_PRIORITIES.map((p) => (
                  <SelectItem key={p} value={p}>{p}</SelectItem>
                ))}
              </SelectContent>
            </Select>
            <div className="flex items-center gap-1.5">
              <Select
                value={sortField}
                onValueChange={(v) => setSortField(v as SortField)}
              >
                <SelectTrigger className="w-32">
                  <SelectValue placeholder="Sort by" />
                </SelectTrigger>
                <SelectContent>
                  {SORT_OPTIONS.map((o) => (
                    <SelectItem key={o.value} value={o.value}>{o.label}</SelectItem>
                  ))}
                </SelectContent>
              </Select>
              <Button
                variant="outline"
                size="icon"
                className="h-9 w-9"
                onClick={() =>
                  setSortDirection((d) => (d === "asc" ? "desc" : "asc"))
                }
                aria-label={`Sort ${sortDirection === "asc" ? "descending" : "ascending"}`}
                title={`Sort ${sortDirection === "asc" ? "descending" : "ascending"}`}
              >
                <ArrowUpDown className="h-4 w-4" />
              </Button>
            </div>
            {hasFilters && (
              <Button variant="ghost" size="sm" onClick={clearFilters}>
                <X className="h-4 w-4 mr-1" />
                Clear
              </Button>
            )}
            {cases && cases.length > 0 && (
              <Button
                variant="outline"
                size="sm"
                onClick={() => {
                  const csv = exportCasesToCsv(sortedCases);
                  const timestamp = new Date().toISOString().slice(0, 10);
                  downloadCsv(`cases_${timestamp}.csv`, csv);
                }}
              >
                <Download className="h-4 w-4 mr-1" />
                Export CSV
              </Button>
            )}
          </div>
        )}

        {renderContent()}

        {cases && cases.length > 0 && !isLoading && !isError && (
          <RecentActivity token={token} />
        )}
      </main>
    </div>
  );
}
