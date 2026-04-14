/**
 * Dashboard — Phase 2: case list with full CRUD entry points.
 *
 * Protected by requireAuthBeforeLoad.
 * Fetches CaseSummary[] via TanStack Query → casesList Tauri command.
 * Each case card navigates to /case/:caseId.
 */

import type React from "react";
import { createFileRoute, Link, useNavigate } from "@tanstack/react-router";
import {
  LayoutDashboard,
  ShieldCheck,
  LogOut,
  PlusCircle,
  FolderOpen,
  RefreshCw,
} from "lucide-react";
import { useQuery, useQueryClient } from "@tanstack/react-query";

import { useSession } from "@/lib/session";
import { requireAuthBeforeLoad } from "@/lib/auth-guard";
import { authLogout, casesList } from "@/lib/bindings";
import { getToken, clearToken } from "@/lib/session";
import { queryKeys } from "@/lib/query";
import { toastError } from "@/lib/error-toast";
import { statusBadgeClass, priorityBadgeClass } from "@/lib/case-enums";
import type { CaseSummary } from "@/lib/bindings";

import { Button } from "@/components/ui/button";
import { Card, CardContent } from "@/components/ui/card";
import { Skeleton } from "@/components/ui/skeleton";
import { Alert, AlertTitle, AlertDescription } from "@/components/ui/alert";

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
}

function CaseCard({ summary, onClick }: CaseCardProps) {
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

  return (
    <div
      role="button"
      tabIndex={0}
      className="rounded-lg border bg-card text-card-foreground shadow-sm p-4 cursor-pointer hover:border-primary/50 hover:bg-accent/10 transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-2"
      onClick={onClick}
      onKeyDown={handleKeyDown}
      aria-label={`Open case ${summary.case_name}`}
    >
      {/* Top row: name + status/priority badges */}
      <div className="flex items-start justify-between gap-3 mb-2">
        <div className="min-w-0">
          <p className="font-semibold text-base leading-tight truncate">
            {summary.case_name}
          </p>
          <code className="text-xs text-muted-foreground font-mono">
            {summary.case_id}
          </code>
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

function DashboardPage() {
  const { session } = useSession();
  const navigate = useNavigate();
  const queryClient = useQueryClient();

  const token = getToken() ?? "";

  const {
    data: cases,
    isLoading,
    isError,
    error,
    refetch,
  } = useQuery({
    queryKey: queryKeys.cases.list(100, 0),
    queryFn: () => casesList({ token, limit: 100, offset: 0 }),
    enabled: !!token,
  });

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

    return (
      <div className="space-y-3">
        {cases.map((summary) => (
          <CaseCard
            key={summary.case_id}
            summary={summary}
            onClick={() => handleCaseClick(summary.case_id)}
          />
        ))}
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

        {renderContent()}
      </main>
    </div>
  );
}
