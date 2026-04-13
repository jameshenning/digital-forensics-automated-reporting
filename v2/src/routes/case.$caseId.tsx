/**
 * /case/:caseId — Case detail view (Phase 3a).
 *
 * Case header card is retained from Phase 2.
 * Below it: a Tabs group with Evidence, Chain of Custody, Hashes, Tools,
 * and Analysis sub-panels.
 *
 * The Phase 2 "coming in Phase 3" placeholder card is removed.
 */

import React from "react";
import { createFileRoute, useNavigate } from "@tanstack/react-router";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import {
  Pencil,
  Trash2,
  ArrowLeft,
  AlertCircle,
  RefreshCw,
} from "lucide-react";

import { requireAuthBeforeLoad } from "@/lib/auth-guard";
import { caseGet, caseDelete } from "@/lib/bindings";
import { getToken } from "@/lib/session";
import { queryKeys } from "@/lib/query";
import { toastError, toastSuccess } from "@/lib/error-toast";
import { statusBadgeClass, priorityBadgeClass } from "@/lib/case-enums";
import type { AppError, CaseDetail } from "@/lib/bindings";

import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Skeleton } from "@/components/ui/skeleton";
import { Alert, AlertTitle, AlertDescription } from "@/components/ui/alert";
import {
  AlertDialog,
  AlertDialogAction,
  AlertDialogCancel,
  AlertDialogContent,
  AlertDialogDescription,
  AlertDialogFooter,
  AlertDialogHeader,
  AlertDialogTitle,
  AlertDialogTrigger,
} from "@/components/ui/alert-dialog";
import { Tabs, TabsList, TabsTrigger, TabsContent } from "@/components/ui/tabs";

import { EvidencePanel } from "@/components/evidence-panel";
import { CustodyPanel } from "@/components/custody-panel";
import { HashPanel } from "@/components/hash-panel";
import { ToolsPanel } from "@/components/tools-panel";
import { AnalysisPanel } from "@/components/analysis-panel";

export const Route = createFileRoute("/case/$caseId")({
  beforeLoad: requireAuthBeforeLoad,
  component: CaseDetailPage,
});

// ---------------------------------------------------------------------------
// Loading skeleton
// ---------------------------------------------------------------------------

function DetailSkeleton() {
  return (
    <div className="space-y-4">
      <Skeleton className="h-7 w-64" />
      <Skeleton className="h-4 w-40" />
      <div className="grid grid-cols-2 gap-4 mt-4">
        {Array.from({ length: 8 }).map((_, i) => (
          <div key={i} className="space-y-1">
            <Skeleton className="h-3 w-20" />
            <Skeleton className="h-4 w-32" />
          </div>
        ))}
      </div>
    </div>
  );
}

// ---------------------------------------------------------------------------
// Detail field display helper
// ---------------------------------------------------------------------------

function DetailRow({
  label,
  value,
  mono = false,
}: {
  label: string;
  value: React.ReactNode;
  mono?: boolean;
}) {
  if (value === null || value === undefined || value === "") return null;
  return (
    <div>
      <p className="text-xs font-medium text-muted-foreground uppercase tracking-wide mb-0.5">
        {label}
      </p>
      <p className={`text-sm ${mono ? "font-mono" : ""}`}>{value}</p>
    </div>
  );
}

// ---------------------------------------------------------------------------
// Delete dialog — handles CaseHasEvidence specially
// ---------------------------------------------------------------------------

interface DeleteDialogProps {
  caseId: string;
  caseName: string;
  isPending: boolean;
  hasEvidenceError: boolean;
  onConfirm: () => void;
}

function DeleteDialog({
  caseId,
  caseName,
  isPending,
  hasEvidenceError,
  onConfirm,
}: DeleteDialogProps) {
  return (
    <AlertDialog>
      <AlertDialogTrigger asChild>
        <Button variant="destructive" size="sm">
          <Trash2 className="h-4 w-4 mr-1" />
          Delete
        </Button>
      </AlertDialogTrigger>
      <AlertDialogContent>
        <AlertDialogHeader>
          <AlertDialogTitle>Delete case {caseId}?</AlertDialogTitle>
          <AlertDialogDescription asChild>
            <div className="space-y-3">
              <p>
                <strong>{caseName}</strong> will be permanently removed. This
                action cannot be undone.
              </p>
              {hasEvidenceError && (
                <div className="rounded-md border border-destructive/50 bg-destructive/10 p-3 text-sm text-destructive">
                  <strong>Cannot delete:</strong> this case has linked evidence
                  items. Delete all evidence items from the Evidence tab first.
                </div>
              )}
            </div>
          </AlertDialogDescription>
        </AlertDialogHeader>
        <AlertDialogFooter>
          <AlertDialogCancel>Cancel</AlertDialogCancel>
          {!hasEvidenceError && (
            <AlertDialogAction
              onClick={onConfirm}
              disabled={isPending}
              className="bg-destructive text-destructive-foreground hover:bg-destructive/90"
            >
              {isPending ? "Deleting…" : "Delete case"}
            </AlertDialogAction>
          )}
        </AlertDialogFooter>
      </AlertDialogContent>
    </AlertDialog>
  );
}

// ---------------------------------------------------------------------------
// Main page
// ---------------------------------------------------------------------------

function CaseDetailPage() {
  const { caseId } = Route.useParams();
  const navigate = useNavigate();
  const queryClient = useQueryClient();
  const token = getToken() ?? "";

  const [deleteHasEvidenceError, setDeleteHasEvidenceError] =
    React.useState(false);

  const { data, isLoading, isError, error, refetch } = useQuery<CaseDetail>({
    queryKey: queryKeys.cases.detail(caseId),
    queryFn: () => caseGet({ token, case_id: caseId }),
    enabled: !!token,
  });

  // On CaseNotFound, redirect to dashboard with a toast
  React.useEffect(() => {
    if (isError) {
      const appErr = error as Partial<AppError>;
      if (appErr?.code === "CaseNotFound") {
        toastError(error);
        void navigate({ to: "/dashboard" });
      }
    }
  }, [isError, error, navigate]);

  const deleteMutation = useMutation({
    mutationFn: () => caseDelete({ token, case_id: caseId }),
    onSuccess: () => {
      queryClient.removeQueries({
        queryKey: queryKeys.cases.detail(caseId),
      });
      void queryClient.invalidateQueries({ queryKey: queryKeys.cases.all });
      toastSuccess(`Case ${caseId} deleted.`);
      void navigate({ to: "/dashboard" });
    },
    onError: (err) => {
      const appErr = err as Partial<AppError>;
      if (appErr?.code === "CaseHasEvidence") {
        setDeleteHasEvidenceError(true);
      } else {
        toastError(err);
      }
    },
  });

  // Format dates for display
  function fmtDate(iso: string | null): string {
    if (!iso) return "—";
    return new Date(iso).toLocaleDateString(undefined, {
      year: "numeric",
      month: "long",
      day: "numeric",
    });
  }

  if (isLoading) {
    return (
      <div className="min-h-screen bg-background">
        <main className="mx-auto max-w-4xl px-6 py-8">
          <Skeleton className="h-8 w-32 mb-6" />
          <Card>
            <CardContent className="pt-6">
              <DetailSkeleton />
            </CardContent>
          </Card>
        </main>
      </div>
    );
  }

  if (isError) {
    const appErr = error as Partial<AppError>;
    if (appErr?.code === "CaseNotFound") return null;

    return (
      <div className="min-h-screen bg-background">
        <main className="mx-auto max-w-4xl px-6 py-8">
          <Button
            variant="ghost"
            size="sm"
            className="mb-4 -ml-2"
            onClick={() => void navigate({ to: "/dashboard" })}
          >
            <ArrowLeft className="h-4 w-4 mr-1" />
            Dashboard
          </Button>
          <Alert variant="destructive">
            <AlertCircle className="h-4 w-4" />
            <AlertTitle>Failed to load case</AlertTitle>
            <AlertDescription className="mt-2 space-y-2">
              <p>{appErr?.message ?? "An unexpected error occurred."}</p>
              <Button variant="outline" size="sm" onClick={() => void refetch()}>
                <RefreshCw className="h-4 w-4 mr-2" />
                Retry
              </Button>
            </AlertDescription>
          </Alert>
        </main>
      </div>
    );
  }

  if (!data) return null;

  const { case: c, tags } = data;

  return (
    <div className="min-h-screen bg-background">
      <main className="mx-auto max-w-4xl px-6 py-8">
        {/* Back */}
        <Button
          variant="ghost"
          size="sm"
          className="mb-4 -ml-2"
          onClick={() => void navigate({ to: "/dashboard" })}
        >
          <ArrowLeft className="h-4 w-4 mr-1" />
          Dashboard
        </Button>

        {/* Case header card */}
        <Card className="mb-4">
          <CardHeader>
            <div className="flex items-start justify-between gap-3">
              <div className="min-w-0">
                <CardTitle className="text-xl">{c.case_name}</CardTitle>
                <code className="text-xs text-muted-foreground font-mono mt-1 block">
                  {c.case_id}
                </code>
                <div className="flex flex-wrap gap-1.5 mt-2">
                  <span
                    className={`inline-flex items-center rounded-full border px-2 py-0.5 text-xs font-medium ${statusBadgeClass(c.status)}`}
                  >
                    {c.status}
                  </span>
                  <span
                    className={`inline-flex items-center rounded-full border px-2 py-0.5 text-xs font-medium ${priorityBadgeClass(c.priority)}`}
                  >
                    {c.priority}
                  </span>
                  {tags.map((tag) => (
                    <Badge key={tag} variant="secondary" className="text-xs">
                      {tag}
                    </Badge>
                  ))}
                </div>
              </div>
              <div className="flex gap-2 shrink-0">
                <Button
                  size="sm"
                  variant="outline"
                  onClick={() =>
                    void navigate({
                      to: "/case/$caseId/edit",
                      params: { caseId },
                    })
                  }
                >
                  <Pencil className="h-4 w-4 mr-1" />
                  Edit
                </Button>
                <DeleteDialog
                  caseId={caseId}
                  caseName={c.case_name}
                  isPending={deleteMutation.isPending}
                  hasEvidenceError={deleteHasEvidenceError}
                  onConfirm={() => deleteMutation.mutate()}
                />
              </div>
            </div>
          </CardHeader>

          <CardContent>
            <div className="grid grid-cols-1 gap-4 sm:grid-cols-2">
              <DetailRow label="Investigator" value={c.investigator} />
              <DetailRow label="Agency" value={c.agency} />
              <DetailRow label="Start Date" value={fmtDate(c.start_date)} />
              <DetailRow label="End Date" value={fmtDate(c.end_date)} />
              <DetailRow label="Classification" value={c.classification} />
              <DetailRow
                label="Evidence Drive"
                value={c.evidence_drive_path}
                mono
              />
              <DetailRow label="Created" value={fmtDate(c.created_at)} />
              <DetailRow label="Last Updated" value={fmtDate(c.updated_at)} />
            </div>

            {c.description && (
              <div className="mt-4">
                <p className="text-xs font-medium text-muted-foreground uppercase tracking-wide mb-1">
                  Description
                </p>
                <p className="text-sm whitespace-pre-wrap">{c.description}</p>
              </div>
            )}
          </CardContent>
        </Card>

        {/* Sub-panel tabs */}
        <Tabs defaultValue="evidence">
          <TabsList className="w-full justify-start overflow-x-auto flex-wrap h-auto gap-1 mb-4">
            <TabsTrigger value="evidence">Evidence</TabsTrigger>
            <TabsTrigger value="custody">Chain of Custody</TabsTrigger>
            <TabsTrigger value="hashes">Hashes</TabsTrigger>
            <TabsTrigger value="tools">Tools</TabsTrigger>
            <TabsTrigger value="analysis">Analysis</TabsTrigger>
          </TabsList>

          <TabsContent value="evidence">
            <Card>
              <CardHeader>
                <CardTitle className="text-base">Evidence Items</CardTitle>
              </CardHeader>
              <CardContent>
                <EvidencePanel caseId={caseId} />
              </CardContent>
            </Card>
          </TabsContent>

          <TabsContent value="custody">
            <Card>
              <CardHeader>
                <CardTitle className="text-base">Chain of Custody — Case Timeline</CardTitle>
              </CardHeader>
              <CardContent>
                <CustodyPanel scope={{ kind: "case", caseId }} />
              </CardContent>
            </Card>
          </TabsContent>

          <TabsContent value="hashes">
            <Card>
              <CardHeader>
                <CardTitle className="text-base">Hash Verifications</CardTitle>
              </CardHeader>
              <CardContent>
                <HashPanel scope={{ kind: "case", caseId }} />
              </CardContent>
            </Card>
          </TabsContent>

          <TabsContent value="tools">
            <Card>
              <CardHeader>
                <CardTitle className="text-base">Tool Usage</CardTitle>
              </CardHeader>
              <CardContent>
                <ToolsPanel caseId={caseId} />
              </CardContent>
            </Card>
          </TabsContent>

          <TabsContent value="analysis">
            <Card>
              <CardHeader>
                <CardTitle className="text-base">Analysis Notes</CardTitle>
              </CardHeader>
              <CardContent>
                <AnalysisPanel caseId={caseId} />
              </CardContent>
            </Card>
          </TabsContent>
        </Tabs>
      </main>
    </div>
  );
}
