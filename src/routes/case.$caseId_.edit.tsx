/**
 * /case/:caseId/edit — Edit case metadata.
 *
 * Protected by requireAuthBeforeLoad.
 * Pre-populates the form from the TanStack Query cache (warm from detail page)
 * or fetches fresh.  case_id and investigator are read-only (immutable PK /
 * chain-of-custody integrity — mirrors v1 case_edit.html).
 *
 * On success: invalidates cases.all + cases.detail(caseId) → navigates back
 * to the case detail page.
 */

import { createFileRoute, useNavigate } from "@tanstack/react-router";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { ArrowLeft, AlertCircle } from "lucide-react";

import { requireAuthBeforeLoad } from "@/lib/auth-guard";
import { caseGet, caseUpdate, type CaseInput, type CaseDetail } from "@/lib/bindings";
import { getToken } from "@/lib/session";
import { queryKeys } from "@/lib/query";
import { toastError, toastSuccess } from "@/lib/error-toast";
import { normalizeTags } from "@/lib/case-enums";
import type { CaseFormValues } from "@/lib/case-schema";

import { CaseForm } from "@/components/case-form";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Skeleton } from "@/components/ui/skeleton";
import { Alert, AlertTitle, AlertDescription } from "@/components/ui/alert";

export const Route = createFileRoute("/case/$caseId_/edit")({
  beforeLoad: requireAuthBeforeLoad,
  component: EditCasePage,
});

function EditCasePage() {
  const { caseId } = Route.useParams();
  const navigate = useNavigate();
  const queryClient = useQueryClient();
  const token = getToken() ?? "";

  // Fetch (or reuse cache) the case detail to hydrate the form
  const { data, isLoading, isError, error } = useQuery<CaseDetail>({
    queryKey: queryKeys.cases.detail(caseId),
    queryFn: () => caseGet({ token, case_id: caseId }),
    enabled: !!token,
  });

  const mutation = useMutation({
    mutationFn: (input: CaseInput) =>
      caseUpdate({ token, case_id: caseId, input }),
    onSuccess: (updated) => {
      // Warm the detail cache with the fresh response
      queryClient.setQueryData(queryKeys.cases.detail(caseId), updated);
      void queryClient.invalidateQueries({ queryKey: queryKeys.cases.all });
      toastSuccess(`Case ${caseId} updated.`);
      void navigate({ to: "/case/$caseId", params: { caseId } });
    },
    onError: (err) => {
      toastError(err);
    },
  });

  function handleSubmit(values: CaseFormValues) {
    const input: CaseInput = {
      case_id: caseId, // ignored by backend on update, but required by type
      case_name: values.case_name,
      description: values.description?.trim() || null,
      investigator: values.investigator,
      agency: values.agency?.trim() || null,
      start_date: values.start_date,
      end_date: values.end_date?.trim() || null,
      status: values.status ?? null,
      priority: values.priority ?? null,
      classification: values.classification?.trim() || null,
      evidence_drive_path: values.evidence_drive_path?.trim() || null,
      tags: normalizeTags(values.tags_raw ?? ""),
    };
    mutation.mutate(input);
  }

  function handleCancel() {
    void navigate({ to: "/case/$caseId", params: { caseId } });
  }

  if (isLoading) {
    return (
      <div className="min-h-screen bg-background">
        <main className="mx-auto max-w-3xl px-6 py-8">
          <Skeleton className="h-8 w-32 mb-6" />
          <Card>
            <CardContent className="pt-6 space-y-4">
              {Array.from({ length: 6 }).map((_, i) => (
                <Skeleton key={i} className="h-10 w-full" />
              ))}
            </CardContent>
          </Card>
        </main>
      </div>
    );
  }

  if (isError || !data) {
    return (
      <div className="min-h-screen bg-background">
        <main className="mx-auto max-w-3xl px-6 py-8">
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
            <AlertDescription>
              {isError && error instanceof Object && "message" in error
                ? String((error as { message: unknown }).message)
                : "Case not found or could not be loaded."}
            </AlertDescription>
          </Alert>
        </main>
      </div>
    );
  }

  const { case: c, tags } = data;

  // Build default values from the fetched case
  const defaultValues: CaseFormValues = {
    case_id: c.case_id,
    case_name: c.case_name,
    description: c.description ?? "",
    investigator: c.investigator,
    agency: c.agency ?? "",
    start_date: c.start_date,
    end_date: c.end_date ?? "",
    status: c.status,
    priority: c.priority,
    classification: c.classification ?? "",
    evidence_drive_path: c.evidence_drive_path ?? "",
    tags_raw: tags.join(", "),
  };

  return (
    <div className="min-h-screen bg-background">
      <main className="mx-auto max-w-3xl px-6 py-8">
        {/* Back link */}
        <Button
          variant="ghost"
          size="sm"
          className="mb-4 -ml-2"
          onClick={handleCancel}
        >
          <ArrowLeft className="h-4 w-4 mr-1" />
          {c.case_name}
        </Button>

        <h1 className="text-xl font-semibold mb-1">
          Edit Case{" "}
          <code className="text-base font-mono text-muted-foreground">
            {caseId}
          </code>
        </h1>
        <p className="text-sm text-muted-foreground mb-6">
          Case ID and investigator are immutable for chain-of-custody integrity.
          Evidence, custody, and analysis records cannot be edited — add
          superseding records from the case detail page.
        </p>

        <Card>
          <CardHeader>
            <CardTitle className="text-base">Case Metadata</CardTitle>
          </CardHeader>
          <CardContent>
            <CaseForm
              defaultValues={defaultValues}
              readonlyCaseId={true}
              isPending={mutation.isPending}
              onSubmit={handleSubmit}
              onCancel={handleCancel}
              submitLabel="Save Changes"
            />
          </CardContent>
        </Card>
      </main>
    </div>
  );
}
