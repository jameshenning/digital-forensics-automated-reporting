/**
 * /case/new — Create a new forensic case.
 *
 * Protected by requireAuthBeforeLoad.
 * Uses react-hook-form + zod via the shared CaseForm component.
 * On success: invalidates cases query cache → navigates to the new case detail.
 * On error: shows a toast, keeps form state intact for retry.
 */

import { createFileRoute, useNavigate } from "@tanstack/react-router";
import { useMutation, useQueryClient } from "@tanstack/react-query";
import { ArrowLeft } from "lucide-react";

import { requireAuthBeforeLoad } from "@/lib/auth-guard";
import { caseCreate, type CaseInput } from "@/lib/bindings";
import { getToken } from "@/lib/session";
import { queryKeys } from "@/lib/query";
import { toastError, toastSuccess } from "@/lib/error-toast";
import { normalizeTags } from "@/lib/case-enums";
import type { CaseFormValues } from "@/lib/case-schema";

import { CaseForm } from "@/components/case-form";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";

export const Route = createFileRoute("/case/new")({
  beforeLoad: requireAuthBeforeLoad,
  component: NewCasePage,
});

function NewCasePage() {
  const navigate = useNavigate();
  const queryClient = useQueryClient();
  const token = getToken() ?? "";

  const mutation = useMutation({
    mutationFn: (input: CaseInput) => caseCreate({ token, input }),
    onSuccess: (data) => {
      // Warm the detail cache immediately so the detail page loads instantly
      queryClient.setQueryData(
        queryKeys.cases.detail(data.case.case_id),
        data
      );
      // Invalidate the list so the dashboard re-fetches
      void queryClient.invalidateQueries({ queryKey: queryKeys.cases.all });
      toastSuccess(`Case ${data.case.case_id} created.`);
      void navigate({
        to: "/case/$caseId",
        params: { caseId: data.case.case_id },
      });
    },
    onError: (err) => {
      toastError(err);
    },
  });

  function handleSubmit(values: CaseFormValues) {
    const input: CaseInput = {
      case_id: values.case_id,
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
    void navigate({ to: "/dashboard" });
  }

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
          Dashboard
        </Button>

        <h1 className="text-xl font-semibold mb-6">New Case</h1>

        <Card>
          <CardHeader>
            <CardTitle className="text-base">Case Information</CardTitle>
          </CardHeader>
          <CardContent>
            <CaseForm
              isPending={mutation.isPending}
              onSubmit={handleSubmit}
              onCancel={handleCancel}
              submitLabel="Create Case"
            />
          </CardContent>
        </Card>
      </main>
    </div>
  );
}
