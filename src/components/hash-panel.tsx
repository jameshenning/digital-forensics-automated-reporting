/**
 * HashPanel — lists hash verification records.
 *
 * No edit, no delete (matches v1 behavior — hashes are append-only).
 *
 * Scope prop mirrors CustodyPanel:
 *   { kind: 'case', caseId: string }           — case-wide tab
 *   { kind: 'evidence', evidenceId: string, caseId: string } — inline on evidence card
 */

import React from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { Plus, AlertCircle, ShieldCheck } from "lucide-react";

import {
  hashListForCase,
  hashListForEvidence,
  hashAdd,
  type HashRecord,
  type HashInput,
} from "@/lib/bindings";
import { getToken } from "@/lib/session";
import { queryKeys } from "@/lib/query";
import { toastError, toastSuccess } from "@/lib/error-toast";
import type { HashFormValues } from "@/lib/hash-schema";

import { Button } from "@/components/ui/button";
import { Skeleton } from "@/components/ui/skeleton";
import { Alert, AlertDescription } from "@/components/ui/alert";
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { HashForm } from "@/components/hash-form";

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

type HashScope =
  | { kind: "evidence"; evidenceId: string; caseId: string }
  | { kind: "case"; caseId: string };

interface HashPanelProps {
  scope: HashScope;
}

// ---------------------------------------------------------------------------
// Helper: format datetime
// ---------------------------------------------------------------------------

function fmtDatetime(iso: string | null): string {
  if (!iso) return "—";
  const d = new Date(iso.replace(" ", "T"));
  if (isNaN(d.getTime())) return iso;
  return d.toLocaleString(undefined, {
    year: "numeric",
    month: "short",
    day: "numeric",
    hour: "2-digit",
    minute: "2-digit",
  });
}

// ---------------------------------------------------------------------------
// Convert form values → HashInput (lowercase the hash value on submit)
// ---------------------------------------------------------------------------

function formValuesToInput(values: HashFormValues): HashInput {
  return {
    algorithm: values.algorithm,
    hash_value: values.hash_value.toLowerCase(),
    verified_by: values.verified_by,
    verification_datetime: values.verification_datetime,
    notes: values.notes || null,
  };
}

// ---------------------------------------------------------------------------
// HashPanel
// ---------------------------------------------------------------------------

export function HashPanel({ scope }: HashPanelProps) {
  const token = getToken() ?? "";
  const queryClient = useQueryClient();
  const [addOpen, setAddOpen] = React.useState(false);

  const queryKey =
    scope.kind === "evidence"
      ? queryKeys.hashes.listForEvidence(scope.evidenceId)
      : queryKeys.hashes.listForCase(scope.caseId);

  const { data, isLoading, isError, error } = useQuery<HashRecord[]>({
    queryKey,
    queryFn: () =>
      scope.kind === "evidence"
        ? hashListForEvidence({ token, evidence_id: scope.evidenceId })
        : hashListForCase({ token, case_id: scope.caseId }),
    enabled: !!token,
  });

  function invalidate() {
    void queryClient.invalidateQueries({
      queryKey: queryKeys.hashes.listForCase(scope.caseId),
    });
    if (scope.kind === "evidence") {
      void queryClient.invalidateQueries({
        queryKey: queryKeys.hashes.listForEvidence(scope.evidenceId),
      });
    }
  }

  const addMutation = useMutation({
    mutationFn: (values: HashFormValues) => {
      const evidenceId =
        scope.kind === "evidence" ? scope.evidenceId : "";
      if (!evidenceId) {
        return Promise.reject(new Error("Evidence ID required to add a hash record"));
      }
      return hashAdd({ token, evidence_id: evidenceId, input: formValuesToInput(values) });
    },
    onSuccess: () => {
      invalidate();
      setAddOpen(false);
      toastSuccess("Hash verification added.");
    },
    onError: toastError,
  });

  if (isLoading) {
    return (
      <div className="space-y-2">
        {Array.from({ length: 2 }).map((_, i) => (
          <Skeleton key={i} className="h-10 w-full" />
        ))}
      </div>
    );
  }

  if (isError) {
    return (
      <Alert variant="destructive">
        <AlertCircle className="h-4 w-4" />
        <AlertDescription>
          {(error as Partial<{ message: string }>)?.message ?? "Failed to load hash records."}
        </AlertDescription>
      </Alert>
    );
  }

  const records = data ?? [];

  return (
    <div className="space-y-3">
      {/* Add button — only for evidence scope */}
      {scope.kind === "evidence" && (
        <div className="flex justify-end">
          <Button size="sm" variant="outline" onClick={() => setAddOpen(true)}>
            <Plus className="h-4 w-4 mr-1" />
            Add Hash
          </Button>
        </div>
      )}

      {/* Add button for case scope too */}
      {scope.kind === "case" && (
        <div className="flex items-center justify-between">
          <p className="text-xs text-muted-foreground">
            Hashes must be added from individual evidence items (Evidence tab).
          </p>
        </div>
      )}

      {/* Empty state */}
      {records.length === 0 && (
        <p className="text-sm text-muted-foreground py-3 text-center">
          No hash verifications recorded
          {scope.kind === "evidence" ? " for this evidence item" : " for this case"}.
        </p>
      )}

      {/* Record list */}
      {records.length > 0 && (
        <div className="space-y-1">
          {records.map((hr) => (
            <div
              key={hr.hash_id}
              className="flex items-start gap-3 rounded-md border p-3 text-sm"
            >
              <ShieldCheck className="h-4 w-4 text-green-500 shrink-0 mt-0.5" />
              <div className="flex-1 min-w-0">
                <div className="flex items-center gap-2 flex-wrap">
                  <span className="font-medium text-xs">{hr.algorithm}</span>
                  {scope.kind === "case" && (
                    <span className="font-mono text-xs text-muted-foreground">
                      {hr.evidence_id}
                    </span>
                  )}
                </div>
                <p className="font-mono text-xs break-all mt-0.5 text-muted-foreground">
                  {hr.hash_value}
                </p>
                <p className="text-xs text-muted-foreground mt-0.5">
                  Verified by {hr.verified_by} &middot; {fmtDatetime(hr.verification_datetime)}
                  {hr.notes && <span className="italic"> &middot; {hr.notes}</span>}
                </p>
              </div>
            </div>
          ))}
        </div>
      )}

      {/* Add Dialog */}
      <Dialog open={addOpen} onOpenChange={setAddOpen}>
        <DialogContent className="max-w-lg">
          <DialogHeader>
            <DialogTitle>Add Hash Verification</DialogTitle>
          </DialogHeader>
          <HashForm
            isPending={addMutation.isPending}
            onSubmit={(values) => addMutation.mutate(values)}
            onCancel={() => setAddOpen(false)}
          />
        </DialogContent>
      </Dialog>
    </div>
  );
}

export type { HashScope };
