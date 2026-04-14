/**
 * CustodyPanel — renders a chain-of-custody list.
 *
 * Supports two modes via the `scope` prop:
 *   { kind: 'evidence', evidenceId: string }  — inline within an evidence card
 *   { kind: 'case', caseId: string }           — case-wide timeline tab
 *
 * Each entry shows: #sequence action | from → to @ datetime | location | purpose
 * Edit opens a Dialog with CustodyForm pre-populated.
 * Delete uses an AlertDialog.
 */

import React from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { Plus, Pencil, Trash2, AlertCircle } from "lucide-react";

import {
  custodyListForEvidence,
  custodyListForCase,
  custodyAdd,
  custodyUpdate,
  custodyDelete,
  type CustodyEvent,
  type CustodyInput,
} from "@/lib/bindings";
import { getToken } from "@/lib/session";
import { queryKeys } from "@/lib/query";
import { toastError, toastSuccess } from "@/lib/error-toast";
import type { CustodyFormValues } from "@/lib/custody-schema";

import { Button } from "@/components/ui/button";
import { Skeleton } from "@/components/ui/skeleton";
import { Alert, AlertDescription } from "@/components/ui/alert";
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
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
import { CustodyForm } from "@/components/custody-form";

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

type CustodyScope =
  | { kind: "evidence"; evidenceId: string; caseId: string }
  | { kind: "case"; caseId: string };

interface CustodyPanelProps {
  scope: CustodyScope;
}

// ---------------------------------------------------------------------------
// Helper: format a datetime string for display
// ---------------------------------------------------------------------------

function fmtDatetime(iso: string | null): string {
  if (!iso) return "—";
  // Handle both YYYY-MM-DDTHH:MM:SS and YYYY-MM-DDTHH:MM
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
// Convert form values → CustodyInput
// ---------------------------------------------------------------------------

function formValuesToInput(values: CustodyFormValues): CustodyInput {
  return {
    action: values.action,
    from_party: values.from_party,
    to_party: values.to_party,
    location: values.location || null,
    custody_datetime: values.custody_datetime,
    purpose: values.purpose || null,
    notes: values.notes || null,
  };
}

// ---------------------------------------------------------------------------
// Convert CustodyEvent → CustodyFormValues (for pre-populating edit form)
// ---------------------------------------------------------------------------

function eventToFormValues(event: CustodyEvent): CustodyFormValues {
  // Strip seconds from datetime if present (datetime-local needs YYYY-MM-DDTHH:MM)
  const dt = event.custody_datetime.replace(" ", "T").slice(0, 16);
  return {
    action: event.action,
    from_party: event.from_party,
    to_party: event.to_party,
    location: event.location ?? "",
    custody_datetime: dt,
    purpose: event.purpose ?? "",
    notes: event.notes ?? "",
  };
}

// ---------------------------------------------------------------------------
// CustodyPanel
// ---------------------------------------------------------------------------

export function CustodyPanel({ scope }: CustodyPanelProps) {
  const token = getToken() ?? "";
  const queryClient = useQueryClient();

  const [addOpen, setAddOpen] = React.useState(false);
  const [editTarget, setEditTarget] = React.useState<CustodyEvent | null>(null);

  // Derive caseId for invalidation — both scope kinds carry caseId
  const caseIdForInvalidation = scope.caseId;

  const queryKey =
    scope.kind === "evidence"
      ? queryKeys.custody.listForEvidence(scope.evidenceId)
      : queryKeys.custody.listForCase(scope.caseId);

  const { data, isLoading, isError, error } = useQuery<CustodyEvent[]>({
    queryKey,
    queryFn: () =>
      scope.kind === "evidence"
        ? custodyListForEvidence({ token, evidence_id: scope.evidenceId })
        : custodyListForCase({ token, case_id: scope.caseId }),
    enabled: !!token,
  });

  function invalidate() {
    void queryClient.invalidateQueries({ queryKey: queryKeys.custody.listForCase(caseIdForInvalidation) });
    if (scope.kind === "evidence") {
      void queryClient.invalidateQueries({
        queryKey: queryKeys.custody.listForEvidence(scope.evidenceId),
      });
    }
  }

  const addMutation = useMutation({
    mutationFn: (values: CustodyFormValues) => {
      const evidenceId =
        scope.kind === "evidence" ? scope.evidenceId : "";
      if (!evidenceId) {
        return Promise.reject(new Error("Evidence ID required for custody add"));
      }
      return custodyAdd({ token, evidence_id: evidenceId, input: formValuesToInput(values) });
    },
    onSuccess: () => {
      invalidate();
      setAddOpen(false);
      toastSuccess("Custody event added.");
    },
    onError: toastError,
  });

  const editMutation = useMutation({
    mutationFn: (values: CustodyFormValues) => {
      if (!editTarget) return Promise.reject(new Error("No edit target"));
      return custodyUpdate({
        token,
        custody_id: editTarget.custody_id,
        input: formValuesToInput(values),
      });
    },
    onSuccess: () => {
      invalidate();
      setEditTarget(null);
      toastSuccess("Custody event updated.");
    },
    onError: toastError,
  });

  const deleteMutation = useMutation({
    mutationFn: (custody_id: number) => custodyDelete({ token, custody_id }),
    onSuccess: () => {
      invalidate();
      toastSuccess("Custody event deleted.");
    },
    onError: toastError,
  });

  if (isLoading) {
    return (
      <div className="space-y-2">
        {Array.from({ length: 3 }).map((_, i) => (
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
          {(error as Partial<{ message: string }>)?.message ?? "Failed to load custody events."}
        </AlertDescription>
      </Alert>
    );
  }

  const events = data ?? [];

  return (
    <div className="space-y-3">
      {/* Header with Add button — only show for evidence scope (case-scope add requires an evidence_id) */}
      {scope.kind === "evidence" && (
        <div className="flex justify-end">
          <Button
            size="sm"
            variant="outline"
            onClick={() => setAddOpen(true)}
          >
            <Plus className="h-4 w-4 mr-1" />
            Add Custody Event
          </Button>
        </div>
      )}

      {/* Empty state */}
      {events.length === 0 && (
        <p className="text-sm text-muted-foreground py-3 text-center">
          No custody events recorded
          {scope.kind === "evidence" ? " for this evidence item" : " for this case"}.
        </p>
      )}

      {/* Event list */}
      {events.length > 0 && (
        <div className="space-y-1">
          {events.map((ev) => (
            <div
              key={ev.custody_id}
              className="flex items-start justify-between gap-3 rounded-md border p-3 text-sm"
            >
              <div className="flex-1 min-w-0">
                <div className="flex items-center gap-2 flex-wrap">
                  <span className="font-mono text-xs text-muted-foreground">
                    #{ev.custody_sequence}
                  </span>
                  <span className="font-medium">{ev.action}</span>
                  <span className="text-muted-foreground">
                    {ev.from_party} &rarr; {ev.to_party}
                  </span>
                  <span className="text-xs text-muted-foreground">
                    @ {fmtDatetime(ev.custody_datetime)}
                  </span>
                </div>
                <div className="mt-0.5 flex gap-3 text-xs text-muted-foreground flex-wrap">
                  {ev.location && <span>Location: {ev.location}</span>}
                  {ev.purpose && <span>Purpose: {ev.purpose}</span>}
                  {ev.notes && <span className="italic">{ev.notes}</span>}
                  {scope.kind === "case" && (
                    <span className="font-mono">Evidence: {ev.evidence_id}</span>
                  )}
                </div>
              </div>
              <div className="flex gap-1 shrink-0">
                <Button
                  size="sm"
                  variant="ghost"
                  className="h-7 w-7 p-0"
                  onClick={() => setEditTarget(ev)}
                  aria-label="Edit custody event"
                >
                  <Pencil className="h-3.5 w-3.5" />
                </Button>
                <AlertDialog>
                  <AlertDialogTrigger asChild>
                    <Button
                      size="sm"
                      variant="ghost"
                      className="h-7 w-7 p-0 text-destructive hover:text-destructive"
                      aria-label="Delete custody event"
                    >
                      <Trash2 className="h-3.5 w-3.5" />
                    </Button>
                  </AlertDialogTrigger>
                  <AlertDialogContent>
                    <AlertDialogHeader>
                      <AlertDialogTitle>Delete custody event?</AlertDialogTitle>
                      <AlertDialogDescription>
                        Custody event #{ev.custody_sequence} ({ev.action}: {ev.from_party}{" "}
                        &rarr; {ev.to_party}) will be permanently deleted.
                      </AlertDialogDescription>
                    </AlertDialogHeader>
                    <AlertDialogFooter>
                      <AlertDialogCancel>Cancel</AlertDialogCancel>
                      <AlertDialogAction
                        onClick={() => deleteMutation.mutate(ev.custody_id)}
                        className="bg-destructive text-destructive-foreground hover:bg-destructive/90"
                      >
                        Delete
                      </AlertDialogAction>
                    </AlertDialogFooter>
                  </AlertDialogContent>
                </AlertDialog>
              </div>
            </div>
          ))}
        </div>
      )}

      {/* Add Dialog */}
      <Dialog open={addOpen} onOpenChange={setAddOpen}>
        <DialogContent className="max-w-lg">
          <DialogHeader>
            <DialogTitle>Add Custody Event</DialogTitle>
          </DialogHeader>
          <CustodyForm
            isPending={addMutation.isPending}
            onSubmit={(values) => addMutation.mutate(values)}
            onCancel={() => setAddOpen(false)}
          />
        </DialogContent>
      </Dialog>

      {/* Edit Dialog */}
      <Dialog open={editTarget !== null} onOpenChange={(open) => { if (!open) setEditTarget(null); }}>
        <DialogContent className="max-w-lg">
          <DialogHeader>
            <DialogTitle>Edit Custody Event</DialogTitle>
          </DialogHeader>
          {editTarget && (
            <CustodyForm
              defaultValues={eventToFormValues(editTarget)}
              isPending={editMutation.isPending}
              onSubmit={(values) => editMutation.mutate(values)}
              onCancel={() => setEditTarget(null)}
              submitLabel="Save Changes"
            />
          )}
        </DialogContent>
      </Dialog>
    </div>
  );
}

// Re-export the scope type for use in other files
export type { CustodyScope };
