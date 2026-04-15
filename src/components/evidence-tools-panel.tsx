/**
 * EvidenceToolsPanel — tool_usage rows linked to a specific evidence item.
 *
 * Rendered inline under each EvidenceCard so the tools used to examine a
 * particular piece of evidence live next to the evidence itself instead of
 * in a separate case-wide Tools tab. Each tool renders as a full narrative
 * card (ToolCard) with the About / Purpose / Findings / Why / Investigation
 * chain sections the user asked for.
 *
 * Data source: `toolListForEvidence(evidence_id)` — only rows where
 * `tool_usage.evidence_id` matches. Case-wide tool runs (evidence_id=null)
 * live in the Case-wide Tools tab and never appear here.
 *
 * Dependency chain resolution still uses the full case's tool list (from
 * `toolListForCase`) so the "feeds into" / "consumes from" chips can link
 * to tools that aren't necessarily attached to the same evidence item.
 */

import React from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { Plus, AlertCircle, Wrench } from "lucide-react";

import {
  toolListForEvidence,
  toolListForCase,
  toolAdd,
  type ToolUsage,
  type ToolInput,
} from "@/lib/bindings";
import { getToken } from "@/lib/session";
import { queryKeys } from "@/lib/query";
import { toastError, toastSuccess } from "@/lib/error-toast";
import type { ToolFormValues } from "@/lib/tool-schema";

import { Button } from "@/components/ui/button";
import { Skeleton } from "@/components/ui/skeleton";
import { Alert, AlertDescription } from "@/components/ui/alert";
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { ToolForm } from "@/components/tool-form";
import { ToolCard } from "@/components/tool-card";

// ---------------------------------------------------------------------------
// Helper — form → input
// ---------------------------------------------------------------------------

function formValuesToInput(
  values: ToolFormValues,
  lockedEvidenceId: string,
): ToolInput {
  // Rust ToolInput.execution_datetime is Option<NaiveDateTime>; serde requires
  // "YYYY-MM-DDTHH:MM:SS". datetime-local inputs emit "YYYY-MM-DDTHH:MM" (no
  // seconds), so append ":00" if needed before sending to Rust.
  const dtRaw = values.execution_datetime || null;
  const execution_datetime =
    dtRaw && /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}$/.test(dtRaw) ? dtRaw + ":00" : dtRaw;

  return {
    // Locked — always use the caller-supplied evidence_id, ignore form state.
    evidence_id: lockedEvidenceId,
    tool_name: values.tool_name,
    version: values.version || null,
    purpose: values.purpose,
    command_used: values.command_used || null,
    input_file: values.input_file || null,
    output_file: values.output_file || null,
    execution_datetime,
    operator: values.operator,
    input_sha256: values.input_sha256 || null,
    output_sha256: values.output_sha256 || null,
    environment_notes: values.environment_notes || null,
    reproduction_notes: values.reproduction_notes || null,
  };
}

// ---------------------------------------------------------------------------
// Props
// ---------------------------------------------------------------------------

interface EvidenceToolsPanelProps {
  caseId: string;
  evidenceId: string;
}

// ---------------------------------------------------------------------------
// EvidenceToolsPanel
// ---------------------------------------------------------------------------

export function EvidenceToolsPanel({ caseId, evidenceId }: EvidenceToolsPanelProps) {
  const token = getToken() ?? "";
  const queryClient = useQueryClient();
  const [addOpen, setAddOpen] = React.useState(false);

  // Tools specifically for this evidence item.
  const { data, isLoading, isError, error } = useQuery<ToolUsage[]>({
    queryKey: queryKeys.tools.listForEvidence(evidenceId),
    queryFn: () => toolListForEvidence({ token, evidence_id: evidenceId }),
    enabled: !!token,
  });

  // All tools in the case — used by ToolCard's dependency-chain resolver so
  // "feeds into" / "consumes from" chips can reference tools attached to
  // other evidence items or to the case as a whole.
  const { data: allCaseTools } = useQuery<ToolUsage[]>({
    queryKey: queryKeys.tools.listForCase(caseId),
    queryFn: () => toolListForCase({ token, case_id: caseId }),
    enabled: !!token,
  });

  const addMutation = useMutation({
    mutationFn: (values: ToolFormValues) =>
      toolAdd({
        token,
        case_id: caseId,
        input: formValuesToInput(values, evidenceId),
      }),
    onSuccess: () => {
      void queryClient.invalidateQueries({
        queryKey: queryKeys.tools.listForEvidence(evidenceId),
      });
      void queryClient.invalidateQueries({
        queryKey: queryKeys.tools.listForCase(caseId),
      });
      setAddOpen(false);
      toastSuccess("Tool usage added.");
    },
    onError: toastError,
  });

  if (isLoading) {
    return (
      <div className="space-y-3">
        <Skeleton className="h-40 w-full" />
      </div>
    );
  }

  if (isError) {
    return (
      <Alert variant="destructive">
        <AlertCircle className="h-4 w-4" />
        <AlertDescription>
          {(error as Partial<{ message: string }>)?.message ??
            "Failed to load tools."}
        </AlertDescription>
      </Alert>
    );
  }

  const tools = data ?? [];
  const caseToolNames = (allCaseTools ?? []).map((t) => t.tool_name);

  return (
    <div className="space-y-3">
      {/* Header */}
      <div className="flex items-center justify-between">
        <p className="text-xs text-muted-foreground">
          {tools.length === 0
            ? "No tools recorded for this evidence item yet."
            : `${tools.length} tool${tools.length === 1 ? "" : "s"} used on this evidence item`}
        </p>
        <Button size="sm" variant="outline" onClick={() => setAddOpen(true)}>
          <Plus className="h-3.5 w-3.5 mr-1.5" />
          Add Tool
        </Button>
      </div>

      {/* Tool narrative cards */}
      {tools.length === 0 ? (
        <div className="rounded-md border border-dashed p-4 text-center">
          <Wrench className="h-6 w-6 mx-auto text-muted-foreground/50 mb-1.5" />
          <p className="text-xs text-muted-foreground">
            Click <span className="font-medium">Add Tool</span> to record a
            forensic tool run against this evidence.
          </p>
        </div>
      ) : (
        <div className="space-y-3">
          {tools.map((t) => (
            <ToolCard
              key={t.tool_id}
              usage={t}
              caseToolNames={caseToolNames}
              hideScopeBadge
            />
          ))}
        </div>
      )}

      {/* Add Dialog */}
      <Dialog open={addOpen} onOpenChange={setAddOpen}>
        <DialogContent className="max-w-xl max-h-[90vh] overflow-y-auto">
          <DialogHeader>
            <DialogTitle>Add Tool for Evidence {evidenceId}</DialogTitle>
          </DialogHeader>
          <ToolForm
            evidenceList={[]}
            lockedEvidenceId={evidenceId}
            isPending={addMutation.isPending}
            onSubmit={(values) => addMutation.mutate(values)}
            onCancel={() => setAddOpen(false)}
          />
        </DialogContent>
      </Dialog>
    </div>
  );
}
