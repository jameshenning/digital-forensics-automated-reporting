/**
 * ToolsPanel — case-wide tool runs only.
 *
 * Tools attached to a specific evidence item now render INSIDE that evidence
 * item's "Tools Used" disclosure in the Evidence tab (see EvidenceToolsPanel).
 * This panel shows only tools with `evidence_id = null`, which are case-wide
 * operations like OSINT runs that Agent Zero performs against a person
 * entity, or case-level hash verifications.
 *
 * Each tool is rendered via the shared `ToolCard` component — same narrative
 * format as the per-evidence panel.
 */

import React from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { Plus, AlertCircle, Wrench } from "lucide-react";

import {
  toolListForCase,
  toolAdd,
  evidenceListForCase,
  type ToolUsage,
  type ToolInput,
  type Evidence,
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
// Types
// ---------------------------------------------------------------------------

interface ToolsPanelProps {
  caseId: string;
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function formValuesToInput(values: ToolFormValues): ToolInput {
  // Rust ToolInput.execution_datetime is Option<NaiveDateTime>; serde requires
  // "YYYY-MM-DDTHH:MM:SS". datetime-local emits "YYYY-MM-DDTHH:MM" — append
  // ":00" so deserialization succeeds.
  const dtRaw = values.execution_datetime || null;
  const execution_datetime =
    dtRaw && /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}$/.test(dtRaw) ? dtRaw + ":00" : dtRaw;

  // Case-wide panel — evidence_id is always null here. Evidence-specific
  // tool runs are added via EvidenceToolsPanel and the inline disclosure
  // under each EvidenceCard.
  return {
    evidence_id: null,
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
// ToolsPanel
// ---------------------------------------------------------------------------

export function ToolsPanel({ caseId }: ToolsPanelProps) {
  const token = getToken() ?? "";
  const queryClient = useQueryClient();
  const [addOpen, setAddOpen] = React.useState(false);

  const { data, isLoading, isError, error } = useQuery<ToolUsage[]>({
    queryKey: queryKeys.tools.listForCase(caseId),
    queryFn: () => toolListForCase({ token, case_id: caseId }),
    enabled: !!token,
  });

  const { data: evidenceData } = useQuery<Evidence[]>({
    queryKey: queryKeys.evidence.listForCase(caseId),
    queryFn: () => evidenceListForCase({ token, case_id: caseId }),
    enabled: !!token,
  });

  const addMutation = useMutation({
    mutationFn: (values: ToolFormValues) =>
      toolAdd({ token, case_id: caseId, input: formValuesToInput(values) }),
    onSuccess: () => {
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
        {Array.from({ length: 2 }).map((_, i) => (
          <Skeleton key={i} className="h-64 w-full" />
        ))}
      </div>
    );
  }

  if (isError) {
    return (
      <Alert variant="destructive">
        <AlertCircle className="h-4 w-4" />
        <AlertDescription>
          {(error as Partial<{ message: string }>)?.message ?? "Failed to load tool usages."}
        </AlertDescription>
      </Alert>
    );
  }

  const allTools = data ?? [];
  const evidenceList = evidenceData ?? [];
  // Case-wide panel: only tools with evidence_id = null (OSINT runs,
  // case-level operations). Evidence-specific tools render inside the
  // Evidence tab's per-evidence Tools Used disclosure (EvidenceToolsPanel).
  const caseWideTools = allTools.filter((t) => t.evidence_id === null);
  // Dependency-chain resolution uses the full case tool set so the "feeds
  // into" / "consumes from" chips can reference tools attached to specific
  // evidence items, not just case-wide ones.
  const caseToolNames = allTools.map((t) => t.tool_name);

  return (
    <div className="space-y-4">
      {/* Header */}
      <div className="flex items-center justify-between gap-3 flex-wrap">
        <div className="min-w-0">
          <p className="text-sm text-muted-foreground">
            {caseWideTools.length === 0
              ? "No case-wide tool runs recorded."
              : `${caseWideTools.length} case-wide tool run${caseWideTools.length === 1 ? "" : "s"}`}
          </p>
          <p className="text-xs text-muted-foreground/80 mt-0.5">
            Tools used to examine a specific evidence item live under that
            item in the <span className="font-medium">Evidence</span> tab.
            This tab shows only case-wide runs (OSINT, case-level forensics).
          </p>
        </div>
        <Button size="sm" onClick={() => setAddOpen(true)}>
          <Plus className="h-4 w-4 mr-1.5" />
          Add Case-wide Tool
        </Button>
      </div>

      {/* Narrative cards */}
      {caseWideTools.length === 0 ? (
        <div className="rounded-lg border border-dashed p-8 text-center">
          <Wrench className="h-8 w-8 mx-auto text-muted-foreground/50 mb-2" />
          <p className="text-sm font-medium">No case-wide tool runs yet</p>
          <p className="text-xs text-muted-foreground mt-1">
            To record a tool that examined specific evidence, open the{" "}
            <span className="font-medium">Evidence</span> tab, expand the
            evidence item, and click <span className="font-medium">Tools Used</span>.
          </p>
        </div>
      ) : (
        <div className="space-y-4">
          {caseWideTools.map((t) => (
            <ToolCard
              key={t.tool_id}
              usage={t}
              caseToolNames={caseToolNames}
              hideScopeBadge
            />
          ))}
        </div>
      )}

      {/* Add Dialog — case-wide only (evidence_id forced null in formValuesToInput) */}
      <Dialog open={addOpen} onOpenChange={setAddOpen}>
        <DialogContent className="max-w-xl">
          <DialogHeader>
            <DialogTitle>Add Case-wide Tool</DialogTitle>
          </DialogHeader>
          <ToolForm
            evidenceList={evidenceList}
            isPending={addMutation.isPending}
            onSubmit={(values) => addMutation.mutate(values)}
            onCancel={() => setAddOpen(false)}
          />
        </DialogContent>
      </Dialog>
    </div>
  );
}
