/**
 * ToolsPanel — lists tool usage records for a case.
 *
 * "Add Tool" opens a Dialog with ToolForm.
 * Each row shows: tool_name + version, purpose (truncated), operator,
 * execution_datetime, and an evidence chip if evidence_id is non-null.
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
import { Badge } from "@/components/ui/badge";
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { ToolForm } from "@/components/tool-form";

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

interface ToolsPanelProps {
  caseId: string;
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
// Convert form values → ToolInput
// ---------------------------------------------------------------------------

const CASE_WIDE_VALUE = "__case_wide__";

function formValuesToInput(values: ToolFormValues): ToolInput {
  return {
    evidence_id: values.evidence_id && values.evidence_id !== CASE_WIDE_VALUE
      ? values.evidence_id
      : null,
    tool_name: values.tool_name,
    version: values.version || null,
    purpose: values.purpose,
    command_used: values.command_used || null,
    input_file: values.input_file || null,
    output_file: values.output_file || null,
    execution_datetime: values.execution_datetime || null,
    operator: values.operator,
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

  // Load evidence list to populate the tool form's evidence select
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
      <div className="space-y-2">
        {Array.from({ length: 3 }).map((_, i) => (
          <Skeleton key={i} className="h-14 w-full" />
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

  const tools = data ?? [];
  const evidenceList = evidenceData ?? [];

  return (
    <div className="space-y-3">
      {/* Header */}
      <div className="flex items-center justify-between">
        <p className="text-sm text-muted-foreground">
          {tools.length === 0
            ? "No tool usages recorded."
            : `${tools.length} tool usage${tools.length === 1 ? "" : "s"}`}
        </p>
        <Button size="sm" onClick={() => setAddOpen(true)}>
          <Plus className="h-4 w-4 mr-1" />
          Add Tool
        </Button>
      </div>

      {/* List */}
      {tools.map((t) => (
        <div key={t.tool_id} className="flex items-start gap-3 rounded-md border p-3 text-sm">
          <Wrench className="h-4 w-4 shrink-0 mt-0.5 text-muted-foreground" />
          <div className="flex-1 min-w-0">
            <div className="flex items-center gap-2 flex-wrap">
              <span className="font-medium">{t.tool_name}</span>
              {t.version && (
                <span className="font-mono text-xs text-muted-foreground">v{t.version}</span>
              )}
              {t.evidence_id && (
                <Badge variant="secondary" className="text-xs font-mono">
                  {t.evidence_id}
                </Badge>
              )}
            </div>
            <p
              className="text-sm text-muted-foreground truncate"
              title={t.purpose}
            >
              {t.purpose}
            </p>
            <p className="text-xs text-muted-foreground mt-0.5">
              {t.operator} &middot; {fmtDatetime(t.execution_datetime)}
            </p>
            {t.command_used && (
              <p className="font-mono text-xs text-muted-foreground truncate mt-0.5" title={t.command_used}>
                {t.command_used}
              </p>
            )}
          </div>
        </div>
      ))}

      {/* Add Dialog */}
      <Dialog open={addOpen} onOpenChange={setAddOpen}>
        <DialogContent className="max-w-xl">
          <DialogHeader>
            <DialogTitle>Add Tool Usage</DialogTitle>
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
