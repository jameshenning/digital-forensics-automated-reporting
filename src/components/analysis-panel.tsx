/**
 * AnalysisPanel — lists analysis notes for a case.
 *
 * "Add Note" opens a Dialog with AnalysisForm.
 * Notes are grouped by category with a small section heading per group.
 * Each note shows: finding (big), description (smaller), confidence badge,
 * created_at, and linked evidence_id if present.
 */

import React from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { Plus, AlertCircle, FileText } from "lucide-react";

import {
  analysisListForCase,
  analysisAdd,
  evidenceListForCase,
  type AnalysisNote,
  type AnalysisInput,
  type AnalysisCategory,
  type Evidence,
} from "@/lib/bindings";
import { ANALYSIS_CATEGORIES } from "@/lib/record-enums";
import { getToken } from "@/lib/session";
import { queryKeys } from "@/lib/query";
import { toastError, toastSuccess } from "@/lib/error-toast";
import type { AnalysisFormValues } from "@/lib/analysis-schema";

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
import { AnalysisForm } from "@/components/analysis-form";

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

interface AnalysisPanelProps {
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
// Confidence badge helper
// ---------------------------------------------------------------------------

function confidenceBadgeClass(level: string): string {
  switch (level) {
    case "High":
      return "bg-green-600/20 text-green-400 border-green-600/30";
    case "Medium":
      return "bg-yellow-600/20 text-yellow-400 border-yellow-600/30";
    case "Low":
      return "bg-slate-600/20 text-slate-400 border-slate-600/30";
    default:
      return "";
  }
}

// ---------------------------------------------------------------------------
// Convert form values → AnalysisInput
// ---------------------------------------------------------------------------

const CASE_LEVEL_VALUE = "__case_level__";

function formValuesToInput(values: AnalysisFormValues): AnalysisInput {
  return {
    evidence_id:
      values.evidence_id && values.evidence_id !== CASE_LEVEL_VALUE
        ? values.evidence_id
        : null,
    category: values.category,
    finding: values.finding,
    description: values.description || null,
    confidence_level: values.confidence_level ?? null,
  };
}

// ---------------------------------------------------------------------------
// AnalysisPanel
// ---------------------------------------------------------------------------

export function AnalysisPanel({ caseId }: AnalysisPanelProps) {
  const token = getToken() ?? "";
  const queryClient = useQueryClient();
  const [addOpen, setAddOpen] = React.useState(false);

  const { data, isLoading, isError, error } = useQuery<AnalysisNote[]>({
    queryKey: queryKeys.analysis.listForCase(caseId),
    queryFn: () => analysisListForCase({ token, case_id: caseId }),
    enabled: !!token,
  });

  const { data: evidenceData } = useQuery<Evidence[]>({
    queryKey: queryKeys.evidence.listForCase(caseId),
    queryFn: () => evidenceListForCase({ token, case_id: caseId }),
    enabled: !!token,
  });

  const addMutation = useMutation({
    mutationFn: (values: AnalysisFormValues) =>
      analysisAdd({ token, case_id: caseId, input: formValuesToInput(values) }),
    onSuccess: () => {
      void queryClient.invalidateQueries({
        queryKey: queryKeys.analysis.listForCase(caseId),
      });
      setAddOpen(false);
      toastSuccess("Analysis note added.");
    },
    onError: toastError,
  });

  if (isLoading) {
    return (
      <div className="space-y-3">
        {Array.from({ length: 3 }).map((_, i) => (
          <Skeleton key={i} className="h-16 w-full" />
        ))}
      </div>
    );
  }

  if (isError) {
    return (
      <Alert variant="destructive">
        <AlertCircle className="h-4 w-4" />
        <AlertDescription>
          {(error as Partial<{ message: string }>)?.message ?? "Failed to load analysis notes."}
        </AlertDescription>
      </Alert>
    );
  }

  const notes = data ?? [];
  const evidenceList = evidenceData ?? [];

  // Group by category in the order defined in ANALYSIS_CATEGORIES
  const grouped = ANALYSIS_CATEGORIES.reduce<Record<AnalysisCategory, AnalysisNote[]>>(
    (acc, cat) => {
      acc[cat] = notes.filter((n) => n.category === cat);
      return acc;
    },
    {} as Record<AnalysisCategory, AnalysisNote[]>
  );

  const categoriesWithNotes = ANALYSIS_CATEGORIES.filter(
    (cat) => (grouped[cat]?.length ?? 0) > 0
  );

  return (
    <div className="space-y-4">
      {/* Header */}
      <div className="flex items-center justify-between">
        <p className="text-sm text-muted-foreground">
          {notes.length === 0
            ? "No analysis notes recorded."
            : `${notes.length} note${notes.length === 1 ? "" : "s"} across ${categoriesWithNotes.length} categor${categoriesWithNotes.length === 1 ? "y" : "ies"}`}
        </p>
        <Button size="sm" onClick={() => setAddOpen(true)}>
          <Plus className="h-4 w-4 mr-1" />
          Add Note
        </Button>
      </div>

      {/* Grouped notes */}
      {categoriesWithNotes.map((cat) => (
        <div key={cat}>
          <h4 className="text-xs font-semibold uppercase tracking-wider text-muted-foreground mb-2 flex items-center gap-1.5">
            <FileText className="h-3.5 w-3.5" />
            {cat}
            <span className="font-normal">({grouped[cat]?.length ?? 0})</span>
          </h4>
          <div className="space-y-2 pl-1">
            {(grouped[cat] ?? []).map((note) => (
              <div
                key={note.note_id}
                className="rounded-md border p-3 text-sm space-y-1"
              >
                <div className="flex items-start justify-between gap-2">
                  <p className="font-medium leading-snug">{note.finding}</p>
                  <span
                    className={`inline-flex items-center rounded-full border px-2 py-0.5 text-xs font-medium shrink-0 ${confidenceBadgeClass(note.confidence_level)}`}
                  >
                    {note.confidence_level}
                  </span>
                </div>
                {note.description && (
                  <p className="text-xs text-muted-foreground whitespace-pre-wrap">
                    {note.description}
                  </p>
                )}
                <div className="flex items-center gap-2 text-xs text-muted-foreground flex-wrap">
                  <span>{fmtDatetime(note.created_at)}</span>
                  {note.evidence_id && (
                    <Badge variant="secondary" className="text-xs font-mono">
                      {note.evidence_id}
                    </Badge>
                  )}
                </div>
              </div>
            ))}
          </div>
        </div>
      ))}

      {/* Add Dialog */}
      <Dialog open={addOpen} onOpenChange={setAddOpen}>
        <DialogContent className="max-w-xl">
          <DialogHeader>
            <DialogTitle>Add Analysis Note</DialogTitle>
          </DialogHeader>
          <AnalysisForm
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
