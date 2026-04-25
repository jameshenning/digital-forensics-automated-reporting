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
import {
  Plus,
  AlertCircle,
  FileText,
  CheckCircle2,
  ShieldCheck,
  User as UserIcon,
  Wrench,
} from "lucide-react";

import {
  analysisListForCase,
  analysisAdd,
  analysisReviewsListForCase,
  evidenceListForCase,
  type AnalysisNote,
  type AnalysisReview,
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
import { AnalysisReviewDialog } from "@/components/analysis-review-dialog";

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
  // Empty strings from the form are sent as null to the Rust layer so
  // the DB stores NULL (not empty string) for "not recorded". Matches
  // the existing pattern for `description`.
  const nullIfEmpty = (s: string | undefined): string | null => {
    const trimmed = (s ?? "").trim();
    return trimmed.length === 0 ? null : trimmed;
  };
  return {
    evidence_id:
      values.evidence_id && values.evidence_id !== CASE_LEVEL_VALUE
        ? values.evidence_id
        : null,
    category: values.category,
    finding: values.finding,
    description: values.description || null,
    confidence_level: values.confidence_level ?? null,
    created_by: nullIfEmpty(values.created_by),
    method_reference: nullIfEmpty(values.method_reference),
    alternatives_considered: nullIfEmpty(values.alternatives_considered),
    tool_version: nullIfEmpty(values.tool_version),
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

  // Single round-trip for ALL reviews in the case. Each AnalysisNoteCard
  // gets a pre-grouped slice via React.useMemo, eliminating the N+1 fetch
  // that the previous per-card useQuery produced.
  const { data: allReviews } = useQuery<AnalysisReview[]>({
    queryKey: queryKeys.analysisReviews.forCase(caseId),
    queryFn: () => analysisReviewsListForCase({ token, case_id: caseId }),
    enabled: !!token,
  });

  const reviewsByNote = React.useMemo(() => {
    const map = new Map<number, AnalysisReview[]>();
    for (const r of allReviews ?? []) {
      const list = map.get(r.note_id);
      if (list) list.push(r);
      else map.set(r.note_id, [r]);
    }
    return map;
  }, [allReviews]);

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
              <AnalysisNoteCard
                key={note.note_id}
                note={note}
                reviews={reviewsByNote.get(note.note_id) ?? []}
              />
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

// ─── Note card ──────────────────────────────────────────────────────────────

/**
 * Renders a single analysis note with validation chips, alternatives
 * disclosure, and review footer. `reviews` is sliced from the parent
 * panel's single per-case query — DO NOT add a per-card useQuery here
 * (the panel used to do that and produced an N+1 fetch pattern).
 */
function AnalysisNoteCard({
  note,
  reviews,
}: {
  note: AnalysisNote;
  reviews: AnalysisReview[];
}) {
  const [reviewOpen, setReviewOpen] = React.useState(false);
  const isReviewed = reviews.length > 0;

  return (
    <div className="rounded-md border p-3 text-sm space-y-2">
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

      {/* Validation metadata chips. The author chip ALWAYS renders so
           a v1 note (no metadata) shows "by not recorded" — visible
           reminder that provenance is missing, matches the report's
           rendering. Method + tool only appear when populated. */}
      <div className="flex items-center flex-wrap gap-1.5 pt-1">
        <Badge
          variant="outline"
          className={`text-[10px] py-0 px-2 font-normal ${
            note.created_by
              ? ""
              : "border-dashed text-muted-foreground/70"
          }`}
        >
          <UserIcon className="h-3 w-3 mr-1" />
          {note.created_by ?? "not recorded"}
        </Badge>
        {note.method_reference && (
          <Badge variant="outline" className="text-[10px] py-0 px-2 font-normal">
            <ShieldCheck className="h-3 w-3 mr-1" />
            {note.method_reference}
          </Badge>
        )}
        {note.tool_version && (
          <Badge variant="outline" className="text-[10px] py-0 px-2 font-normal">
            <Wrench className="h-3 w-3 mr-1" />
            {note.tool_version}
          </Badge>
        )}
      </div>

      {note.alternatives_considered && (
        <details className="rounded border-l-2 border-muted-foreground/30 pl-3 py-1 text-xs">
          <summary className="cursor-pointer text-muted-foreground select-none">
            Alternative explanations considered
          </summary>
          <p className="mt-1 whitespace-pre-wrap text-muted-foreground">
            {note.alternatives_considered}
          </p>
        </details>
      )}

      {/* Footer: timestamp, evidence link, review status + action */}
      <div className="flex items-center gap-2 text-xs text-muted-foreground flex-wrap pt-1 border-t border-border/50">
        <span>{fmtDatetime(note.created_at)}</span>
        {note.evidence_id && (
          <Badge variant="secondary" className="text-xs font-mono">
            {note.evidence_id}
          </Badge>
        )}
        {isReviewed ? (
          reviews.map((r) => (
            <Badge
              key={r.review_id}
              variant="outline"
              className="text-[10px] py-0 px-2 border-green-600/40 text-green-400"
              // Review commentary surfaces on hover/long-press; full
              // text is below the chip when populated.
              title={r.review_notes ?? undefined}
            >
              <CheckCircle2 className="h-3 w-3 mr-1" />
              Reviewed by {r.reviewed_by}
            </Badge>
          ))
        ) : (
          <Badge
            variant="outline"
            className="text-[10px] py-0 px-2 border-amber-600/40 text-amber-400"
          >
            Pending peer review
          </Badge>
        )}
        <Button
          size="sm"
          variant="ghost"
          className="ml-auto h-6 text-xs"
          onClick={() => setReviewOpen(true)}
        >
          Mark reviewed
        </Button>
      </div>

      {/* Inline review-notes block — only rendered when at least one
           review carries commentary. Indented + dim styling keeps the
           card readable while making substantive feedback visible. */}
      {reviews.some((r) => r.review_notes && r.review_notes.trim().length > 0) && (
        <div className="ml-2 pl-3 border-l-2 border-green-600/30 space-y-1 text-xs text-muted-foreground">
          {reviews
            .filter((r) => r.review_notes && r.review_notes.trim().length > 0)
            .map((r) => (
              <div key={r.review_id} className="whitespace-pre-wrap">
                <span className="text-green-400 font-medium mr-1">
                  {r.reviewed_by}:
                </span>
                {r.review_notes}
              </div>
            ))}
        </div>
      )}

      <AnalysisReviewDialog
        noteId={note.note_id}
        noteFinding={note.finding}
        open={reviewOpen}
        onOpenChange={setReviewOpen}
      />
    </div>
  );
}
