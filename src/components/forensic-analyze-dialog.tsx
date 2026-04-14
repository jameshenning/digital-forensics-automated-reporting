/**
 * ForensicAnalyzeDialog — AI-powered forensic analysis for a single evidence item.
 *
 * Flow:
 *   1. Trigger button opens the dialog with a narrative textarea.
 *   2. "Start analysis" calls evidence_forensic_analyze (300 s timeout).
 *   3. Progress states are shown during the long operation.
 *   4. Result displays the narrative (markdown), tools_used, platforms_used.
 *   5. "Save to analysis notes" button calls analysis_add to persist the result.
 */

import React from "react";
import { useMutation, useQueryClient } from "@tanstack/react-query";
import { useForm } from "react-hook-form";
import { zodResolver } from "@hookform/resolvers/zod";
import { z } from "zod";
import { FlaskConical, Loader2, CheckCircle2 } from "lucide-react";
import ReactMarkdown from "react-markdown";
import remarkGfm from "remark-gfm";

import {
  evidenceForensicAnalyze,
  analysisAdd,
  type ForensicAnalysisResult,
} from "@/lib/bindings";
import { getToken } from "@/lib/session";
import { queryKeys } from "@/lib/query";
import { toastError, toastSuccess } from "@/lib/error-toast";

import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
  DialogFooter,
} from "@/components/ui/dialog";
import { Button } from "@/components/ui/button";
import { Textarea } from "@/components/ui/textarea";
import { Label } from "@/components/ui/label";
import { Badge } from "@/components/ui/badge";

// ---------------------------------------------------------------------------
// Schema
// ---------------------------------------------------------------------------

const narrativeSchema = z.object({
  narrative: z
    .string()
    .min(1, "Narrative is required")
    .max(2000, "Narrative must be 2000 characters or fewer"),
});

type NarrativeValues = z.input<typeof narrativeSchema>;

// ---------------------------------------------------------------------------
// Progress states
// ---------------------------------------------------------------------------

type AnalysisPhase =
  | "idle"
  | "uploading"
  | "analyzing"
  | "receiving"
  | "done";

const PHASE_LABELS: Record<AnalysisPhase, string> = {
  idle: "",
  uploading: "Uploading to Agent Zero...",
  analyzing: "Agent Zero analyzing (up to 5 minutes)...",
  receiving: "Receiving result...",
  done: "Analysis complete",
};

// ---------------------------------------------------------------------------
// Props
// ---------------------------------------------------------------------------

export interface ForensicAnalyzeDialogProps {
  evidenceId: string;
  caseId: string;
  open: boolean;
  onClose: () => void;
}

// ---------------------------------------------------------------------------
// Component
// ---------------------------------------------------------------------------

export function ForensicAnalyzeDialog({
  evidenceId,
  caseId,
  open,
  onClose,
}: ForensicAnalyzeDialogProps) {
  const token = getToken() ?? "";
  const queryClient = useQueryClient();
  const [phase, setPhase] = React.useState<AnalysisPhase>("idle");
  const [result, setResult] = React.useState<ForensicAnalysisResult | null>(null);
  const [saved, setSaved] = React.useState(false);

  const {
    register,
    handleSubmit,
    reset,
    formState: { errors },
  } = useForm<NarrativeValues>({
    resolver: zodResolver(narrativeSchema),
  });

  const analyzeMutation = useMutation({
    mutationFn: async (values: NarrativeValues) => {
      setPhase("uploading");
      // Small yield so React renders the uploading state
      await new Promise<void>((r) => setTimeout(r, 150));
      setPhase("analyzing");
      const res = await evidenceForensicAnalyze({
        token,
        evidence_id: evidenceId,
        narrative: values.narrative,
      });
      setPhase("receiving");
      await new Promise<void>((r) => setTimeout(r, 100));
      return res;
    },
    onSuccess: (res) => {
      setResult(res);
      setPhase("done");
    },
    onError: (err) => {
      setPhase("idle");
      toastError(err);
    },
  });

  const saveMutation = useMutation({
    mutationFn: () => {
      if (!result) throw new Error("No result to save");
      return analysisAdd({
        token,
        case_id: caseId,
        input: {
          evidence_id: evidenceId,
          category: "Conclusion",
          finding: result.tools_used
            ? `Forensic analysis using: ${result.tools_used}`
            : "Forensic analysis result",
          description: result.narrative,
          confidence_level: "High",
        },
      });
    },
    onSuccess: () => {
      void queryClient.invalidateQueries({
        queryKey: queryKeys.analysis.listForCase(caseId),
      });
      void queryClient.invalidateQueries({
        queryKey: queryKeys.analysis.listForEvidence(evidenceId),
      });
      setSaved(true);
      toastSuccess("Forensic analysis saved to analysis notes.");
    },
    onError: toastError,
  });

  function handleClose() {
    if (analyzeMutation.isPending) return; // block close during 300s analysis
    reset();
    setResult(null);
    setPhase("idle");
    setSaved(false);
    onClose();
  }

  const isPending = analyzeMutation.isPending;

  return (
    <Dialog open={open} onOpenChange={(isOpen) => { if (!isOpen) handleClose(); }}>
      <DialogContent
        className="max-w-2xl"
        onInteractOutside={isPending ? (e) => e.preventDefault() : undefined}
        onEscapeKeyDown={isPending ? (e) => e.preventDefault() : undefined}
      >
        <DialogHeader>
          <div className="flex items-center gap-2">
            <FlaskConical className="h-5 w-5 text-primary shrink-0" />
            <DialogTitle>Forensic Analysis — {evidenceId}</DialogTitle>
          </div>
        </DialogHeader>

        {phase === "idle" && (
          <form
            onSubmit={handleSubmit((v) => analyzeMutation.mutate(v))}
            className="space-y-4"
            noValidate
          >
            <div className="space-y-1.5">
              <Label htmlFor="forensic-narrative">
                Analysis narrative <span aria-hidden="true">*</span>
              </Label>
              <Textarea
                id="forensic-narrative"
                rows={5}
                placeholder="Describe what you want Agent Zero to analyze — e.g. 'Examine this drive image for signs of data wiping or hidden partitions.'"
                {...register("narrative")}
              />
              {errors.narrative && (
                <p className="text-sm text-destructive">{errors.narrative.message}</p>
              )}
              <p className="text-xs text-muted-foreground">
                Max 2000 characters. Agent Zero will use this to guide its forensic
                tool selection and analysis focus.
              </p>
            </div>

            <div className="rounded-md border border-amber-500/40 bg-amber-500/10 p-3 text-sm text-amber-700 dark:text-amber-400">
              <strong>Note:</strong> Agent Zero will download evidence files from the
              DFARS server using a scoped API token. Analysis may take up to 5 minutes.
            </div>

            <DialogFooter>
              <Button type="button" variant="outline" onClick={handleClose}>
                Cancel
              </Button>
              <Button type="submit">
                <FlaskConical className="h-4 w-4 mr-1.5" />
                Start analysis
              </Button>
            </DialogFooter>
          </form>
        )}

        {(phase === "uploading" || phase === "analyzing" || phase === "receiving") && (
          <div className="py-8 flex flex-col items-center gap-4 text-center">
            <Loader2 className="h-10 w-10 animate-spin text-primary" />
            <p className="text-sm font-medium">{PHASE_LABELS[phase]}</p>
            {phase === "analyzing" && (
              <p className="text-xs text-muted-foreground max-w-sm">
                Agent Zero is running forensic tools against your evidence files.
                Do not close this window.
              </p>
            )}
          </div>
        )}

        {phase === "done" && result && (
          <div className="space-y-4">
            {result.error_message && (
              <div className="rounded-md border border-destructive/50 bg-destructive/10 p-3 text-sm text-destructive">
                <strong>Warning:</strong> {result.error_message}
              </div>
            )}

            <div className="flex gap-2 flex-wrap">
              {result.tools_used && result.tools_used.trim().length > 0 && (
                <div className="space-y-1">
                  <p className="text-xs font-medium text-muted-foreground uppercase tracking-wide">
                    Tools used
                  </p>
                  <div className="flex gap-1 flex-wrap">
                    {result.tools_used.split(",").map((t) => (
                      <Badge key={t.trim()} variant="secondary" className="text-xs font-mono">
                        {t.trim()}
                      </Badge>
                    ))}
                  </div>
                </div>
              )}
              {result.platforms_used && result.platforms_used.trim().length > 0 && (
                <div className="space-y-1">
                  <p className="text-xs font-medium text-muted-foreground uppercase tracking-wide">
                    Platforms
                  </p>
                  <div className="flex gap-1 flex-wrap">
                    {result.platforms_used.split(",").map((p) => (
                      <Badge key={p.trim()} variant="outline" className="text-xs">
                        {p.trim()}
                      </Badge>
                    ))}
                  </div>
                </div>
              )}
            </div>

            <div className="border rounded-md p-4 max-h-80 overflow-y-auto prose prose-sm dark:prose-invert max-w-none">
              <ReactMarkdown remarkPlugins={[remarkGfm]}>
                {result.narrative}
              </ReactMarkdown>
            </div>

            <DialogFooter className="flex gap-2 sm:justify-between items-center">
              <div>
                {saved && (
                  <span className="flex items-center gap-1 text-sm text-green-600 dark:text-green-400">
                    <CheckCircle2 className="h-4 w-4" />
                    Saved to analysis notes
                  </span>
                )}
              </div>
              <div className="flex gap-2">
                <Button
                  type="button"
                  variant="outline"
                  disabled={saved || saveMutation.isPending}
                  onClick={() => saveMutation.mutate()}
                >
                  {saveMutation.isPending ? "Saving..." : "Save to analysis notes"}
                </Button>
                <Button type="button" onClick={handleClose}>
                  Close
                </Button>
              </div>
            </DialogFooter>
          </div>
        )}
      </DialogContent>
    </Dialog>
  );
}
