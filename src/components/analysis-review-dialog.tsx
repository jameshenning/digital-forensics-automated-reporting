/**
 * AnalysisReviewDialog — peer-review stamp for an analysis note.
 *
 * Opens from the "Mark reviewed" button on an AnalysisPanel note card.
 * Append-only: each submit creates a new `analysis_reviews` row; the
 * existing note is never mutated.
 *
 * The `reviewed_at` field is an HTML datetime-local input which emits
 * `"YYYY-MM-DDTHH:MM"`; we append `":00"` before the IPC call so chrono
 * on the Rust side sees a full `HH:MM:SS` (same pattern as hash-panel
 * and tools-panel — see feedback_tauri_v2_camelcase.md).
 */

import React from "react";
import { useForm } from "react-hook-form";
import { zodResolver } from "@hookform/resolvers/zod";
import { useMutation, useQueryClient } from "@tanstack/react-query";

import { analysisMarkReviewed, type AnalysisReviewInput } from "@/lib/bindings";
import { getToken } from "@/lib/session";
import { queryKeys } from "@/lib/query";
import { toastError, toastSuccess } from "@/lib/error-toast";
import {
  analysisReviewFormSchema,
  type AnalysisReviewFormValues,
} from "@/lib/analysis-review-schema";

import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Textarea } from "@/components/ui/textarea";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import {
  Form,
  FormControl,
  FormDescription,
  FormField,
  FormItem,
  FormLabel,
  FormMessage,
} from "@/components/ui/form";

interface AnalysisReviewDialogProps {
  noteId: number;
  /** Used only for display in the dialog header — "Peer-review: <finding>". */
  noteFinding: string;
  open: boolean;
  onOpenChange: (open: boolean) => void;
}

/**
 * Current local time as a `datetime-local`-compatible string
 * (`YYYY-MM-DDTHH:MM`). Used to pre-fill the reviewed_at field so the
 * common "sign off right now" path is one click.
 */
function nowDatetimeLocal(): string {
  const d = new Date();
  const pad = (n: number) => String(n).padStart(2, "0");
  return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())}T${pad(d.getHours())}:${pad(d.getMinutes())}`;
}

function formValuesToInput(values: AnalysisReviewFormValues): AnalysisReviewInput {
  // datetime-local emits HH:MM; append :00 so chrono's NaiveDateTime
  // parser on the Rust side is happy regardless of which tolerant
  // format it picks.
  let at = values.reviewed_at.trim();
  if (/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}$/.test(at)) {
    at = `${at}:00`;
  }
  return {
    reviewed_by: values.reviewed_by.trim(),
    reviewed_at: at,
    review_notes: values.review_notes?.trim() ? values.review_notes.trim() : null,
  };
}

export function AnalysisReviewDialog({
  noteId,
  noteFinding,
  open,
  onOpenChange,
}: AnalysisReviewDialogProps) {
  const token = getToken() ?? "";
  const queryClient = useQueryClient();

  const form = useForm<AnalysisReviewFormValues>({
    resolver: zodResolver(analysisReviewFormSchema),
    defaultValues: {
      reviewed_by: "",
      reviewed_at: nowDatetimeLocal(),
      review_notes: "",
    },
  });

  // Reset the form state each time the dialog opens — stale
  // "reviewed_at" from a previous session would otherwise carry over.
  // `form` from useForm is referentially stable across renders so
  // including it in deps is a no-op (no re-trigger on render); we
  // include it anyway to satisfy exhaustive-deps without a disable.
  React.useEffect(() => {
    if (open) {
      form.reset({
        reviewed_by: "",
        reviewed_at: nowDatetimeLocal(),
        review_notes: "",
      });
    }
  }, [open, form]);

  const mutation = useMutation({
    mutationFn: (values: AnalysisReviewFormValues) =>
      analysisMarkReviewed({
        token,
        note_id: noteId,
        input: formValuesToInput(values),
      }),
    onSuccess: () => {
      // Invalidate the prefix so BOTH the panel's per-case aggregate
      // and any per-note cache refresh. Cheaper than threading caseId
      // into the dialog just to invalidate the right key, and the
      // refetch cost is tiny (single per-case query).
      void queryClient.invalidateQueries({
        queryKey: queryKeys.analysisReviews.all(),
      });
      toastSuccess("Peer review recorded.");
      onOpenChange(false);
    },
    onError: toastError,
  });

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="max-w-md">
        <DialogHeader>
          <DialogTitle>Record peer review</DialogTitle>
          <DialogDescription className="line-clamp-2">
            {noteFinding}
          </DialogDescription>
        </DialogHeader>

        <Form {...form}>
          <form
            onSubmit={form.handleSubmit((values) => mutation.mutate(values))}
            className="space-y-4"
            noValidate
          >
            <FormField
              control={form.control}
              name="reviewed_by"
              render={({ field }) => (
                <FormItem>
                  <FormLabel>
                    Reviewer <span aria-hidden="true">*</span>
                  </FormLabel>
                  <FormControl>
                    <Input
                      placeholder="Reviewer name or identifier"
                      {...field}
                    />
                  </FormControl>
                  <FormMessage />
                </FormItem>
              )}
            />

            <FormField
              control={form.control}
              name="reviewed_at"
              render={({ field }) => (
                <FormItem>
                  <FormLabel>
                    Date/time <span aria-hidden="true">*</span>
                  </FormLabel>
                  <FormControl>
                    <Input type="datetime-local" {...field} />
                  </FormControl>
                  <FormMessage />
                </FormItem>
              )}
            />

            <FormField
              control={form.control}
              name="review_notes"
              render={({ field }) => (
                <FormItem>
                  <FormLabel>Review notes</FormLabel>
                  <FormControl>
                    <Textarea
                      placeholder="What did you concur with, flag, or request more detail on?"
                      rows={4}
                      {...field}
                    />
                  </FormControl>
                  <FormDescription>
                    Optional — visible in the generated report.
                  </FormDescription>
                  <FormMessage />
                </FormItem>
              )}
            />

            <div className="flex gap-2 pt-2">
              <Button type="submit" disabled={mutation.isPending}>
                {mutation.isPending ? "Recording…" : "Record review"}
              </Button>
              <Button
                type="button"
                variant="outline"
                onClick={() => onOpenChange(false)}
              >
                Cancel
              </Button>
            </div>
          </form>
        </Form>
      </DialogContent>
    </Dialog>
  );
}
