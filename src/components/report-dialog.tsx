/**
 * ReportDialog — case report preview and generate.
 *
 * Opened from the case detail page header.  Fetches a live markdown preview
 * from the backend via TanStack Query and renders it with react-markdown +
 * remark-gfm.  Two footer actions:
 *   - Download as Markdown  (calls case_report_generate, opens the file)
 *   - Close
 *
 * The preview query is cached for the lifetime of the dialog mount and
 * is refetched when the dialog is reopened (cache is invalidated on close).
 */

import { useQuery, useMutation } from "@tanstack/react-query";
import ReactMarkdown from "react-markdown";
import remarkGfm from "remark-gfm";
import { openPath } from "@tauri-apps/plugin-opener";
import { FileText, Loader2, AlertCircle, RefreshCw } from "lucide-react";

import { caseReportPreview, caseReportGenerate } from "@/lib/bindings";
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
import { Skeleton } from "@/components/ui/skeleton";
import { Alert, AlertDescription } from "@/components/ui/alert";

// ---------------------------------------------------------------------------
// Props
// ---------------------------------------------------------------------------

interface ReportDialogProps {
  caseId: string;
  open: boolean;
  onClose: () => void;
}

// ---------------------------------------------------------------------------
// Component
// ---------------------------------------------------------------------------

export function ReportDialog({ caseId, open, onClose }: ReportDialogProps) {
  const token = getToken() ?? "";

  const { data: markdown, isLoading, isError, error, refetch } = useQuery<string>({
    queryKey: queryKeys.reports.preview(caseId),
    queryFn: () => caseReportPreview({ token, case_id: caseId }),
    enabled: open && !!token,
    // Keep the preview fresh for the lifetime of the dialog.
    // Stale after 5 minutes so a long-open dialog doesn't show stale data.
    staleTime: 5 * 60 * 1000,
  });

  const generateMutation = useMutation({
    mutationFn: () =>
      caseReportGenerate({ token, case_id: caseId, format: "Markdown" }),
    onSuccess: (outputPath) => {
      toastSuccess("Report written.");
      void openPath(outputPath);
    },
    onError: toastError,
  });

  return (
    <Dialog open={open} onOpenChange={(o) => { if (!o) onClose(); }}>
      <DialogContent className="max-w-3xl h-[80vh] flex flex-col p-0 gap-0">
        <DialogHeader className="px-6 pt-6 pb-3 shrink-0">
          <DialogTitle className="flex items-center gap-2 text-lg">
            <FileText className="h-5 w-5 shrink-0" aria-hidden="true" />
            Case Report Preview
          </DialogTitle>
        </DialogHeader>

        {/* Scrollable content */}
        <div className="flex-1 overflow-y-auto px-6 pb-2">
          {isLoading && (
            <div className="space-y-3 pt-2">
              {Array.from({ length: 6 }).map((_, i) => (
                <Skeleton key={i} className={`h-4 w-${i % 2 === 0 ? "full" : "3/4"}`} />
              ))}
            </div>
          )}

          {isError && (
            <div className="pt-2 space-y-3">
              <Alert variant="destructive">
                <AlertCircle className="h-4 w-4" />
                <AlertDescription>
                  {(error as Partial<{ message: string }>)?.message ??
                    "Failed to generate report preview."}
                </AlertDescription>
              </Alert>
              <Button
                variant="outline"
                size="sm"
                onClick={() => void refetch()}
              >
                <RefreshCw className="h-4 w-4 mr-2" aria-hidden="true" />
                Retry
              </Button>
            </div>
          )}

          {markdown && (
            <div
              className={[
                "prose prose-sm dark:prose-invert max-w-none",
                "prose-headings:font-semibold",
                "prose-code:before:content-none prose-code:after:content-none",
                "prose-code:bg-muted prose-code:rounded prose-code:px-1 prose-code:py-0.5",
                "prose-table:border-collapse",
                "prose-th:border prose-th:border-border prose-th:px-2 prose-th:py-1",
                "prose-td:border prose-td:border-border prose-td:px-2 prose-td:py-1",
              ].join(" ")}
            >
              <ReactMarkdown remarkPlugins={[remarkGfm]}>
                {markdown}
              </ReactMarkdown>
            </div>
          )}
        </div>

        <DialogFooter className="px-6 py-4 border-t shrink-0 gap-2">
          <Button
            variant="default"
            onClick={() => generateMutation.mutate()}
            disabled={generateMutation.isPending || isLoading}
          >
            {generateMutation.isPending ? (
              <>
                <Loader2 className="h-4 w-4 mr-2 animate-spin" aria-hidden="true" />
                Generating…
              </>
            ) : (
              "Download as Markdown"
            )}
          </Button>
          <Button variant="outline" onClick={onClose}>
            Close
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}
