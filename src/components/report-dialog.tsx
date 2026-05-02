/**
 * ReportDialog — case report preview and generate.
 *
 * Opened from the case detail page header.  Fetches a live markdown preview
 * from the backend via TanStack Query and renders it with react-markdown +
 * remark-gfm.  Footer actions:
 *   - Format selector (Markdown / HTML / PDF)
 *   - Template selector (Standard / SWGDE Compliant) — visible when PDF
 *   - Download button
 *   - Close
 *
 * The preview query is cached for the lifetime of the dialog mount and
 * is refetched when the dialog is reopened (cache is invalidated on close).
 */

import { useState } from "react";
import { useQuery, useMutation } from "@tanstack/react-query";
import ReactMarkdown from "react-markdown";
import remarkGfm from "remark-gfm";
import { openPath } from "@tauri-apps/plugin-opener";
import { FileText, Loader2, AlertCircle, RefreshCw, Download, Share2 } from "lucide-react";

import { caseReportPreview, caseReportGenerate } from "@/lib/bindings";
import { getToken } from "@/lib/session";
import { queryKeys } from "@/lib/query";
import { toastError, toastSuccess } from "@/lib/error-toast";
import type { ReportFormat, ReportTemplate } from "@/lib/report-schema";

import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
  DialogFooter,
} from "@/components/ui/dialog";
import { Button } from "@/components/ui/button";
import { ShareDialog } from "@/components/share-dialog";
import { Skeleton } from "@/components/ui/skeleton";
import { Alert, AlertDescription } from "@/components/ui/alert";
import { Label } from "@/components/ui/label";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";

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
  const [format, setFormat] = useState<ReportFormat>("Markdown");
  const [template, setTemplate] = useState<ReportTemplate>("Standard");
  const [shareOpen, setShareOpen] = useState(false);

  const { data: markdown, isLoading, isError, error, refetch } = useQuery<string>({
    queryKey: queryKeys.reports.preview(caseId),
    queryFn: () => caseReportPreview({ token, case_id: caseId }),
    enabled: open && !!token,
    staleTime: 5 * 60 * 1000,
  });

  const generateMutation = useMutation({
    mutationFn: () =>
      caseReportGenerate({
        token,
        case_id: caseId,
        format,
        template: format === "Pdf" ? template : undefined,
      }),
    onSuccess: (outputPath) => {
      toastSuccess("Report written.");
      void openPath(outputPath);
    },
    onError: toastError,
  });

  const formatLabel = format === "Pdf" ? "PDF" : format;

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

        <DialogFooter className="px-6 py-4 border-t shrink-0 gap-3 flex-wrap items-end">
          <div className="flex flex-col gap-1.5">
            <Label htmlFor="report-format" className="text-xs text-muted-foreground">
              Format
            </Label>
            <Select
              value={format}
              onValueChange={(v) => setFormat(v as ReportFormat)}
            >
              <SelectTrigger id="report-format" className="w-36 h-9">
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="Markdown">Markdown</SelectItem>
                <SelectItem value="Html">HTML</SelectItem>
                <SelectItem value="Pdf">PDF</SelectItem>
              </SelectContent>
            </Select>
          </div>

          {format === "Pdf" && (
            <div className="flex flex-col gap-1.5">
              <Label htmlFor="report-template" className="text-xs text-muted-foreground">
                Template
              </Label>
              <Select
                value={template}
                onValueChange={(v) => setTemplate(v as ReportTemplate)}
              >
                <SelectTrigger id="report-template" className="w-44 h-9">
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="Standard">Standard</SelectItem>
                  <SelectItem value="Swgde">SWGDE Compliant</SelectItem>
                </SelectContent>
              </Select>
            </div>
          )}

          <Button
            variant="default"
            onClick={() => generateMutation.mutate()}
            disabled={generateMutation.isPending || isLoading}
            className="ml-auto"
          >
            {generateMutation.isPending ? (
              <>
                <Loader2 className="h-4 w-4 mr-2 animate-spin" aria-hidden="true" />
                Generating…
              </>
            ) : (
              <>
                <Download className="h-4 w-4 mr-2" aria-hidden="true" />
                Download as {formatLabel}
              </>
            )}
          </Button>
          <Button
            variant="outline"
            onClick={() => setShareOpen(true)}
            disabled={generateMutation.isPending || isLoading}
          >
            <Share2 className="h-4 w-4 mr-2" aria-hidden="true" />
            Log Share
          </Button>
          <Button variant="outline" onClick={onClose}>
            Close
          </Button>
        </DialogFooter>
      </DialogContent>

      <ShareDialog
        caseId={caseId}
        recordType="report"
        recordId={caseId}
        recordSummary={`Case report (${format}${format === "Pdf" ? ", " + template : ""})`}
        open={shareOpen}
        onClose={() => setShareOpen(false)}
      />
    </Dialog>
  );
}
