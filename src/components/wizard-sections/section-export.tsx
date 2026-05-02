/**
 * Section 10 — Authorization & Export
 * Provides report generation and export actions.
 */

import { lazy, Suspense, useState } from "react";
import { FileText, ShieldCheck } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";

const ReportDialog = lazy(() =>
  import("@/components/report-dialog").then((m) => ({
    default: m.ReportDialog,
  }))
);

interface SectionExportProps {
  caseId: string;
}

export function SectionExport({ caseId }: SectionExportProps) {
  const [reportOpen, setReportOpen] = useState(false);

  return (
    <div className="space-y-6">
      <div>
        <h2 className="text-xl font-semibold tracking-tight">
          Authorization & Export
        </h2>
        <p className="mt-1 text-sm text-muted-foreground">
          Generate and export the final examination report.
        </p>
      </div>

      {/* Export actions */}
      <Card>
        <CardHeader>
          <CardTitle className="text-base">Export Options</CardTitle>
        </CardHeader>
        <CardContent className="space-y-3">
          <Button
            className="w-full justify-start gap-2 bg-primary text-primary-foreground hover:bg-primary/90"
            onClick={() => setReportOpen(true)}
          >
            <FileText className="h-4 w-4" />
            Generate Report
          </Button>
          <p className="text-xs text-muted-foreground">
            Produces a SWGDE-compliant examination report in PDF, HTML, or
            Markdown format.
          </p>
        </CardContent>
      </Card>

      {/* Validation checklist placeholder */}
      <Card>
        <CardHeader>
          <CardTitle className="text-base">Pre-Export Checklist</CardTitle>
        </CardHeader>
        <CardContent>
          <div className="space-y-2">
            {[
              "Case metadata complete",
              "Evidence items documented",
              "Chain of custody recorded",
              "Hash verification performed",
              "Analysis notes entered",
            ].map((item, i) => (
              <div key={i} className="flex items-center gap-2 text-sm">
                <Badge variant="outline" className="h-5 w-5 p-0 flex items-center justify-center rounded-full">
                  <ShieldCheck className="h-3 w-3 text-success" />
                </Badge>
                <span className="text-muted-foreground">{item}</span>
              </div>
            ))}
          </div>
        </CardContent>
      </Card>

      <Suspense fallback={null}>
        <ReportDialog
          caseId={caseId}
          open={reportOpen}
          onClose={() => setReportOpen(false)}
        />
      </Suspense>
    </div>
  );
}
