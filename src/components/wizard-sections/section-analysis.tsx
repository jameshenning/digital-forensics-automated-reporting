/**
 * Section 7 — Examination Process & Findings
 * Reuses the existing AnalysisPanel.
 */

import { AnalysisPanel } from "@/components/analysis-panel";

interface SectionAnalysisProps {
  caseId: string;
}

export function SectionAnalysis({ caseId }: SectionAnalysisProps) {
  return (
    <div className="space-y-4">
      <div>
        <h2 className="text-xl font-semibold tracking-tight">Examination Process & Findings</h2>
        <p className="mt-1 text-sm text-muted-foreground">
          Record analysis notes, findings, and observations.
        </p>
      </div>
      <AnalysisPanel caseId={caseId} />
    </div>
  );
}
