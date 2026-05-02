/**
 * Section 6 — Examination Environment & Tools
 * Reuses the existing ToolsPanel.
 */

import { ToolsPanel } from "@/components/tools-panel";

interface SectionToolsProps {
  caseId: string;
}

export function SectionTools({ caseId }: SectionToolsProps) {
  return (
    <div className="space-y-4">
      <div>
        <h2 className="text-xl font-semibold tracking-tight">Examination Environment & Tools</h2>
        <p className="mt-1 text-sm text-muted-foreground">
          Document forensic tools used and examination setup.
        </p>
      </div>
      <ToolsPanel caseId={caseId} />
    </div>
  );
}
