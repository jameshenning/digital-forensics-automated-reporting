/**
 * Section 2 — Chain of Custody
 * Reuses the existing CustodyPanel.
 */

import { CustodyPanel } from "@/components/custody-panel";

interface SectionCoCProps {
  caseId: string;
}

export function SectionCoC({ caseId }: SectionCoCProps) {
  return (
    <div className="space-y-4">
      <div>
        <h2 className="text-xl font-semibold tracking-tight">Chain of Custody</h2>
        <p className="mt-1 text-sm text-muted-foreground">
          Track every custody event for this case.
        </p>
      </div>
      <CustodyPanel scope={{ kind: "case", caseId }} />
    </div>
  );
}
