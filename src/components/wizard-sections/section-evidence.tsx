/**
 * Section 4 — Evidence Inventory
 * Reuses the existing EvidencePanel.
 */

import { useNavigate } from "@tanstack/react-router";
import { EvidencePanel } from "@/components/evidence-panel";

interface SectionEvidenceProps {
  caseId: string;
}

export function SectionEvidence({ caseId }: SectionEvidenceProps) {
  const navigate = useNavigate();
  return (
    <div className="space-y-4">
      <div>
        <h2 className="text-xl font-semibold tracking-tight">Evidence Inventory</h2>
        <p className="mt-1 text-sm text-muted-foreground">
          All evidence items collected for this case.
        </p>
      </div>
      <EvidencePanel
        caseId={caseId}
        onNavigateToCaseEdit={() =>
          void navigate({ to: "/case/$caseId/edit", params: { caseId } })
        }
      />
    </div>
  );
}
