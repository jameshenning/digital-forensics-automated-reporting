/**
 * Section 5 — Acquisition / Hash Verification
 * Reuses the existing HashPanel.
 */

import { HashPanel } from "@/components/hash-panel";

interface SectionHashesProps {
  caseId: string;
}

export function SectionHashes({ caseId }: SectionHashesProps) {
  return (
    <div className="space-y-4">
      <div>
        <h2 className="text-xl font-semibold tracking-tight">Acquisition & Hash Verification</h2>
        <p className="mt-1 text-sm text-muted-foreground">
          Verify integrity of acquired evidence via cryptographic hashes.
        </p>
      </div>
      <HashPanel scope={{ kind: "case", caseId }} />
    </div>
  );
}
