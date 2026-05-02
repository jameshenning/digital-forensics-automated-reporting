/**
 * Section 3 — Evidence Collection
 * Placeholder for collection-specific fields.
 */

import { Card, CardContent } from "@/components/ui/card";

interface SectionCollectionProps {
  caseId: string;
}

export function SectionCollection({ caseId: _caseId }: SectionCollectionProps) {
  return (
    <div className="space-y-6">
      <div>
        <h2 className="text-xl font-semibold tracking-tight">Evidence Collection</h2>
        <p className="mt-1 text-sm text-muted-foreground">
          Document how and where evidence was collected.
        </p>
      </div>

      <Card>
        <CardContent className="pt-6">
          <p className="text-sm text-muted-foreground">
            Collection details are recorded per evidence item in the{" "}
            <strong>Evidence Inventory</strong> section. Navigate there to add
            collection datetime, location, and collector information for each
            item.
          </p>
        </CardContent>
      </Card>
    </div>
  );
}
