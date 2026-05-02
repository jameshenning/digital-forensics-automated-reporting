/**
 * Section 9 — Disposition
 * Shows current evidence status overview.
 */

import { Card, CardContent } from "@/components/ui/card";
import { useQuery } from "@tanstack/react-query";
import { evidenceListForCase } from "@/lib/bindings";
import { getToken } from "@/lib/session";
import { queryKeys } from "@/lib/query";
import { Skeleton } from "@/components/ui/skeleton";
import { Badge } from "@/components/ui/badge";

interface SectionDispositionProps {
  caseId: string;
}

const STATUS_COLORS: Record<string, string> = {
  Active: "bg-primary/15 text-primary dark:bg-primary/20 dark:text-primary",
  Closed: "bg-success/15 text-success dark:bg-success/20 dark:text-success",
  Pending: "bg-warning/15 text-warning dark:bg-warning/20 dark:text-warning",
  Archived: "bg-gray-100 text-gray-800 dark:bg-gray-800 dark:text-gray-200",
};

export function SectionDisposition({ caseId }: SectionDispositionProps) {
  const token = getToken() ?? "";
  const { data, isLoading } = useQuery({
    queryKey: queryKeys.evidence.listForCase(caseId),
    queryFn: () => evidenceListForCase({ token, case_id: caseId }),
    enabled: !!token,
  });

  return (
    <div className="space-y-6">
      <div>
        <h2 className="text-xl font-semibold tracking-tight">Disposition</h2>
        <p className="mt-1 text-sm text-muted-foreground">
          Overview of evidence status and storage locations.
        </p>
      </div>

      {isLoading ? (
        <Skeleton className="h-32 w-full" />
      ) : !data || data.length === 0 ? (
        <Card>
          <CardContent className="pt-6">
            <p className="text-sm text-muted-foreground">
              No evidence items recorded. Add items in the Evidence Inventory
              section.
            </p>
          </CardContent>
        </Card>
      ) : (
        <div className="space-y-3">
          {data.map((item) => (
            <Card key={item.evidence_id}>
              <CardContent className="pt-4 flex items-start justify-between gap-4">
                <div className="min-w-0">
                  <p className="text-sm font-medium truncate">
                    {item.description}
                  </p>
                  <p className="text-xs text-muted-foreground font-mono mt-0.5">
                    {item.evidence_id}
                  </p>
                  <p className="text-xs text-muted-foreground mt-1">
                    Storage: {item.storage_location ?? "—"}
                  </p>
                </div>
                <Badge
                  variant="secondary"
                  className={STATUS_COLORS[item.status] ?? ""}
                >
                  {item.status}
                </Badge>
              </CardContent>
            </Card>
          ))}
        </div>
      )}
    </div>
  );
}
