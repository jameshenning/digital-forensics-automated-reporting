/**
 * Section 1 — Case Setup
 * Displays case metadata. Links to edit page.
 */

import { useNavigate } from "@tanstack/react-router";
import { Pencil } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Card, CardContent } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Skeleton } from "@/components/ui/skeleton";
import { useQuery } from "@tanstack/react-query";
import { caseGet } from "@/lib/bindings";
import { getToken } from "@/lib/session";
import { queryKeys } from "@/lib/query";
import { statusBadgeClass, priorityBadgeClass } from "@/lib/case-enums";
import type { CaseDetail } from "@/lib/bindings";

interface SectionCaseSetupProps {
  caseId: string;
}

function fmtDate(iso: string | null): string {
  if (!iso) return "—";
  return new Date(iso).toLocaleDateString(undefined, {
    year: "numeric",
    month: "long",
    day: "numeric",
  });
}

export function SectionCaseSetup({ caseId }: SectionCaseSetupProps) {
  const navigate = useNavigate();
  const token = getToken() ?? "";

  const { data, isLoading } = useQuery<CaseDetail>({
    queryKey: queryKeys.cases.detail(caseId),
    queryFn: () => caseGet({ token, case_id: caseId }),
    enabled: !!token,
  });

  if (isLoading) {
    return (
      <div className="space-y-4">
        <Skeleton className="h-6 w-48" />
        <Skeleton className="h-32 w-full" />
      </div>
    );
  }

  if (!data) return null;

  const { case: c, tags } = data;

  return (
    <div className="space-y-6">
      <div className="flex items-start justify-between">
        <div>
          <h2 className="text-xl font-semibold tracking-tight">Case Setup</h2>
          <p className="mt-1 text-sm text-muted-foreground">
            Review and edit case metadata.
          </p>
        </div>
        <Button
          size="sm"
          variant="outline"
          onClick={() =>
            void navigate({ to: "/case/$caseId/edit", params: { caseId } })
          }
        >
          <Pencil className="h-4 w-4 mr-1.5" />
          Edit Case
        </Button>
      </div>

      <Card>
        <CardContent className="pt-6 space-y-6">
          {/* Identifiers */}
          <div>
            <h3 className="text-sm font-medium text-muted-foreground uppercase tracking-wide mb-2">
              Identifiers
            </h3>
            <div className="grid grid-cols-1 gap-3 sm:grid-cols-2">
              <div>
                <p className="text-xs text-muted-foreground">Case Name</p>
                <p className="text-sm font-medium">{c.case_name}</p>
              </div>
              <div>
                <p className="text-xs text-muted-foreground">Case ID</p>
                <p className="text-sm font-mono">{c.case_id}</p>
              </div>
            </div>
          </div>

          {/* Status */}
          <div>
            <h3 className="text-sm font-medium text-muted-foreground uppercase tracking-wide mb-2">
              Status
            </h3>
            <div className="flex flex-wrap gap-2">
              <span className={`inline-flex items-center rounded-full border px-2.5 py-0.5 text-xs font-medium ${statusBadgeClass(c.status)}`}>
                {c.status}
              </span>
              <span className={`inline-flex items-center rounded-full border px-2.5 py-0.5 text-xs font-medium ${priorityBadgeClass(c.priority)}`}>
                {c.priority}
              </span>
              {tags.map((tag) => (
                <Badge key={tag} variant="secondary" className="text-xs">
                  {tag}
                </Badge>
              ))}
            </div>
          </div>

          {/* Details */}
          <div>
            <h3 className="text-sm font-medium text-muted-foreground uppercase tracking-wide mb-2">
              Details
            </h3>
            <div className="grid grid-cols-1 gap-3 sm:grid-cols-2">
              <div>
                <p className="text-xs text-muted-foreground">Investigator</p>
                <p className="text-sm">{c.investigator}</p>
              </div>
              <div>
                <p className="text-xs text-muted-foreground">Agency</p>
                <p className="text-sm">{c.agency ?? "—"}</p>
              </div>
              <div>
                <p className="text-xs text-muted-foreground">Start Date</p>
                <p className="text-sm">{fmtDate(c.start_date)}</p>
              </div>
              <div>
                <p className="text-xs text-muted-foreground">End Date</p>
                <p className="text-sm">{fmtDate(c.end_date)}</p>
              </div>
              <div>
                <p className="text-xs text-muted-foreground">Classification</p>
                <p className="text-sm">{c.classification ?? "—"}</p>
              </div>
              <div>
                <p className="text-xs text-muted-foreground">Evidence Drive</p>
                <p className="text-sm font-mono">{c.evidence_drive_path ?? "—"}</p>
              </div>
            </div>
          </div>

          {c.description && (
            <div>
              <h3 className="text-sm font-medium text-muted-foreground uppercase tracking-wide mb-2">
                Description
              </h3>
              <p className="text-sm whitespace-pre-wrap">{c.description}</p>
            </div>
          )}
        </CardContent>
      </Card>
    </div>
  );
}
