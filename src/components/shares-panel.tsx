/**
 * SharesPanel — audit trail of email/print share events for a case.
 *
 * Lists all share records from the case_shares table, ordered by
 * created_at DESC (most recent first). Each row shows: what was shared,
 * how (email/print), by whom, when, and the narrative.
 */

import { useQuery } from "@tanstack/react-query";
import { Share2, Mail, Printer, AlertCircle, Clock } from "lucide-react";

import { sharesListForCase, type CaseShare } from "@/lib/bindings";
import { getToken } from "@/lib/session";
import { queryKeys } from "@/lib/query";

import { Skeleton } from "@/components/ui/skeleton";
import { Alert, AlertDescription } from "@/components/ui/alert";
import { Badge } from "@/components/ui/badge";

// ---------------------------------------------------------------------------
// Props
// ---------------------------------------------------------------------------

interface SharesPanelProps {
  caseId: string;
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function fmtDatetime(iso: string | null): string {
  if (!iso) return "—";
  const d = new Date(iso.replace(" ", "T"));
  if (isNaN(d.getTime())) return iso;
  return d.toLocaleString(undefined, {
    year: "numeric",
    month: "short",
    day: "numeric",
    hour: "2-digit",
    minute: "2-digit",
  });
}

function actionIcon(action: string) {
  if (action === "email") return <Mail className="h-3.5 w-3.5" />;
  if (action === "print") return <Printer className="h-3.5 w-3.5" />;
  return <Share2 className="h-3.5 w-3.5" />;
}

function actionBadgeClass(action: string): string {
  if (action === "email") return "bg-blue-600/20 text-blue-400 border-blue-600/30";
  if (action === "print") return "bg-secondary/20 text-secondary border-secondary/30";
  return "";
}

function recordTypeLabel(rt: string): string {
  switch (rt) {
    case "evidence": return "Evidence";
    case "hash": return "Hash";
    case "custody": return "Custody";
    case "tool": return "Tool";
    case "analysis": return "Analysis";
    case "report": return "Report";
    default: return rt;
  }
}

// ---------------------------------------------------------------------------
// Component
// ---------------------------------------------------------------------------

export function SharesPanel({ caseId }: SharesPanelProps) {
  const token = getToken() ?? "";

  const { data, isLoading, isError, error } = useQuery<CaseShare[]>({
    queryKey: queryKeys.shares.listForCase(caseId),
    queryFn: () => sharesListForCase({ token, case_id: caseId }),
    enabled: !!token,
  });

  if (isLoading) {
    return (
      <div className="space-y-2">
        {Array.from({ length: 3 }).map((_, i) => (
          <Skeleton key={i} className="h-16 w-full" />
        ))}
      </div>
    );
  }

  if (isError) {
    return (
      <Alert variant="destructive">
        <AlertCircle className="h-4 w-4" />
        <AlertDescription>
          {(error as Partial<{ message: string }>)?.message ?? "Failed to load share history."}
        </AlertDescription>
      </Alert>
    );
  }

  const shares = data ?? [];

  if (shares.length === 0) {
    return (
      <div className="rounded-lg border border-dashed p-8 text-center">
        <Share2 className="h-8 w-8 mx-auto text-muted-foreground/50 mb-2" />
        <p className="text-sm font-medium">No share events recorded</p>
        <p className="text-xs text-muted-foreground mt-1">
          Use the share button on evidence, analysis, custody, hash, tool, or report items to log when data leaves the app.
        </p>
      </div>
    );
  }

  return (
    <div className="space-y-2">
      <p className="text-xs text-muted-foreground mb-2">
        {shares.length} share event{shares.length === 1 ? "" : "s"} recorded
      </p>
      {shares.map((share) => (
        <div
          key={share.share_id}
          className="rounded-md border p-3 text-sm space-y-1.5"
        >
          <div className="flex items-start justify-between gap-2">
            <div className="flex items-center gap-2 flex-wrap">
              <Badge
                variant="outline"
                className={`text-xs flex items-center gap-1 ${actionBadgeClass(share.action)}`}
              >
                {actionIcon(share.action)}
                {share.action}
              </Badge>
              <span className="font-medium text-xs">
                {recordTypeLabel(share.record_type)}
              </span>
              <code className="text-xs font-mono text-muted-foreground">
                {share.record_id}
              </code>
            </div>
            <div className="flex items-center gap-1 text-xs text-muted-foreground shrink-0">
              <Clock className="h-3 w-3" />
              {fmtDatetime(share.created_at)}
            </div>
          </div>

          {share.record_summary && (
            <p className="text-xs text-muted-foreground">
              {share.record_summary}
            </p>
          )}

          {share.recipient && (
            <p className="text-xs text-muted-foreground">
              Recipient: <span className="font-medium">{share.recipient}</span>
            </p>
          )}

          <p className="text-xs text-muted-foreground">
            Shared by <span className="font-medium">{share.shared_by}</span>
          </p>

          {share.narrative && (
            <p className="text-xs text-muted-foreground italic border-l-2 border-muted-foreground/20 pl-2 mt-1">
              {share.narrative}
            </p>
          )}
        </div>
      ))}
    </div>
  );
}
