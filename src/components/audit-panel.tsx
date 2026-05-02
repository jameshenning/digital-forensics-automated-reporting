/**
 * AuditPanel — hash-chained tamper-evident audit timeline for a case.
 *
 * Lists all audit_entries for the case in chronological order.
 * Each row shows: action icon, actor, action label, timestamp,
 * optional details, and the chain hashes (prev_hash + entry_hash).
 * A "Verify Chain" button runs audit_verify_chain and reports
 * integrity status via toast.
 */

import { useState } from "react";
import { useQuery, useMutation } from "@tanstack/react-query";
import {
  ShieldCheck,
  ChevronDown,
  ChevronUp,
  AlertCircle,
  Clock,
  FileCheck,
  List,
} from "lucide-react";

import { auditListForCase, auditVerifyChain, type AuditEntry } from "@/lib/bindings";
import { getToken } from "@/lib/session";
import { queryKeys } from "@/lib/query";
import { toastError, toastSuccess } from "@/lib/error-toast";
import { activityIcon, activityLabel, fmtActivityTime } from "@/routes/dashboard";

import { Skeleton } from "@/components/ui/skeleton";
import { Alert, AlertDescription } from "@/components/ui/alert";
import { Button } from "@/components/ui/button";

// ---------------------------------------------------------------------------
// Props
// ---------------------------------------------------------------------------

interface AuditPanelProps {
  caseId: string;
}

// ---------------------------------------------------------------------------
// Component
// ---------------------------------------------------------------------------

export function AuditPanel({ caseId }: AuditPanelProps) {
  const token = getToken() ?? "";

  const { data, isLoading, isError, error } = useQuery<AuditEntry[]>({
    queryKey: queryKeys.audit.listForCase(caseId),
    queryFn: () => auditListForCase({ token, case_id: caseId }),
    enabled: !!token,
  });

  const verifyMutation = useMutation({
    mutationFn: () => auditVerifyChain({ token, case_id: caseId }),
    onSuccess: (intact) => {
      if (intact) {
        toastSuccess("Audit chain verified — all hashes intact and sequential.");
      } else {
        toastSuccess("Audit chain integrity failure — the hash chain has been tampered with or is broken.");
      }
    },
    onError: (err: unknown) => {
      toastError(err);
    },
  });

  if (isLoading) {
    return (
      <div className="space-y-2">
        {Array.from({ length: 4 }).map((_, i) => (
          <Skeleton key={i} className="h-20 w-full" />
        ))}
      </div>
    );
  }

  if (isError) {
    return (
      <Alert variant="destructive">
        <AlertCircle className="h-4 w-4" />
        <AlertDescription>
          {(error as Partial<{ message: string }>)?.message ?? "Failed to load audit trail."}
        </AlertDescription>
      </Alert>
    );
  }

  const entries = data ?? [];

  if (entries.length === 0) {
    return (
      <div className="rounded-lg border border-dashed p-8 text-center">
        <List className="h-8 w-8 mx-auto text-muted-foreground/50 mb-2" />
        <p className="text-sm font-medium">No audit entries recorded</p>
        <p className="text-xs text-muted-foreground mt-1">
          Audit entries are created automatically when case data is modified.
        </p>
      </div>
    );
  }

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between flex-wrap gap-2">
        <p className="text-xs text-muted-foreground">
          {entries.length} audit entr{entries.length === 1 ? "y" : "ies"} — hash-chained tamper-evident log
        </p>
        <Button
          size="sm"
          variant="outline"
          disabled={verifyMutation.isPending}
          onClick={() => verifyMutation.mutate()}
        >
          {verifyMutation.isPending ? (
            <FileCheck className="h-3.5 w-3.5 mr-1.5 animate-spin" />
          ) : (
            <ShieldCheck className="h-3.5 w-3.5 mr-1.5" />
          )}
          Verify Chain
        </Button>
      </div>

      <div className="space-y-2">
        {entries.map((entry) => (
          <AuditRow key={entry.entry_id} entry={entry} />
        ))}
      </div>
    </div>
  );
}

// ---------------------------------------------------------------------------
// AuditRow
// ---------------------------------------------------------------------------

function AuditRow({ entry }: { entry: AuditEntry }) {
  const [expanded, setExpanded] = useState(false);
  const Icon = activityIcon(entry.action);
  const label = activityLabel(entry.action);

  return (
    <div className="rounded-md border p-3 text-sm">
      <div className="flex items-start gap-3">
        <div className="mt-0.5 shrink-0">
          <Icon className="h-4 w-4 text-muted-foreground" />
        </div>
        <div className="flex-1 min-w-0 space-y-1">
          <div className="flex items-start justify-between gap-2 flex-wrap">
            <p className="font-medium">
              {label}
              <span className="text-muted-foreground font-normal">
                {" "}· {entry.actor}
              </span>
            </p>
            <div className="flex items-center gap-1 text-xs text-muted-foreground shrink-0">
              <Clock className="h-3 w-3" />
              <span>{fmtActivityTime(entry.timestamp)}</span>
            </div>
          </div>

          {entry.details && (
            <p className="text-xs text-muted-foreground">{entry.details}</p>
          )}

          <button
            type="button"
            onClick={() => setExpanded((v) => !v)}
            className="flex items-center gap-1 text-xs text-muted-foreground hover:text-foreground transition-colors mt-1"
          >
            {expanded ? (
              <>
                <ChevronUp className="h-3 w-3" />
                Hide hashes
              </>
            ) : (
              <>
                <ChevronDown className="h-3 w-3" />
                Show hashes
              </>
            )}
          </button>

          {expanded && (
            <div className="mt-2 space-y-1.5 rounded bg-muted p-2 font-mono text-[10px] leading-tight text-muted-foreground">
              <div className="flex gap-2">
                <span className="shrink-0 w-16 text-right">prev_hash</span>
                <span className="break-all">{entry.prev_hash}</span>
              </div>
              <div className="flex gap-2">
                <span className="shrink-0 w-16 text-right">entry_hash</span>
                <span className="break-all">{entry.entry_hash}</span>
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
