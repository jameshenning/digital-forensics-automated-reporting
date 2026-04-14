/**
 * EvidencePanel — the evidence sub-panel on the case detail page.
 *
 * - Header: "Evidence Items" title + "Add Evidence" button opening a Dialog.
 * - Body: list of evidence cards loaded via TanStack Query.
 * - Each card has an inline disclosure toggle showing the CustodyPanel
 *   for that evidence item (mirrors v1's nested table layout).
 * - Delete: AlertDialog with EvidenceHasDependents error handling.
 */

import React from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import {
  Plus,
  Trash2,
  AlertCircle,
  ChevronDown,
  ChevronRight,
  Shield,
  Hash,
  Paperclip,
  Sparkles,
  FlaskConical,
} from "lucide-react";

import {
  evidenceListForCase,
  evidenceAdd,
  evidenceDelete,
  aiEnhance,
  settingsGetAgentZero,
  type Evidence,
  type EvidenceInput,
  type AppError,
} from "@/lib/bindings";
import { getToken } from "@/lib/session";
import { queryKeys } from "@/lib/query";
import { toastError, toastSuccess } from "@/lib/error-toast";
import type { EvidenceFormValues } from "@/lib/evidence-schema";

import { Button } from "@/components/ui/button";
import { Skeleton } from "@/components/ui/skeleton";
import { Alert, AlertDescription } from "@/components/ui/alert";
import { Badge } from "@/components/ui/badge";
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import {
  AlertDialog,
  AlertDialogAction,
  AlertDialogCancel,
  AlertDialogContent,
  AlertDialogDescription,
  AlertDialogFooter,
  AlertDialogHeader,
  AlertDialogTitle,
  AlertDialogTrigger,
} from "@/components/ui/alert-dialog";
import { EvidenceForm } from "@/components/evidence-form";
import { CustodyPanel } from "@/components/custody-panel";
import { HashPanel } from "@/components/hash-panel";
import { EvidenceFilesPanel } from "@/components/evidence-files-panel";
import { ForensicAnalyzeDialog } from "@/components/forensic-analyze-dialog";

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

interface EvidencePanelProps {
  caseId: string;
  /** Called when the OneDrive warning dialog navigates to case edit. */
  onNavigateToCaseEdit?: () => void;
}

// ---------------------------------------------------------------------------
// Helper: format datetime
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

// ---------------------------------------------------------------------------
// Convert form values → EvidenceInput
// ---------------------------------------------------------------------------

function formValuesToInput(values: EvidenceFormValues): EvidenceInput {
  return {
    evidence_id: values.evidence_id,
    description: values.description,
    collected_by: values.collected_by,
    collection_datetime: values.collection_datetime,
    location: values.location || null,
    status: values.status || null,
    evidence_type: values.evidence_type || null,
    make_model: values.make_model || null,
    serial_number: values.serial_number || null,
    storage_location: values.storage_location || null,
  };
}

// ---------------------------------------------------------------------------
// EvidenceCard — individual evidence item with inline custody disclosure
// ---------------------------------------------------------------------------

interface EvidenceCardProps {
  evidence: Evidence;
  caseId: string;
  agentZeroConfigured: boolean;
  onDelete: (evidenceId: string) => void;
  isDeleting: boolean;
  hasDependentsError: boolean;
  onDialogClose: () => void;
  onNavigateToCaseEdit: () => void;
}

function EvidenceCard({
  evidence: ev,
  caseId,
  agentZeroConfigured,
  onDelete,
  isDeleting,
  hasDependentsError,
  onDialogClose,
  onNavigateToCaseEdit,
}: EvidenceCardProps) {
  const token = getToken() ?? "";
  const [custodyOpen, setCustodyOpen] = React.useState(false);
  const [hashOpen, setHashOpen] = React.useState(false);
  const [filesOpen, setFilesOpen] = React.useState(false);
  const [forensicOpen, setForensicOpen] = React.useState(false);

  // Polish description with AI
  const [description, setDescription] = React.useState(ev.description);
  const enhanceMutation = useMutation({
    mutationFn: () => aiEnhance({ token, text: description }),
    onSuccess: (newText) => {
      setDescription(newText);
      toastSuccess("Description polished by AI. Review and save if appropriate.");
    },
    onError: toastError,
  });

  const handleDeleteAttempt = () => {
    onDelete(ev.evidence_id);
  };

  // Reset error when dialog closes
  const handleDialogChange = (open: boolean) => {
    if (!open) onDialogClose();
  };

  return (
    <div className="rounded-md border bg-card p-3 space-y-2">
      {/* Card header */}
      <div className="flex items-start justify-between gap-2">
        <div className="flex-1 min-w-0">
          <div className="flex items-center gap-2 flex-wrap">
            <code className="text-sm font-mono font-medium">{ev.evidence_id}</code>
            {ev.evidence_type && (
              <Badge variant="secondary" className="text-xs">
                {ev.evidence_type}
              </Badge>
            )}
            <Badge
              variant="outline"
              className="text-xs"
            >
              {ev.status}
            </Badge>
          </div>
          <p className="text-sm text-muted-foreground mt-0.5">{description}</p>
          <p className="text-xs text-muted-foreground mt-0.5">
            Collected by {ev.collected_by} &middot; {fmtDatetime(ev.collection_datetime)}
            {ev.location && <span> &middot; {ev.location}</span>}
          </p>
          {(ev.make_model || ev.serial_number) && (
            <p className="text-xs text-muted-foreground font-mono">
              {ev.make_model}
              {ev.make_model && ev.serial_number && " / "}
              {ev.serial_number}
            </p>
          )}
        </div>

        {/* Actions */}
        <div className="flex gap-1 shrink-0">
          {/* AI: Polish description */}
          {agentZeroConfigured && (
            <Button
              size="sm"
              variant="ghost"
              className="h-7 px-1.5 text-xs"
              disabled={enhanceMutation.isPending || description.trim().length === 0}
              onClick={() => enhanceMutation.mutate()}
              title="Polish description with AI"
            >
              <Sparkles className="h-3.5 w-3.5" />
              <span className="sr-only">Polish description with AI</span>
            </Button>
          )}
          {/* AI: Forensic analysis */}
          {agentZeroConfigured && (
            <Button
              size="sm"
              variant="ghost"
              className="h-7 px-1.5 text-xs"
              onClick={() => setForensicOpen(true)}
              title="Run forensic analysis"
            >
              <FlaskConical className="h-3.5 w-3.5" />
              <span className="sr-only">Run forensic analysis</span>
            </Button>
          )}
          <AlertDialog onOpenChange={handleDialogChange}>
            <AlertDialogTrigger asChild>
              <Button
                size="sm"
                variant="ghost"
                className="h-7 w-7 p-0 text-destructive hover:text-destructive"
                aria-label="Delete evidence item"
                disabled={isDeleting}
              >
                <Trash2 className="h-3.5 w-3.5" />
              </Button>
            </AlertDialogTrigger>
            <AlertDialogContent>
              <AlertDialogHeader>
                <AlertDialogTitle>Delete evidence {ev.evidence_id}?</AlertDialogTitle>
                <AlertDialogDescription asChild>
                  <div className="space-y-2">
                    <p>
                      <strong>{ev.description}</strong> will be permanently removed.
                    </p>
                    {hasDependentsError && (
                      <div className="rounded-md border border-destructive/50 bg-destructive/10 p-3 text-sm text-destructive">
                        <strong>Cannot delete:</strong> this evidence item has custody events,
                        hashes, or tool records. Remove them first.
                      </div>
                    )}
                  </div>
                </AlertDialogDescription>
              </AlertDialogHeader>
              <AlertDialogFooter>
                <AlertDialogCancel>Cancel</AlertDialogCancel>
                {!hasDependentsError && (
                  <AlertDialogAction
                    onClick={handleDeleteAttempt}
                    className="bg-destructive text-destructive-foreground hover:bg-destructive/90"
                  >
                    Delete
                  </AlertDialogAction>
                )}
              </AlertDialogFooter>
            </AlertDialogContent>
          </AlertDialog>
        </div>
      </div>

      {/* Disclosure toggles */}
      <div className="flex gap-2 flex-wrap">
        <Button
          size="sm"
          variant="ghost"
          className="h-6 px-2 text-xs"
          onClick={() => {
            setCustodyOpen(!custodyOpen);
            if (hashOpen) setHashOpen(false);
          }}
        >
          {custodyOpen ? (
            <ChevronDown className="h-3 w-3 mr-1" />
          ) : (
            <ChevronRight className="h-3 w-3 mr-1" />
          )}
          <Shield className="h-3 w-3 mr-1" />
          Chain of Custody
        </Button>
        <Button
          size="sm"
          variant="ghost"
          className="h-6 px-2 text-xs"
          onClick={() => {
            setHashOpen(!hashOpen);
            if (custodyOpen) setCustodyOpen(false);
            if (filesOpen) setFilesOpen(false);
          }}
        >
          {hashOpen ? (
            <ChevronDown className="h-3 w-3 mr-1" />
          ) : (
            <ChevronRight className="h-3 w-3 mr-1" />
          )}
          <Hash className="h-3 w-3 mr-1" />
          Hashes
        </Button>
        <Button
          size="sm"
          variant="ghost"
          className="h-6 px-2 text-xs"
          onClick={() => {
            setFilesOpen(!filesOpen);
            if (custodyOpen) setCustodyOpen(false);
            if (hashOpen) setHashOpen(false);
          }}
        >
          {filesOpen ? (
            <ChevronDown className="h-3 w-3 mr-1" />
          ) : (
            <ChevronRight className="h-3 w-3 mr-1" />
          )}
          <Paperclip className="h-3 w-3 mr-1" />
          Files
        </Button>
      </div>

      {/* Inline custody disclosure */}
      {custodyOpen && (
        <div className="mt-1 pl-3 border-l-2 border-muted">
          <CustodyPanel
            scope={{ kind: "evidence", evidenceId: ev.evidence_id, caseId }}
          />
        </div>
      )}

      {/* Inline hash disclosure */}
      {hashOpen && (
        <div className="mt-1 pl-3 border-l-2 border-muted">
          <HashPanel
            scope={{ kind: "evidence", evidenceId: ev.evidence_id, caseId }}
          />
        </div>
      )}

      {/* Inline files disclosure (Phase 3b) */}
      {filesOpen && (
        <div className="mt-1 pl-3 border-l-2 border-muted">
          <EvidenceFilesPanel
            evidenceId={ev.evidence_id}
            caseId={caseId}
            onNavigateToCaseEdit={onNavigateToCaseEdit}
          />
        </div>
      )}

      {/* Forensic analysis dialog (Phase 5) */}
      <ForensicAnalyzeDialog
        evidenceId={ev.evidence_id}
        caseId={caseId}
        open={forensicOpen}
        onClose={() => setForensicOpen(false)}
      />
    </div>
  );
}

// ---------------------------------------------------------------------------
// EvidencePanel
// ---------------------------------------------------------------------------

export function EvidencePanel({ caseId, onNavigateToCaseEdit }: EvidencePanelProps) {
  const token = getToken() ?? "";
  const queryClient = useQueryClient();
  const [addOpen, setAddOpen] = React.useState(false);
  const [deletingId, setDeletingId] = React.useState<string | null>(null);
  // Track which evidence item hit the EvidenceHasDependents error for dialog display
  const [dependentsErrorId, setDependentsErrorId] = React.useState<string | null>(null);

  // Read Agent Zero configured state so cards can show/hide AI buttons
  const { data: azSettings } = useQuery({
    queryKey: queryKeys.agentZero.settings,
    queryFn: () => settingsGetAgentZero({ token }),
    enabled: !!token,
    refetchOnWindowFocus: false,
  });
  const agentZeroConfigured = azSettings?.is_configured ?? false;

  const { data, isLoading, isError, error } = useQuery<Evidence[]>({
    queryKey: queryKeys.evidence.listForCase(caseId),
    queryFn: () => evidenceListForCase({ token, case_id: caseId }),
    enabled: !!token,
  });

  const addMutation = useMutation({
    mutationFn: (values: EvidenceFormValues) =>
      evidenceAdd({ token, case_id: caseId, input: formValuesToInput(values) }),
    onSuccess: () => {
      void queryClient.invalidateQueries({
        queryKey: queryKeys.evidence.listForCase(caseId),
      });
      setAddOpen(false);
      toastSuccess("Evidence item added.");
    },
    onError: toastError,
  });

  const deleteMutation = useMutation({
    mutationFn: (evidenceId: string) => evidenceDelete({ token, evidence_id: evidenceId }),
    onSuccess: () => {
      void queryClient.invalidateQueries({
        queryKey: queryKeys.evidence.listForCase(caseId),
      });
      setDeletingId(null);
      toastSuccess("Evidence item deleted.");
    },
    onError: (err, evidenceId) => {
      setDeletingId(null);
      const appErr = err as Partial<AppError>;
      if (appErr?.code === "EvidenceHasDependents") {
        // Signal the specific card's AlertDialog to show the dependents error
        setDependentsErrorId(evidenceId);
      } else {
        toastError(err);
      }
    },
  });

  const handleDelete = (evidenceId: string) => {
    setDeletingId(evidenceId);
    deleteMutation.mutate(evidenceId);
  };

  if (isLoading) {
    return (
      <div className="space-y-3">
        {Array.from({ length: 2 }).map((_, i) => (
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
          {(error as Partial<{ message: string }>)?.message ?? "Failed to load evidence."}
        </AlertDescription>
      </Alert>
    );
  }

  const evidenceList = data ?? [];

  return (
    <div className="space-y-3">
      {/* Panel header */}
      <div className="flex items-center justify-between">
        <p className="text-sm text-muted-foreground">
          {evidenceList.length === 0
            ? "No evidence items recorded."
            : `${evidenceList.length} evidence item${evidenceList.length === 1 ? "" : "s"}`}
        </p>
        <Button size="sm" onClick={() => setAddOpen(true)}>
          <Plus className="h-4 w-4 mr-1" />
          Add Evidence
        </Button>
      </div>

      {/* Evidence cards */}
      {evidenceList.map((ev) => (
        <EvidenceCard
          key={ev.evidence_id}
          evidence={ev}
          caseId={caseId}
          agentZeroConfigured={agentZeroConfigured}
          onDelete={handleDelete}
          isDeleting={deletingId === ev.evidence_id}
          hasDependentsError={dependentsErrorId === ev.evidence_id}
          onDialogClose={() => setDependentsErrorId(null)}
          onNavigateToCaseEdit={onNavigateToCaseEdit ?? (() => {})}
        />
      ))}

      {/* Add Dialog */}
      <Dialog open={addOpen} onOpenChange={setAddOpen}>
        <DialogContent className="max-w-xl">
          <DialogHeader>
            <DialogTitle>Add Evidence Item</DialogTitle>
          </DialogHeader>
          <EvidenceForm
            isPending={addMutation.isPending}
            onSubmit={(values) => addMutation.mutate(values)}
            onCancel={() => setAddOpen(false)}
          />
        </DialogContent>
      </Dialog>
    </div>
  );
}
