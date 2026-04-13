/**
 * EvidenceFilesPanel — SEC-3 compliant file upload/download sub-panel.
 *
 * Mounts inside an expanded evidence card.  Shows the list of uploaded
 * artifact files for a single evidence item, with upload, download,
 * soft-delete, and purge actions.
 *
 * SEC-3 requirements implemented here:
 *   MUST-DO 4 — hash_verified=false triggers a modal INTEGRITY FAILURE dialog.
 *   MUST-DO 5 — OneDriveSyncWarning triggers the blocking OneDriveWarningDialog.
 *   SHOULD-DO 2 — is_executable=true triggers an executable confirmation dialog.
 */

import React from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { open as openFilePicker } from "@tauri-apps/plugin-dialog";
import { openPath } from "@tauri-apps/plugin-opener";
import { useForm } from "react-hook-form";
import { zodResolver } from "@hookform/resolvers/zod";
import {
  Upload,
  Download,
  Trash2,
  ShieldCheck,
  ShieldAlert,
  ShieldQuestion,
  AlertCircle,
  Copy,
  Check,
  Loader2,
} from "lucide-react";

import {
  evidenceFilesUpload,
  evidenceFilesList,
  evidenceFilesDownload,
  evidenceFilesSoftDelete,
  evidenceFilesPurge,
  type EvidenceFile,
  type EvidenceFileDownload,
  type AppError,
} from "@/lib/bindings";
import { getToken } from "@/lib/session";
import { queryKeys } from "@/lib/query";
import { toastError, toastSuccess } from "@/lib/error-toast";
import { formatBytes } from "@/lib/format-bytes";
import { purgeSchema, type PurgeFormValues } from "@/lib/purge-schema";
import { OneDriveWarningDialog } from "@/components/onedrive-warning-dialog";

import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Skeleton } from "@/components/ui/skeleton";
import { Alert, AlertDescription } from "@/components/ui/alert";
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
  DialogFooter,
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
import {
  Form,
  FormControl,
  FormField,
  FormItem,
  FormLabel,
  FormMessage,
} from "@/components/ui/form";
import { Textarea } from "@/components/ui/textarea";

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

interface EvidenceFilesPanelProps {
  evidenceId: string;
  /** Needed for navigate-to-case-edit in the OneDrive warning dialog. */
  caseId: string;
  /** Called when the user chooses "Configure a forensic drive" in the OneDrive
   * warning.  The parent should navigate to the case edit page. */
  onNavigateToCaseEdit: () => void;
}

/** Per-row integrity status tracked after a download this session. */
type IntegrityStatus = "verified" | "tampered" | "unchecked";

// ---------------------------------------------------------------------------
// IntegrityBadge
// ---------------------------------------------------------------------------

function IntegrityBadge({ status }: { status: IntegrityStatus }) {
  if (status === "verified") {
    return (
      <span
        className="inline-flex items-center gap-1 text-xs text-emerald-700 dark:text-emerald-400"
        title="SHA-256 verified on last download"
      >
        <ShieldCheck className="h-3.5 w-3.5" aria-hidden="true" />
        verified
      </span>
    );
  }
  if (status === "tampered") {
    return (
      <span
        className="inline-flex items-center gap-1 text-xs font-bold text-destructive"
        title="INTEGRITY FAILURE: hash mismatch on last download"
      >
        <ShieldAlert className="h-3.5 w-3.5" aria-hidden="true" />
        TAMPERED
      </span>
    );
  }
  return (
    <span
      className="inline-flex items-center gap-1 text-xs text-muted-foreground"
      title="Not verified this session"
    >
      <ShieldQuestion className="h-3.5 w-3.5" aria-hidden="true" />
      not verified
    </span>
  );
}

// ---------------------------------------------------------------------------
// SHA copy button
// ---------------------------------------------------------------------------

function Sha256Cell({ hash }: { hash: string }) {
  const [copied, setCopied] = React.useState(false);
  const preview = hash.slice(0, 12);

  function handleCopy() {
    void navigator.clipboard.writeText(hash).then(() => {
      setCopied(true);
      setTimeout(() => setCopied(false), 1500);
    });
  }

  return (
    <button
      type="button"
      onClick={handleCopy}
      className="inline-flex items-center gap-1 font-mono text-xs text-muted-foreground hover:text-foreground transition-colors"
      title={`Click to copy full SHA-256: ${hash}`}
      aria-label={`Copy SHA-256 hash starting with ${preview}`}
    >
      {preview}&hellip;
      {copied ? (
        <Check className="h-3 w-3 text-emerald-600" aria-hidden="true" />
      ) : (
        <Copy className="h-3 w-3" aria-hidden="true" />
      )}
    </button>
  );
}

// ---------------------------------------------------------------------------
// IntegrityFailureDialog  (SEC-3 MUST-DO 4 — must be impossible to miss)
// ---------------------------------------------------------------------------

interface IntegrityFailureDialogProps {
  open: boolean;
  onClose: () => void;
  /** Called when investigator chooses to open the file anyway. */
  onOpenAnyway: () => void;
  filename: string;
}

function IntegrityFailureDialog({
  open,
  onClose,
  onOpenAnyway,
  filename,
}: IntegrityFailureDialogProps) {
  function handleOpenChange(nextOpen: boolean) {
    // Prevent closing via overlay/Escape — investigator must make an explicit choice.
    if (!nextOpen) return;
  }

  return (
    <Dialog open={open} onOpenChange={handleOpenChange}>
      <DialogContent
        className="max-w-lg border-4 border-destructive bg-destructive/5"
        onInteractOutside={(e: Event) => e.preventDefault()}
        onEscapeKeyDown={(e: KeyboardEvent) => e.preventDefault()}
      >
        <DialogHeader>
          <DialogTitle className="flex items-center gap-3 text-destructive text-xl">
            <ShieldAlert className="h-7 w-7 shrink-0" aria-hidden="true" />
            INTEGRITY FAILURE
          </DialogTitle>
        </DialogHeader>

        <div className="space-y-3 text-sm">
          <div className="rounded-md border-2 border-destructive bg-destructive/10 p-4">
            <p className="font-bold text-destructive">
              This file does not match its original SHA-256 hash.
            </p>
          </div>

          <p>
            The file{" "}
            <code className="rounded bg-muted px-1 py-0.5 font-mono text-xs">
              {filename}
            </code>{" "}
            has been modified since it was uploaded. The stored SHA-256 digest
            no longer matches the bytes on disk.
          </p>
          <p>
            <strong>Chain-of-custody integrity is compromised.</strong> An
            integrity failure of this kind is typically caused by:
          </p>
          <ul className="list-disc pl-5 space-y-1 text-muted-foreground">
            <li>Deliberate tampering by a local attacker with filesystem access.</li>
            <li>Silent corruption by antivirus software, OneDrive sync, or disk failure.</li>
            <li>A software defect in a prior version of this application.</li>
          </ul>
          <p className="font-medium">
            Do not rely on this file as evidence until a source reacquisition
            is performed and the hash of the reacquired file is verified.
          </p>
          <p className="text-muted-foreground text-xs">
            This failure has been recorded in the audit log at ERROR severity.
          </p>
        </div>

        <DialogFooter className="flex gap-2 sm:justify-between">
          <Button
            variant="outline"
            onClick={onClose}
          >
            Do not open
          </Button>
          {/* "Open anyway" deliberately uses the secondary/outline style and
              is NOT auto-focused — the investigator must consciously click it. */}
          <Button
            variant="destructive"
            onClick={() => {
              onOpenAnyway();
              onClose();
            }}
            tabIndex={-1}
          >
            Open anyway (evidence may be unreliable)
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}

// ---------------------------------------------------------------------------
// ExecutableConfirmDialog  (SEC-3 SHOULD-DO 2)
// ---------------------------------------------------------------------------

interface ExecutableConfirmDialogProps {
  open: boolean;
  onClose: () => void;
  onConfirm: () => void;
  filename: string;
  mimeType: string | null;
}

function ExecutableConfirmDialog({
  open,
  onClose,
  onConfirm,
  filename,
  mimeType,
}: ExecutableConfirmDialogProps) {
  // Derive the reason label from the MIME type for transparency.
  function executableReason(): string {
    if (!mimeType) return "executable binary magic bytes";
    if (mimeType.includes("msdownload") || mimeType.includes("dosexec"))
      return "Windows executable (.exe, .dll, .com)";
    if (mimeType.includes("x-elf")) return "ELF binary (Linux/Unix executable)";
    if (mimeType.includes("x-executable")) return "executable binary";
    if (mimeType.includes("x-mach")) return "Mach-O binary (macOS executable)";
    if (mimeType.includes("x-sh") || mimeType.includes("x-python") || mimeType.includes("x-perl"))
      return "script file with executable shebang";
    return "executable binary (byte-sniffed)";
  }

  return (
    <Dialog
      open={open}
      onOpenChange={(o: boolean) => { if (!o) onClose(); }}
    >
      <DialogContent
        onInteractOutside={(e: Event) => e.preventDefault()}
        onEscapeKeyDown={(e: KeyboardEvent) => e.preventDefault()}
      >
        <DialogHeader>
          <DialogTitle className="text-amber-700 dark:text-amber-400">
            This file is an executable
          </DialogTitle>
        </DialogHeader>
        <div className="space-y-2 text-sm text-foreground">
          <p>
            <code className="rounded bg-muted px-1 py-0.5 font-mono text-xs">
              {filename}
            </code>{" "}
            has been identified as a{" "}
            <strong>{executableReason()}</strong>.
          </p>
          <p>
            Opening it will cause your operating system to execute the code
            it contains. On a forensics workstation, this may compromise
            the integrity of other evidence and the workstation itself.
          </p>
          <p className="text-muted-foreground">
            If you intended to inspect this file, open it in a hex editor
            or isolated environment rather than with the OS default handler.
          </p>
        </div>
        <DialogFooter>
          <Button variant="outline" onClick={onClose}>
            Cancel
          </Button>
          <Button
            className="bg-amber-600 text-white hover:bg-amber-700"
            onClick={() => {
              onConfirm();
              onClose();
            }}
          >
            Open executable anyway
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}

// ---------------------------------------------------------------------------
// PurgeDialog
// ---------------------------------------------------------------------------

interface PurgeDialogProps {
  open: boolean;
  onClose: () => void;
  onConfirm: (justification: string) => void;
  filename: string;
  isPending: boolean;
}

function PurgeDialog({
  open,
  onClose,
  onConfirm,
  filename,
  isPending,
}: PurgeDialogProps) {
  const form = useForm<PurgeFormValues>({
    resolver: zodResolver(purgeSchema),
    defaultValues: { justification: "" },
  });

  function handleSubmit(values: PurgeFormValues) {
    onConfirm(values.justification);
  }

  // Reset form when dialog opens
  React.useEffect(() => {
    if (open) form.reset({ justification: "" });
  }, [open, form]);

  return (
    <Dialog open={open} onOpenChange={(o) => { if (!o) onClose(); }}>
      <DialogContent className="max-w-md">
        <DialogHeader>
          <DialogTitle className="text-destructive">
            Permanently purge file?
          </DialogTitle>
        </DialogHeader>
        <div className="space-y-3 text-sm">
          <p>
            <strong>Purge is permanent and irreversible.</strong> The disk file
            and its database record for{" "}
            <code className="rounded bg-muted px-1 py-0.5 font-mono text-xs">
              {filename}
            </code>{" "}
            will be deleted. The SHA-256 hash will be written to the audit log
            for chain-of-custody continuity.
          </p>
          <Form {...form}>
            <form
              onSubmit={form.handleSubmit(handleSubmit)}
              className="space-y-3"
              noValidate
            >
              <FormField
                control={form.control}
                name="justification"
                render={({ field }) => (
                  <FormItem>
                    <FormLabel>
                      Justification <span aria-hidden="true">*</span>
                    </FormLabel>
                    <FormControl>
                      <Textarea
                        placeholder="Explain why this file is being permanently purged (min. 10 characters)…"
                        rows={3}
                        {...field}
                      />
                    </FormControl>
                    <FormMessage />
                  </FormItem>
                )}
              />
              <DialogFooter>
                <Button
                  type="button"
                  variant="outline"
                  onClick={onClose}
                  disabled={isPending}
                >
                  Cancel
                </Button>
                <Button
                  type="submit"
                  variant="destructive"
                  disabled={isPending}
                >
                  {isPending ? (
                    <>
                      <Loader2 className="h-4 w-4 mr-2 animate-spin" aria-hidden="true" />
                      Purging…
                    </>
                  ) : (
                    "Purge permanently"
                  )}
                </Button>
              </DialogFooter>
            </form>
          </Form>
        </div>
      </DialogContent>
    </Dialog>
  );
}

// ---------------------------------------------------------------------------
// File row
// ---------------------------------------------------------------------------

interface FileRowProps {
  file: EvidenceFile;
  integrityStatus: IntegrityStatus;
  onDownload: (file: EvidenceFile) => void;
  onSoftDelete: (fileId: number) => void;
  onPurge: (file: EvidenceFile) => void;
  isDownloading: boolean;
  isSoftDeleting: boolean;
}

function FileRow({
  file,
  integrityStatus,
  onDownload,
  onSoftDelete,
  onPurge,
  isDownloading,
  isSoftDeleting,
}: FileRowProps) {
  const uploadedDate = React.useMemo(() => {
    const d = new Date(file.uploaded_at.replace(" ", "T"));
    if (isNaN(d.getTime())) return file.uploaded_at;
    return d.toLocaleString(undefined, {
      year: "numeric",
      month: "short",
      day: "numeric",
      hour: "2-digit",
      minute: "2-digit",
    });
  }, [file.uploaded_at]);

  return (
    <div className="flex items-start gap-3 rounded-md border bg-muted/30 p-2.5 text-sm">
      {/* File info */}
      <div className="flex-1 min-w-0 space-y-0.5">
        <div className="flex items-center gap-2 flex-wrap">
          <code className="font-mono text-xs font-medium break-all">
            {file.original_filename}
          </code>
          {file.mime_type && (
            <Badge variant="secondary" className="text-xs shrink-0">
              {file.mime_type}
            </Badge>
          )}
        </div>
        <div className="flex items-center gap-3 text-xs text-muted-foreground flex-wrap">
          <span>{formatBytes(file.size_bytes)}</span>
          <Sha256Cell hash={file.sha256} />
          <span>{uploadedDate}</span>
          <IntegrityBadge status={integrityStatus} />
        </div>
      </div>

      {/* Actions */}
      <div className="flex gap-1 shrink-0">
        {/* Download */}
        <Button
          size="sm"
          variant="ghost"
          className="h-7 px-2"
          aria-label={`Download ${file.original_filename}`}
          disabled={isDownloading}
          onClick={() => onDownload(file)}
          title="Download and verify integrity"
        >
          {isDownloading ? (
            <Loader2 className="h-3.5 w-3.5 animate-spin" aria-hidden="true" />
          ) : (
            <Download className="h-3.5 w-3.5" aria-hidden="true" />
          )}
        </Button>

        {/* Soft delete */}
        <AlertDialog>
          <AlertDialogTrigger asChild>
            <Button
              size="sm"
              variant="ghost"
              className="h-7 px-2 text-muted-foreground hover:text-destructive"
              aria-label={`Soft-delete ${file.original_filename}`}
              disabled={isSoftDeleting}
              title="Soft-delete (disk file is retained)"
            >
              <Trash2 className="h-3.5 w-3.5" aria-hidden="true" />
            </Button>
          </AlertDialogTrigger>
          <AlertDialogContent>
            <AlertDialogHeader>
              <AlertDialogTitle>
                Soft-delete {file.original_filename}?
              </AlertDialogTitle>
              <AlertDialogDescription>
                The file record will be hidden from the list. The disk file is{" "}
                <strong>not</strong> removed (use Purge for permanent deletion).
              </AlertDialogDescription>
            </AlertDialogHeader>
            <AlertDialogFooter>
              <AlertDialogCancel>Cancel</AlertDialogCancel>
              <AlertDialogAction
                onClick={() => onSoftDelete(file.file_id)}
                className="bg-destructive text-destructive-foreground hover:bg-destructive/90"
              >
                Soft-delete
              </AlertDialogAction>
            </AlertDialogFooter>
          </AlertDialogContent>
        </AlertDialog>

        {/* Purge */}
        <Button
          size="sm"
          variant="ghost"
          className="h-7 px-2 text-xs text-muted-foreground hover:text-destructive"
          aria-label={`Permanently purge ${file.original_filename}`}
          onClick={() => onPurge(file)}
          title="Permanently purge (requires justification)"
        >
          Purge
        </Button>
      </div>
    </div>
  );
}

// ---------------------------------------------------------------------------
// EvidenceFilesPanel
// ---------------------------------------------------------------------------

export function EvidenceFilesPanel({
  evidenceId,
  caseId: _caseId,
  onNavigateToCaseEdit,
}: EvidenceFilesPanelProps) {
  const token = getToken() ?? "";
  const queryClient = useQueryClient();

  // Per-file integrity status map (keyed by file_id), reset on component unmount.
  const [integrityMap, setIntegrityMap] = React.useState<
    Map<number, IntegrityStatus>
  >(new Map());

  // Upload state
  const [isUploading, setIsUploading] = React.useState(false);

  // OneDrive warning dialog state
  const [oneDriveOpen, setOneDriveOpen] = React.useState(false);

  // Integrity failure dialog state
  const [integrityDialog, setIntegrityDialog] = React.useState<{
    open: boolean;
    filename: string;
    resolvedPath: string;
  }>({ open: false, filename: "", resolvedPath: "" });

  // Executable confirm dialog state
  const [execDialog, setExecDialog] = React.useState<{
    open: boolean;
    filename: string;
    mimeType: string | null;
    resolvedPath: string;
  }>({ open: false, filename: "", mimeType: null, resolvedPath: "" });

  // Purge dialog state
  const [purgeTarget, setPurgeTarget] = React.useState<EvidenceFile | null>(null);

  // Download in-progress per file_id
  const [downloadingId, setDownloadingId] = React.useState<number | null>(null);

  // Soft-delete in-progress per file_id
  const [softDeletingId, setSoftDeletingId] = React.useState<number | null>(null);

  // ---------------------------------------------------------------------------
  // Queries
  // ---------------------------------------------------------------------------

  const { data, isLoading, isError, error } = useQuery<EvidenceFile[]>({
    queryKey: queryKeys.evidenceFiles.listForEvidence(evidenceId),
    queryFn: () => evidenceFilesList({ token, evidence_id: evidenceId }),
    enabled: !!token,
  });

  // ---------------------------------------------------------------------------
  // Mutations
  // ---------------------------------------------------------------------------

  const softDeleteMutation = useMutation({
    mutationFn: (fileId: number) =>
      evidenceFilesSoftDelete({ token, file_id: fileId }),
    onSuccess: (_data, fileId) => {
      setSoftDeletingId(null);
      setIntegrityMap((m) => {
        const next = new Map(m);
        next.delete(fileId);
        return next;
      });
      void queryClient.invalidateQueries({
        queryKey: queryKeys.evidenceFiles.listForEvidence(evidenceId),
      });
      toastSuccess("File removed from evidence list.");
    },
    onError: (err) => {
      setSoftDeletingId(null);
      toastError(err);
    },
  });

  const purgeMutation = useMutation({
    mutationFn: ({ fileId, justification }: { fileId: number; justification: string }) =>
      evidenceFilesPurge({ token, file_id: fileId, justification }),
    onSuccess: (_data, { fileId }) => {
      setIntegrityMap((m) => {
        const next = new Map(m);
        next.delete(fileId);
        return next;
      });
      setPurgeTarget(null);
      void queryClient.invalidateQueries({
        queryKey: queryKeys.evidenceFiles.listForEvidence(evidenceId),
      });
      toastSuccess("File permanently purged and removed from audit chain.");
    },
    onError: (err) => {
      setPurgeTarget(null);
      toastError(err);
    },
  });

  // ---------------------------------------------------------------------------
  // Upload handler
  // ---------------------------------------------------------------------------

  async function handleUploadClick() {
    let selectedPath: string | null = null;
    try {
      const result = await openFilePicker({ multiple: false, directory: false });
      if (result === null) return; // user cancelled
      selectedPath = result as string;
    } catch {
      toastError({ code: "Io", message: "Could not open the file picker." });
      return;
    }

    setIsUploading(true);
    try {
      const uploaded = await evidenceFilesUpload({
        token,
        evidence_id: evidenceId,
        source_path: selectedPath,
      });

      void queryClient.invalidateQueries({
        queryKey: queryKeys.evidenceFiles.listForEvidence(evidenceId),
      });

      // Soft-warn on files larger than 2 GiB
      const twoGib = 2 * 1024 * 1024 * 1024;
      if (uploaded.size_bytes > twoGib) {
        toastSuccess(
          `File uploaded (${formatBytes(uploaded.size_bytes)}). ` +
          "Large file — verify sufficient disk space before continuing.",
        );
      } else {
        toastSuccess("File uploaded and hash recorded.");
      }
    } catch (err) {
      const appErr = err as Partial<AppError>;
      if (appErr?.code === "OneDriveSyncWarning") {
        setOneDriveOpen(true);
        // Do NOT retry automatically (per spec).
      } else {
        toastError(err);
      }
    } finally {
      setIsUploading(false);
    }
  }

  // ---------------------------------------------------------------------------
  // Download handler
  // ---------------------------------------------------------------------------

  async function handleDownload(file: EvidenceFile) {
    setDownloadingId(file.file_id);
    let result: EvidenceFileDownload;
    try {
      result = await evidenceFilesDownload({ token, file_id: file.file_id });
    } catch (err) {
      setDownloadingId(null);
      toastError(err);
      return;
    }
    setDownloadingId(null);

    // Update integrity status for this file
    const status: IntegrityStatus = result.hash_verified ? "verified" : "tampered";
    setIntegrityMap((m) => new Map(m).set(file.file_id, status));

    if (!result.hash_verified) {
      // SEC-3 MUST-DO 4 — show the blocking integrity failure dialog
      setIntegrityDialog({
        open: true,
        filename: file.original_filename,
        resolvedPath: result.path,
      });
      return;
    }

    if (result.is_executable) {
      // SEC-3 SHOULD-DO 2 — show executable confirmation
      setExecDialog({
        open: true,
        filename: file.original_filename,
        mimeType: file.mime_type,
        resolvedPath: result.path,
      });
      return;
    }

    // Clean: open with OS default handler
    void openPath(result.path);
  }

  // ---------------------------------------------------------------------------
  // OneDrive guard helpers
  // ---------------------------------------------------------------------------

  function handleOneDriveAcknowledge() {
    // After acknowledge, the Rust side has flipped the flag. The user can now
    // manually click Upload again. We do not auto-retry.
    void queryClient.invalidateQueries({
      queryKey: queryKeys.evidenceFiles.listForEvidence(evidenceId),
    });
  }

  // ---------------------------------------------------------------------------
  // Render states
  // ---------------------------------------------------------------------------

  if (isLoading) {
    return (
      <div className="space-y-2">
        <Skeleton className="h-9 w-full" />
        <Skeleton className="h-9 w-full" />
      </div>
    );
  }

  if (isError) {
    return (
      <Alert variant="destructive">
        <AlertCircle className="h-4 w-4" />
        <AlertDescription>
          {(error as Partial<{ message: string }>)?.message ??
            "Failed to load files."}
        </AlertDescription>
      </Alert>
    );
  }

  const files = data ?? [];

  return (
    <div className="space-y-2">
      {/* Header */}
      <div className="flex items-center justify-between gap-2">
        <p className="text-xs font-medium text-muted-foreground uppercase tracking-wide">
          Files
          {files.length > 0 && ` (${files.length})`}
        </p>
        <Button
          size="sm"
          variant="outline"
          className="h-7 px-2 text-xs"
          onClick={() => void handleUploadClick()}
          disabled={isUploading}
          aria-label="Upload a file to this evidence item"
        >
          {isUploading ? (
            <>
              <Loader2 className="h-3 w-3 mr-1 animate-spin" aria-hidden="true" />
              Uploading…
            </>
          ) : (
            <>
              <Upload className="h-3 w-3 mr-1" aria-hidden="true" />
              Upload
            </>
          )}
        </Button>
      </div>

      {/* Empty state */}
      {files.length === 0 && (
        <p className="text-xs text-muted-foreground py-2">
          No files yet. Upload your first artifact.
        </p>
      )}

      {/* File list */}
      {files.map((file) => (
        <FileRow
          key={file.file_id}
          file={file}
          integrityStatus={integrityMap.get(file.file_id) ?? "unchecked"}
          onDownload={handleDownload}
          onSoftDelete={(fileId) => {
            setSoftDeletingId(fileId);
            softDeleteMutation.mutate(fileId);
          }}
          onPurge={(f) => setPurgeTarget(f)}
          isDownloading={downloadingId === file.file_id}
          isSoftDeleting={softDeletingId === file.file_id}
        />
      ))}

      {/* OneDrive blocking warning dialog (SEC-3 MUST-DO 5) */}
      <OneDriveWarningDialog
        open={oneDriveOpen}
        onClose={() => setOneDriveOpen(false)}
        onAcknowledge={handleOneDriveAcknowledge}
        onConfigureDrive={() => {
          setOneDriveOpen(false);
          onNavigateToCaseEdit();
        }}
      />

      {/* Integrity failure dialog (SEC-3 MUST-DO 4) */}
      <IntegrityFailureDialog
        open={integrityDialog.open}
        onClose={() => setIntegrityDialog((d) => ({ ...d, open: false }))}
        onOpenAnyway={() => {
          void openPath(integrityDialog.resolvedPath);
        }}
        filename={integrityDialog.filename}
      />

      {/* Executable confirm dialog (SEC-3 SHOULD-DO 2) */}
      <ExecutableConfirmDialog
        open={execDialog.open}
        onClose={() => setExecDialog((d) => ({ ...d, open: false }))}
        onConfirm={() => {
          void openPath(execDialog.resolvedPath);
        }}
        filename={execDialog.filename}
        mimeType={execDialog.mimeType}
      />

      {/* Purge dialog */}
      {purgeTarget && (
        <PurgeDialog
          open={!!purgeTarget}
          onClose={() => setPurgeTarget(null)}
          onConfirm={(justification) =>
            purgeMutation.mutate({
              fileId: purgeTarget.file_id,
              justification,
            })
          }
          filename={purgeTarget.original_filename}
          isPending={purgeMutation.isPending}
        />
      )}
    </div>
  );
}
