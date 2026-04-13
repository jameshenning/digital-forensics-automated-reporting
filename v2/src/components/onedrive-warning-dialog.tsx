/**
 * OneDriveWarningDialog — SEC-3 MUST-DO 5.
 *
 * Shown when the Rust backend returns an OneDriveSyncWarning error during
 * evidence file upload.  The dialog is BLOCKING — it cannot be dismissed by
 * clicking outside or pressing Escape.  The investigator must choose one of
 * three explicit actions:
 *
 *   1. Configure a forensic drive  → closes the dialog, calls onConfigureDrive.
 *   2. I understand the risk       → calls settings_acknowledge_onedrive_risk,
 *                                    then calls onAcknowledge.
 *   3. Cancel upload               → calls onClose only.
 *
 * Uses Dialog (not AlertDialog) so that onInteractOutside is available to
 * prevent accidental overlay-click dismissal.
 */

import { useMutation } from "@tanstack/react-query";
import { AlertTriangle } from "lucide-react";

import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
  DialogFooter,
} from "@/components/ui/dialog";
import { Button } from "@/components/ui/button";
import { settingsAcknowledgeOneDriveRisk } from "@/lib/bindings";
import { getToken } from "@/lib/session";
import { toastError } from "@/lib/error-toast";

// ---------------------------------------------------------------------------
// Props
// ---------------------------------------------------------------------------

export interface OneDriveWarningDialogProps {
  open: boolean;
  /** Called when the dialog should close regardless of outcome. */
  onClose: () => void;
  /**
   * Called after the investigator clicks "I understand the risk".
   * The parent is responsible for retrying the upload if desired.
   */
  onAcknowledge: () => void;
  /**
   * Called when the investigator clicks "Configure a forensic drive".
   * The parent should navigate to the case edit page.
   */
  onConfigureDrive: () => void;
}

// ---------------------------------------------------------------------------
// Component
// ---------------------------------------------------------------------------

export function OneDriveWarningDialog({
  open,
  onClose,
  onAcknowledge,
  onConfigureDrive,
}: OneDriveWarningDialogProps) {
  const token = getToken() ?? "";

  const acknowledgeMutation = useMutation({
    mutationFn: () => settingsAcknowledgeOneDriveRisk({ token }),
    onSuccess: () => {
      onAcknowledge();
      onClose();
    },
    onError: (err) => {
      toastError(err);
      // Even if the acknowledgement write fails, let the investigator proceed
      // so they aren't permanently blocked.
      onAcknowledge();
      onClose();
    },
  });

  // Prevent accidental dismiss — overlay click and Escape are blocked.
  // Only the three explicit buttons may close this dialog (SEC-3 MUST-DO 5).
  function handleOpenChange(nextOpen: boolean) {
    if (!nextOpen) return; // suppress all close-triggered-by-overlay/Escape
  }

  return (
    <Dialog open={open} onOpenChange={handleOpenChange}>
      <DialogContent
        className="max-w-lg border-2 border-amber-500"
        onInteractOutside={(e: Event) => e.preventDefault()}
        onEscapeKeyDown={(e: KeyboardEvent) => e.preventDefault()}
      >
        <DialogHeader>
          <DialogTitle className="flex items-center gap-2 text-amber-600 dark:text-amber-400">
            <AlertTriangle className="h-5 w-5 shrink-0" aria-hidden="true" />
            Evidence storage is on a cloud-synced folder.
          </DialogTitle>
        </DialogHeader>

        <div className="space-y-3 text-sm text-foreground">
          <p>
            The evidence files storage directory{" "}
            <code className="rounded bg-muted px-1 py-0.5 font-mono text-xs">
              %APPDATA%\DFARS\evidence_files\
            </code>{" "}
            is covered by <strong>Microsoft OneDrive sync</strong>. Any
            evidence files you upload will be silently replicated to
            Microsoft&apos;s cloud servers.
          </p>
          <p>This may:</p>
          <ul className="list-disc pl-5 space-y-1">
            <li>
              Compromise <strong>chain-of-custody integrity</strong> — an
              opposing party could argue that evidence was accessible to
              Microsoft and potentially tampered with.
            </li>
            <li>
              Violate <strong>privacy obligations</strong> for case data
              containing PII, PHI, or law-enforcement-sensitive material.
            </li>
            <li>
              Trigger <strong>GDPR Article 46</strong> cross-border transfer
              obligations if any data subject is in the EU.
            </li>
          </ul>
          <p className="font-medium">
            Recommended action: configure a forensic drive (an external USB
            drive or a local non-synced directory) as the evidence storage
            path for this case.
          </p>
        </div>

        <DialogFooter className="flex-col sm:flex-row gap-2">
          {/* Primary — configure drive */}
          <Button
            className="bg-primary"
            onClick={() => {
              onConfigureDrive();
              onClose();
            }}
          >
            Configure a forensic drive
          </Button>

          {/* Acknowledge risk */}
          <Button
            variant="outline"
            className="border-amber-500 text-amber-700 hover:bg-amber-50 dark:text-amber-400 dark:hover:bg-amber-950"
            disabled={acknowledgeMutation.isPending}
            onClick={() => acknowledgeMutation.mutate()}
          >
            {acknowledgeMutation.isPending
              ? "Saving…"
              : "I understand the risk and proceed anyway"}
          </Button>

          {/* Cancel */}
          <Button variant="ghost" onClick={onClose}>
            Cancel upload
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}
