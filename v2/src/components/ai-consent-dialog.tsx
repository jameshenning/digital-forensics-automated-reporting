/**
 * AiConsentDialog — SEC-4 §2.7 / SHOULD-DO 4 one-time consent gate.
 *
 * Shown exactly once per install before the first ai_summarize_case call.
 * The backend raises AiSummarizeConsentRequired on first call; the parent
 * catches it, shows this dialog, and retries after acknowledgement.
 *
 * BLOCKING: Escape and outside-click dismissal are suppressed (same pattern
 * as OneDriveWarningDialog).  Buttons are the only exit.
 *
 * After the user clicks "Acknowledge and continue":
 *   1. Calls settings_acknowledge_ai_consent (sets the backend flag).
 *   2. Calls onAcknowledge so the parent can retry ai_summarize_case.
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
import { settingsAcknowledgeAiConsent } from "@/lib/bindings";
import { getToken } from "@/lib/session";
import { toastError } from "@/lib/error-toast";

// ---------------------------------------------------------------------------
// Props
// ---------------------------------------------------------------------------

export interface AiConsentDialogProps {
  open: boolean;
  /** The Agent Zero URL currently configured — shown verbatim in the body. */
  agentZeroUrl: string;
  /** Called after acknowledgement is recorded. Parent should retry the summary. */
  onAcknowledge: () => void;
  /** Called when the user clicks Cancel. */
  onClose: () => void;
}

// ---------------------------------------------------------------------------
// Component
// ---------------------------------------------------------------------------

export function AiConsentDialog({
  open,
  agentZeroUrl,
  onAcknowledge,
  onClose,
}: AiConsentDialogProps) {
  const acknowledgeMutation = useMutation({
    mutationFn: () => {
      const token = getToken();
      if (!token) throw new Error("No session token");
      return settingsAcknowledgeAiConsent({ token });
    },
    onSuccess: () => {
      onAcknowledge();
    },
    onError: toastError,
  });

  return (
    <Dialog
      open={open}
      onOpenChange={(isOpen) => {
        // Only allow closing via the buttons — suppress overlay-click / Escape.
        if (!isOpen) return;
      }}
    >
      <DialogContent
        className="max-w-xl"
        // Suppress close-on-outside-click
        onInteractOutside={(e) => e.preventDefault()}
        // Suppress close-on-Escape
        onEscapeKeyDown={(e) => e.preventDefault()}
      >
        <DialogHeader>
          <div className="flex items-center gap-2">
            <AlertTriangle className="h-5 w-5 text-amber-500 shrink-0" />
            <DialogTitle>Send full case to Agent Zero?</DialogTitle>
          </div>
        </DialogHeader>

        <div className="text-sm space-y-3 text-muted-foreground">
          <p>
            The <strong className="text-foreground">Summarize Case</strong>{" "}
            feature sends the <strong className="text-foreground">entire case payload</strong>{" "}
            to your Agent Zero instance so it can produce an executive summary.
            This includes:
          </p>

          <ul className="list-disc pl-5 space-y-1">
            <li>Case header (name, investigator, agency, classification)</li>
            <li>All tags</li>
            <li>All evidence items (description, collector, type, serial numbers)</li>
            <li>Full chain of custody</li>
            <li>All hash verifications</li>
            <li>All tool usage records</li>
            <li>All analysis notes</li>
            <li>Any PII that appears in the above fields</li>
          </ul>

          <p>
            Your Agent Zero is configured to run at{" "}
            <code className="text-foreground font-mono text-xs bg-muted px-1 py-0.5 rounded">
              {agentZeroUrl}
            </code>
            . DFARS has verified this URL is loopback or a local Docker container;
            it will not leave this machine. However, if your Agent Zero has its own
            plugins that forward data externally, those will also see this payload.
          </p>

          <p>
            Click{" "}
            <strong className="text-foreground">Acknowledge and continue</strong>{" "}
            only if you understand what will be sent.
          </p>
        </div>

        <DialogFooter className="flex gap-2 sm:justify-end">
          <Button
            variant="outline"
            onClick={onClose}
            disabled={acknowledgeMutation.isPending}
            autoFocus
          >
            Cancel
          </Button>
          <Button
            variant="destructive"
            onClick={() => acknowledgeMutation.mutate()}
            disabled={acknowledgeMutation.isPending}
          >
            {acknowledgeMutation.isPending
              ? "Saving..."
              : "Acknowledge and continue"}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}
