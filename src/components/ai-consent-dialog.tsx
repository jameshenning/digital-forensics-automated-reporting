/**
 * AiConsentDialog — one-time consent gate for Agent Zero AI features.
 *
 * Supports two scopes:
 *   scope="summarize" (default) — SEC-4 §2.7 / SHOULD-DO 4 gate for
 *     ai_summarize_case. Shown once per install before the first full-case
 *     payload leaves the machine.
 *   scope="osint" — separate gate for ai_osint_person (Persons feature).
 *     More invasive: PII leaves the machine AND is forwarded to external
 *     OSINT sources (LinkedIn, Shodan, Sherlock's site list, etc.) by
 *     Agent Zero's OSINT tools.
 *
 * BLOCKING: Escape and outside-click dismissal are suppressed. Buttons
 * are the only exit.
 *
 * After the user clicks "Acknowledge and continue":
 *   1. Calls settings_acknowledge_ai_consent OR settings_acknowledge_osint_consent
 *      depending on scope
 *   2. Calls onAcknowledge so the parent can retry the original operation
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
import {
  settingsAcknowledgeAiConsent,
  settingsAcknowledgeOsintConsent,
} from "@/lib/bindings";
import { getToken } from "@/lib/session";
import { toastError } from "@/lib/error-toast";

// ---------------------------------------------------------------------------
// Props
// ---------------------------------------------------------------------------

export type AiConsentScope = "summarize" | "osint";

export interface AiConsentDialogProps {
  open: boolean;
  /** Which backend consent gate to acknowledge. Defaults to "summarize". */
  scope?: AiConsentScope;
  /** The Agent Zero URL currently configured — shown verbatim in the body. */
  agentZeroUrl: string;
  /** Called after acknowledgement is recorded. Parent should retry. */
  onAcknowledge: () => void;
  /** Called when the user clicks Cancel. */
  onClose: () => void;
}

// ---------------------------------------------------------------------------
// Component
// ---------------------------------------------------------------------------

export function AiConsentDialog({
  open,
  scope = "summarize",
  agentZeroUrl,
  onAcknowledge,
  onClose,
}: AiConsentDialogProps) {
  const acknowledgeMutation = useMutation({
    mutationFn: () => {
      const token = getToken();
      if (!token) throw new Error("No session token");
      return scope === "osint"
        ? settingsAcknowledgeOsintConsent({ token })
        : settingsAcknowledgeAiConsent({ token });
    },
    onSuccess: () => {
      onAcknowledge();
    },
    onError: toastError,
  });

  const isOsint = scope === "osint";
  const title = isOsint
    ? "Run OSINT on this person?"
    : "Send full case to Agent Zero?";

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
            <DialogTitle>{title}</DialogTitle>
          </div>
        </DialogHeader>

        {isOsint ? (
          <div className="text-sm space-y-3 text-muted-foreground">
            <p>
              The <strong className="text-foreground">Run OSINT</strong> feature sends
              the person's{" "}
              <strong className="text-foreground">
                known identifying fields
              </strong>{" "}
              to your Agent Zero instance, which will orchestrate a set of Kali Linux
              OSINT tools against them. This includes (when set):
            </p>

            <ul className="list-disc pl-5 space-y-1">
              <li>Full name</li>
              <li>Email address</li>
              <li>Phone number</li>
              <li>Username / handle</li>
              <li>Employer</li>
              <li>Date of birth</li>
              <li>Investigator notes</li>
            </ul>

            <p>
              Agent Zero will run tools including{" "}
              <strong className="text-foreground">Sherlock</strong>,{" "}
              <strong className="text-foreground">holehe</strong>,{" "}
              <strong className="text-foreground">theHarvester</strong>, and{" "}
              <strong className="text-foreground">SpiderFoot</strong>, and may run
              additional Kali OSINT tools at its discretion. Each tool will query
              public data sources — <strong className="text-foreground">external
              services such as LinkedIn, Shodan, DNS, certificate transparency logs,
              and hundreds of social/account-existence APIs</strong>.
            </p>

            <p>
              PII will leave this machine by design. You are responsible for
              ensuring this is legally appropriate for your jurisdiction and
              investigation authority.
            </p>

            <p>
              Agent Zero is configured at{" "}
              <code className="text-foreground font-mono text-xs bg-muted px-1 py-0.5 rounded">
                {agentZeroUrl}
              </code>
              . Each tool run will be logged as a <code>tool_usage</code> row in
              this case with the full narrative — attorney-visible in the final
              report.
            </p>

            <p>
              Click{" "}
              <strong className="text-foreground">
                Acknowledge and run OSINT
              </strong>{" "}
              to confirm.
            </p>
          </div>
        ) : (
          <div className="text-sm space-y-3 text-muted-foreground">
            <p>
              The <strong className="text-foreground">Summarize Case</strong>{" "}
              feature sends the{" "}
              <strong className="text-foreground">entire case payload</strong> to
              your Agent Zero instance so it can produce an executive summary.
              This includes:
            </p>

            <ul className="list-disc pl-5 space-y-1">
              <li>Case header (name, investigator, agency, classification)</li>
              <li>All tags</li>
              <li>
                All evidence items (description, collector, type, serial numbers)
              </li>
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
              . DFARS has verified this URL is loopback or a local Docker
              container; it will not leave this machine. However, if your Agent
              Zero has its own plugins that forward data externally, those will
              also see this payload.
            </p>

            <p>
              Click{" "}
              <strong className="text-foreground">
                Acknowledge and continue
              </strong>{" "}
              only if you understand what will be sent.
            </p>
          </div>
        )}

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
              : isOsint
                ? "Acknowledge and run OSINT"
                : "Acknowledge and continue"}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}
