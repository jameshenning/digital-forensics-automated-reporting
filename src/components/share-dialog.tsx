/**
 * ShareDialog — log when forensic data leaves the app.
 *
 * Records an email/print share event to the case_shares audit trail.
 * Used from evidence cards, report dialog, analysis notes, etc.
 */

import { useState } from "react";
import { useMutation } from "@tanstack/react-query";
import { Share2, Loader2, Mail, Printer } from "lucide-react";

import { shareRecord, type CaseShare } from "@/lib/bindings";
import { getToken } from "@/lib/session";
import { toastError, toastSuccess } from "@/lib/error-toast";

import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
  DialogFooter,
} from "@/components/ui/dialog";
import { Button } from "@/components/ui/button";
import { Label } from "@/components/ui/label";
import { Textarea } from "@/components/ui/textarea";
import { Input } from "@/components/ui/input";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";

// ---------------------------------------------------------------------------
// Props
// ---------------------------------------------------------------------------

export interface ShareDialogProps {
  caseId: string;
  recordType: string;
  recordId: string;
  recordSummary?: string;
  open: boolean;
  onClose: () => void;
}

// ---------------------------------------------------------------------------
// Component
// ---------------------------------------------------------------------------

export function ShareDialog({
  caseId,
  recordType,
  recordId,
  recordSummary,
  open,
  onClose,
}: ShareDialogProps) {
  const token = getToken() ?? "";
  const [action, setAction] = useState<"email" | "print">("email");
  const [recipient, setRecipient] = useState("");
  const [narrative, setNarrative] = useState("");

  const mutation = useMutation<CaseShare, Error>({
    mutationFn: () =>
      shareRecord({
        token,
        input: {
          case_id: caseId,
          record_type: recordType,
          record_id: recordId,
          record_summary: recordSummary || undefined,
          action,
          recipient: action === "email" ? recipient || undefined : undefined,
          file_hash: "", // Hash not computed on frontend; backend accepts empty sentinel
          narrative: narrative || "Shared from DFARS Desktop",
        },
      }),
    onSuccess: (share) => {
      toastSuccess(
        `Share logged: ${share.record_type} ${share.record_id} via ${share.action}.`
      );
      setRecipient("");
      setNarrative("");
      onClose();
    },
    onError: toastError,
  });

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    mutation.mutate();
  };

  return (
    <Dialog open={open} onOpenChange={(o) => { if (!o) onClose(); }}>
      <DialogContent className="max-w-md">
        <DialogHeader>
          <DialogTitle className="flex items-center gap-2 text-lg">
            <Share2 className="h-5 w-5 shrink-0" aria-hidden="true" />
            Log Share Event
          </DialogTitle>
        </DialogHeader>

        <form onSubmit={handleSubmit} className="space-y-4">
          <div className="space-y-1.5">
            <Label htmlFor="share-action" className="text-sm">
              Action
            </Label>
            <Select
              value={action}
              onValueChange={(v) => setAction(v as "email" | "print")}
            >
              <SelectTrigger id="share-action">
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="email">
                  <span className="flex items-center gap-2">
                    <Mail className="h-3.5 w-3.5" />
                    Email
                  </span>
                </SelectItem>
                <SelectItem value="print">
                  <span className="flex items-center gap-2">
                    <Printer className="h-3.5 w-3.5" />
                    Print
                  </span>
                </SelectItem>
              </SelectContent>
            </Select>
          </div>

          {action === "email" && (
            <div className="space-y-1.5">
              <Label htmlFor="share-recipient" className="text-sm">
                Recipient
              </Label>
              <Input
                id="share-recipient"
                type="email"
                placeholder="recipient@example.com"
                value={recipient}
                onChange={(e) => setRecipient(e.target.value)}
              />
            </div>
          )}

          <div className="space-y-1.5">
            <Label htmlFor="share-narrative" className="text-sm">
              Narrative
            </Label>
            <Textarea
              id="share-narrative"
              placeholder="Reason for sharing this record…"
              value={narrative}
              onChange={(e) => setNarrative(e.target.value)}
              rows={3}
            />
          </div>

          <DialogFooter className="gap-2">
            <Button
              type="button"
              variant="outline"
              onClick={onClose}
              disabled={mutation.isPending}
            >
              Cancel
            </Button>
            <Button
              type="submit"
              disabled={mutation.isPending}
            >
              {mutation.isPending ? (
                <>
                  <Loader2 className="h-4 w-4 mr-2 animate-spin" />
                  Logging…
                </>
              ) : (
                <>
                  <Share2 className="h-4 w-4 mr-2" />
                  Log Share
                </>
              )}
            </Button>
          </DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  );
}
