/**
 * WizardFooter — sticky footer with navigation actions.
 *
 *   < Back        [Save Draft]        [Save & Next >]
 *
 * Back is disabled on section 1.
 * Save & Next is disabled until current section validates.
 * Save Draft is always available.
 */

import { ChevronLeft, ChevronRight, Save } from "lucide-react";
import { Button } from "@/components/ui/button";
import { cn } from "@/lib/utils";

interface WizardFooterProps {
  activeSection: number;
  canGoNext: boolean;
  isSaving: boolean;
  lastSavedAt?: Date | null;
  onBack: () => void;
  onSaveDraft: () => void;
  onSaveAndNext: () => void;
}

function fmtSavedAt(d: Date | null | undefined): string {
  if (!d) return "";
  return d.toLocaleTimeString(undefined, {
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
  });
}

export function WizardFooter({
  activeSection,
  canGoNext,
  isSaving,
  lastSavedAt,
  onBack,
  onSaveDraft,
  onSaveAndNext,
}: WizardFooterProps) {
  return (
    <div className="sticky bottom-0 z-10 flex items-center justify-between gap-4 border-t bg-card/95 backdrop-blur px-6 py-4">
      <Button
        variant="outline"
        size="default"
        disabled={activeSection <= 1 || isSaving}
        onClick={onBack}
        className={cn("gap-1.5", activeSection <= 1 && "invisible")}
      >
        <ChevronLeft className="h-4 w-4" />
        Back
      </Button>

      <div className="flex items-center gap-3">
        {lastSavedAt && (
          <span className="hidden sm:inline text-xs text-muted-foreground">
            Saved at {fmtSavedAt(lastSavedAt)}
          </span>
        )}
        <Button
          variant="ghost"
          size="default"
          disabled={isSaving}
          onClick={onSaveDraft}
          className="gap-1.5 text-muted-foreground hover:text-foreground"
        >
          <Save className="h-4 w-4" />
          {isSaving ? "Saving…" : "Save Draft"}
        </Button>

        <Button
          variant="default"
          size="default"
          disabled={!canGoNext || isSaving}
          onClick={onSaveAndNext}
          className="gap-1.5 bg-primary text-primary-foreground hover:bg-primary/90"
        >
          {activeSection >= 10 ? "Finish" : "Save & Next"}
          <ChevronRight className="h-4 w-4" />
        </Button>
      </div>
    </div>
  );
}
