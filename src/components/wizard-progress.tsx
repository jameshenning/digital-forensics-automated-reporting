/**
 * WizardProgress — top horizontal progress bar.
 *
 * Shows "X of 10 sections complete (Y%)" with a blue fill bar.
 */

import { cn } from "@/lib/utils";

interface WizardProgressProps {
  completedCount: number;
  total?: number;
}

export function WizardProgress({
  completedCount,
  total = 10,
}: WizardProgressProps) {
  const pct = Math.round((completedCount / total) * 100);

  return (
    <div className="flex items-center gap-4 px-6 py-3 border-b bg-card">
      <div className="flex-1">
        <div className="flex items-center justify-between mb-1.5">
          <span className="text-xs font-medium text-muted-foreground">
            Progress
          </span>
          <span className="text-xs font-medium text-foreground">
            {completedCount} of {total} sections complete ({pct}%)
          </span>
        </div>
        <div className="h-2 w-full rounded-full bg-muted overflow-hidden">
          <div
            className={cn(
              "h-full rounded-full transition-all duration-500 ease-out",
              pct === 100 ? "bg-success" : "bg-primary"
            )}
            style={{ width: `${pct}%` }}
            aria-valuenow={pct}
            aria-valuemin={0}
            aria-valuemax={100}
            role="progressbar"
          />
        </div>
      </div>
    </div>
  );
}
