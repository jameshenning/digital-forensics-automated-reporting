/**
 * WizardRail — left vertical tab list for the DFAR case wizard.
 *
 * Shows 10 sections with states:
 *   locked     → gray, lock icon, not clickable
 *   available  → neutral, empty circle, clickable
 *   active     → blue highlight, arrow icon
 *   complete   → green, checkmark icon
 *
 * Examiner can click backward to any complete/available tab.
 * Forward locked tabs are disabled.
 */

import { Lock, Circle, Play, Check } from "lucide-react";
import { cn } from "@/lib/utils";

export interface WizardSection {
  id: number;
  label: string;
  shortLabel: string;
}

export const WIZARD_SECTIONS: WizardSection[] = [
  { id: 1, label: "Case Setup", shortLabel: "Case" },
  { id: 2, label: "Chain of Custody", shortLabel: "CoC" },
  { id: 3, label: "Evidence Collection", shortLabel: "Collect" },
  { id: 4, label: "Evidence Inventory", shortLabel: "Inventory" },
  { id: 5, label: "Acquisition", shortLabel: "Acquire" },
  { id: 6, label: "Exam Environment & Tools", shortLabel: "Env & Tools" },
  { id: 7, label: "Examination & Findings", shortLabel: "Examine" },
  { id: 8, label: "Opinions & Conclusions", shortLabel: "Opinion" },
  { id: 9, label: "Disposition", shortLabel: "Dispose" },
  { id: 10, label: "Authorization & Export", shortLabel: "Export" },
];

export type SectionState = "locked" | "available" | "active" | "complete";

interface WizardRailProps {
  activeSection: number;
  completedSections: Set<number>;
  onNavigate: (sectionId: number) => void;
}

function getSectionState(
  sectionId: number,
  activeSection: number,
  completedSections: Set<number>
): SectionState {
  if (sectionId === activeSection) return "active";
  if (completedSections.has(sectionId)) return "complete";
  const maxUnlocked = Math.max(activeSection, ...Array.from(completedSections));
  if (sectionId <= maxUnlocked + 1) return "available";
  return "locked";
}

function StatusIcon({ state }: { state: SectionState }) {
  switch (state) {
    case "locked":
      return <Lock className="h-3.5 w-3.5" />;
    case "complete":
      return <Check className="h-3.5 w-3.5" />;
    case "active":
      return <Play className="h-3.5 w-3.5" />;
    case "available":
    default:
      return <Circle className="h-3.5 w-3.5" />;
  }
}

export function WizardRail({
  activeSection,
  completedSections,
  onNavigate,
}: WizardRailProps) {
  return (
    <nav
      className="flex flex-col gap-0.5 w-[220px] shrink-0 py-4"
      aria-label="Case wizard sections"
    >
      {WIZARD_SECTIONS.map((section) => {
        const state = getSectionState(section.id, activeSection, completedSections);
        const isClickable = state === "available" || state === "complete";

        return (
          <button
            key={section.id}
            type="button"
            disabled={!isClickable}
            onClick={() => isClickable && onNavigate(section.id)}
            className={cn(
              "flex items-center gap-2.5 rounded-md px-3 py-2 text-left text-sm transition-colors",
              "focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring",
              state === "active" &&
                "bg-primary/10 text-primary font-medium",
              state === "complete" &&
                "text-success hover:bg-success/10",
              state === "available" &&
                "text-foreground hover:bg-muted cursor-pointer",
              state === "locked" &&
                "text-muted-foreground cursor-not-allowed opacity-60"
            )}
          >
            <span
              className={cn(
                "flex h-5 w-5 shrink-0 items-center justify-center rounded-full",
                state === "active" && "bg-primary text-primary-foreground",
                state === "complete" && "bg-success text-success-foreground",
                state === "available" &&
                  "border border-border text-muted-foreground",
                state === "locked" && "text-muted-foreground"
              )}
            >
              <StatusIcon state={state} />
            </span>
            <span className="truncate">{section.label}</span>
          </button>
        );
      })}
    </nav>
  );
}
