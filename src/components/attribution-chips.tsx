/**
 * AttributionChips — small visual chips for Phase B (migration 0008)
 * attribution metadata on identifiers and entity links.
 *
 * Three chips render conditionally:
 *   - Confidence (Low / Medium / High) — gray / blue / green
 *   - Verification (Unverified / Tentative / Confirmed) — gray / amber / green
 *     (only on identifier rows; entity_links don't carry verification)
 *   - Author — small "by X" text with "not recorded" fallback when null
 *
 * Used by:
 *   - IdentifierRow in person-identifier-editor.tsx + business-identifier-editor.tsx
 *   - Link card in links-panel.tsx
 */

import type { ConfidenceLevel, VerificationStatus } from "@/lib/bindings";

interface AttributionChipsProps {
  confidence: ConfidenceLevel | null | undefined;
  verification?: VerificationStatus | null | undefined;
  attributedBy?: string | null | undefined;
  /** Optional one-line basis string rendered below the chips. */
  basis?: string | null | undefined;
  /** Compact: smaller chip padding, suitable for dense list rows. */
  compact?: boolean;
}

const CONFIDENCE_CLASSES: Record<ConfidenceLevel, string> = {
  Low: "bg-slate-100 text-slate-700 border-slate-200 dark:bg-slate-900/40 dark:text-slate-300 dark:border-slate-700",
  Medium:
    "bg-blue-50 text-blue-700 border-blue-200 dark:bg-blue-900/30 dark:text-blue-300 dark:border-blue-700",
  High: "bg-emerald-50 text-emerald-700 border-emerald-200 dark:bg-emerald-900/30 dark:text-emerald-300 dark:border-emerald-700",
};

const VERIFICATION_CLASSES: Record<VerificationStatus, string> = {
  Unverified:
    "bg-slate-100 text-slate-700 border-slate-200 dark:bg-slate-900/40 dark:text-slate-300 dark:border-slate-700",
  Tentative:
    "bg-amber-50 text-amber-700 border-amber-200 dark:bg-amber-900/30 dark:text-amber-300 dark:border-amber-700",
  Confirmed:
    "bg-emerald-50 text-emerald-700 border-emerald-200 dark:bg-emerald-900/30 dark:text-emerald-300 dark:border-emerald-700",
};

export function AttributionChips({
  confidence,
  verification,
  attributedBy,
  basis,
  compact = false,
}: AttributionChipsProps) {
  // Render nothing when there is nothing meaningful to display. Cards on v1
  // rows should look identical to pre-Phase-B if no data exists yet.
  const hasAnything =
    !!confidence ||
    !!verification ||
    (attributedBy && attributedBy.trim() !== "") ||
    (basis && basis.trim() !== "");
  if (!hasAnything) return null;

  const padX = compact ? "px-1.5" : "px-2";
  const padY = compact ? "py-0" : "py-0.5";
  const textSize = compact ? "text-[10px]" : "text-xs";

  return (
    <div className="mt-1 flex flex-col gap-1">
      <div className="flex flex-wrap items-center gap-1.5">
        {confidence && (
          <span
            className={`inline-flex items-center rounded-full border ${padX} ${padY} ${textSize} font-medium ${CONFIDENCE_CLASSES[confidence]}`}
            title="Confidence level"
          >
            Confidence: {confidence}
          </span>
        )}
        {verification && (
          <span
            className={`inline-flex items-center rounded-full border ${padX} ${padY} ${textSize} font-medium ${VERIFICATION_CLASSES[verification]}`}
            title="Verification status"
          >
            {verification}
          </span>
        )}
        <span
          className={`inline-flex items-center rounded-full border border-dashed ${padX} ${padY} ${textSize} text-muted-foreground`}
          title="Author / attributed by"
        >
          {attributedBy && attributedBy.trim() !== ""
            ? `by ${attributedBy}`
            : "author not recorded"}
        </span>
      </div>
      {basis && basis.trim() !== "" && (
        <p className="text-xs text-muted-foreground italic break-words">
          {basis}
        </p>
      )}
    </div>
  );
}
