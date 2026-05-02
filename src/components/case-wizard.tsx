/**
 * CaseWizard — DFAR-inspired 10-section vertical wizard.
 *
 * Embeddable within the case detail page. Provides:
 *   - Top progress bar
 *   - Left vertical rail
 *   - Main content area (scrollable)
 *   - Sticky footer with nav buttons
 */

import { useState, useCallback, useEffect } from "react";
import { useQueryClient } from "@tanstack/react-query";

import { WizardRail } from "@/components/wizard-rail";
import { WizardProgress } from "@/components/wizard-progress";
import { WizardFooter } from "@/components/wizard-footer";
import { queryKeys } from "@/lib/query";
import { toastSuccess } from "@/lib/error-toast";

import { SectionCaseSetup } from "@/components/wizard-sections/section-case-setup";
import { SectionCoC } from "@/components/wizard-sections/section-coc";
import { SectionCollection } from "@/components/wizard-sections/section-collection";
import { SectionEvidence } from "@/components/wizard-sections/section-evidence";
import { SectionHashes } from "@/components/wizard-sections/section-hashes";
import { SectionTools } from "@/components/wizard-sections/section-tools";
import { SectionAnalysis } from "@/components/wizard-sections/section-analysis";
import { SectionOpinions } from "@/components/wizard-sections/section-opinions";
import { SectionDisposition } from "@/components/wizard-sections/section-disposition";
import { SectionExport } from "@/components/wizard-sections/section-export";

interface CaseWizardProps {
  caseId: string;
}

function SectionContent({
  sectionId,
  caseId,
}: {
  sectionId: number;
  caseId: string;
}) {
  switch (sectionId) {
    case 1:
      return <SectionCaseSetup caseId={caseId} />;
    case 2:
      return <SectionCoC caseId={caseId} />;
    case 3:
      return <SectionCollection caseId={caseId} />;
    case 4:
      return <SectionEvidence caseId={caseId} />;
    case 5:
      return <SectionHashes caseId={caseId} />;
    case 6:
      return <SectionTools caseId={caseId} />;
    case 7:
      return <SectionAnalysis caseId={caseId} />;
    case 8:
      return <SectionOpinions caseId={caseId} />;
    case 9:
      return <SectionDisposition caseId={caseId} />;
    case 10:
      return <SectionExport caseId={caseId} />;
    default:
      return null;
  }
}

export function CaseWizard({ caseId }: CaseWizardProps) {
  const queryClient = useQueryClient();
  const [activeSection, setActiveSection] = useState(1);
  const [completedSections, setCompletedSections] = useState<Set<number>>(
    new Set()
  );
  const [isSaving, setIsSaving] = useState(false);
  const [lastSavedAt, setLastSavedAt] = useState<Date | null>(null);

  /* ── Navigation ── */

  const goToSection = useCallback(
    (id: number) => {
      if (id >= 1 && id <= 10) setActiveSection(id);
    },
    []
  );

  const goBack = useCallback(() => {
    setActiveSection((s) => Math.max(1, s - 1));
  }, []);

  /* ── Validation ──
   * Sections use independent panels/forms that validate on their own.
   * The wizard allows navigation once data is visible (panels load
   * existing data; empty states are valid for draft progress).
   */
  const canGoNext = true;

  /* ── Save actions ── */

  const syncAndToast = useCallback(async () => {
    // Refresh all case-related queries so the examiner sees the latest
    // state from any panel mutations that fired independently.
    await queryClient.invalidateQueries({
      queryKey: queryKeys.cases.detail(caseId),
    });
    await queryClient.invalidateQueries({
      queryKey: queryKeys.evidence.listForCase(caseId),
    });
    setLastSavedAt(new Date());
    toastSuccess("Draft saved.");
  }, [queryClient, caseId]);

  const handleSaveDraft = useCallback(async () => {
    setIsSaving(true);
    await syncAndToast();
    setIsSaving(false);
  }, [syncAndToast]);

  const handleSaveAndNext = useCallback(async () => {
    setIsSaving(true);
    await syncAndToast();

    setCompletedSections((prev) => {
      const next = new Set(prev);
      next.add(activeSection);
      return next;
    });

    if (activeSection >= 10) {
      setIsSaving(false);
      return;
    }

    setActiveSection((s) => s + 1);
    setIsSaving(false);
  }, [activeSection, syncAndToast]);

  /* ── Keyboard shortcuts ── */

  useEffect(() => {
    function onKeyDown(e: KeyboardEvent) {
      // Ctrl+S → Save Draft
      if (e.ctrlKey && e.key === "s") {
        e.preventDefault();
        if (!isSaving) void handleSaveDraft();
        return;
      }
      // Ctrl+Enter → Save & Next
      if (e.ctrlKey && e.key === "Enter") {
        e.preventDefault();
        if (!isSaving && canGoNext) void handleSaveAndNext();
        return;
      }
    }
    window.addEventListener("keydown", onKeyDown);
    return () => window.removeEventListener("keydown", onKeyDown);
  }, [isSaving, canGoNext, handleSaveDraft, handleSaveAndNext]);

  /* ── Autosave every 30s ── */
  useEffect(() => {
    const id = setInterval(() => {
      if (!isSaving) void handleSaveDraft();
    }, 30000);
    return () => clearInterval(id);
  }, [isSaving, handleSaveDraft]);

  return (
    <div
      className="flex flex-col rounded-lg border bg-card overflow-hidden"
      style={{ minHeight: "70vh" }}
    >
      {/* Progress bar */}
      <WizardProgress completedCount={completedSections.size} />

      {/* Main content */}
      <div className="flex flex-1 overflow-hidden">
        {/* Left rail */}
        <aside className="shrink-0 overflow-y-auto border-r bg-muted/30">
          <WizardRail
            activeSection={activeSection}
            completedSections={completedSections}
            onNavigate={goToSection}
          />
        </aside>

        {/* Section content */}
        <main className="flex flex-1 flex-col overflow-hidden">
          <div className="flex-1 overflow-y-auto px-8 py-6">
            <div className="mx-auto max-w-3xl">
              <SectionContent sectionId={activeSection} caseId={caseId} />
            </div>
          </div>

          {/* Footer */}
          <WizardFooter
            activeSection={activeSection}
            canGoNext={canGoNext}
            isSaving={isSaving}
            lastSavedAt={lastSavedAt}
            onBack={goBack}
            onSaveDraft={handleSaveDraft}
            onSaveAndNext={handleSaveAndNext}
          />
        </main>
      </div>
    </div>
  );
}
