/**
 * Section 8 — Opinions & Conclusions
 * Displays analysis conclusions.
 */

import { Card, CardContent } from "@/components/ui/card";
import { useQuery } from "@tanstack/react-query";
import { analysisListForCase } from "@/lib/bindings";
import { getToken } from "@/lib/session";
import { queryKeys } from "@/lib/query";
import { Skeleton } from "@/components/ui/skeleton";

interface SectionOpinionsProps {
  caseId: string;
}

export function SectionOpinions({ caseId }: SectionOpinionsProps) {
  const token = getToken() ?? "";
  const { data, isLoading } = useQuery({
    queryKey: [...queryKeys.cases.detail(caseId), "analysis"],
    queryFn: () => analysisListForCase({ token, case_id: caseId }),
    enabled: !!token,
  });

  const conclusions = data?.filter((a) => a.category === "Conclusion") ?? [];

  return (
    <div className="space-y-6">
      <div>
        <h2 className="text-xl font-semibold tracking-tight">
          Opinions & Conclusions
        </h2>
        <p className="mt-1 text-sm text-muted-foreground">
          Review conclusions drawn from the examination.
        </p>
      </div>

      {isLoading ? (
        <Skeleton className="h-32 w-full" />
      ) : conclusions.length === 0 ? (
        <Card>
          <CardContent className="pt-6">
            <p className="text-sm text-muted-foreground">
              No conclusion notes recorded yet. Add conclusions in the{" "}
              <strong>Examination Process & Findings</strong> section by
              creating an analysis note with category "Conclusion".
            </p>
          </CardContent>
        </Card>
      ) : (
        <div className="space-y-3">
          {conclusions.map((note) => (
            <Card key={note.note_id}>
              <CardContent className="pt-4">
                <p className="text-xs font-medium text-muted-foreground uppercase tracking-wide mb-1">
                  {note.finding}
                </p>
                <p className="text-sm whitespace-pre-wrap">{note.description}</p>
                {note.confidence_level && (
                  <p className="mt-2 text-xs text-muted-foreground">
                    Confidence: {note.confidence_level}
                  </p>
                )}
              </CardContent>
            </Card>
          ))}
        </div>
      )}
    </div>
  );
}
