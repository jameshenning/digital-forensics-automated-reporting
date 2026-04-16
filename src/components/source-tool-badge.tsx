/**
 * SourceToolBadge — a small "Discovered via <tool>" badge rendered next to
 * auto-discovered identifier rows in the Person / Business identifier editors.
 *
 * Hovering the badge reveals a Tooltip with the tool's description pulled
 * from the forensic-tools KB (`src/lib/forensic-tools.ts`). Investigators can
 * see WHAT surfaced a given identifier and WHAT that tool typically finds —
 * the same knowledge that powers the narrative cards on the Tools tab — at
 * the point of triage, without leaving the editor.
 *
 * If the tool is not in the KB (unusual — should add it to
 * `forensic-tools.ts` + `forensic_tools.rs`) the badge still renders but the
 * tooltip falls back to a "No detailed description available" note so the
 * provenance is still visible.
 */

import { Search } from "lucide-react";

import { Badge } from "@/components/ui/badge";
import {
  Tooltip,
  TooltipContent,
  TooltipProvider,
  TooltipTrigger,
} from "@/components/ui/tooltip";
import { lookupTool } from "@/lib/forensic-tools";

interface SourceToolBadgeProps {
  toolName: string;
  className?: string;
}

export function SourceToolBadge({ toolName, className }: SourceToolBadgeProps) {
  const tool = lookupTool(toolName);
  const description = tool?.description ?? "No detailed description available for this tool yet.";
  const typicalFindings = tool?.typicalFindings ?? [];

  return (
    <TooltipProvider delayDuration={150}>
      <Tooltip>
        <TooltipTrigger asChild>
          <Badge
            variant="secondary"
            className={`gap-1 text-xs font-normal cursor-help ${className ?? ""}`.trim()}
          >
            <Search className="h-3 w-3" aria-hidden="true" />
            <span className="text-muted-foreground">via</span>
            <span className="font-medium">{tool?.name ?? toolName}</span>
          </Badge>
        </TooltipTrigger>
        <TooltipContent
          side="top"
          align="start"
          className="max-w-sm whitespace-normal text-left text-xs leading-relaxed p-3"
        >
          <p className="font-medium text-sm mb-1.5">
            {tool?.name ?? toolName}
          </p>
          <p className="text-muted-foreground mb-2">{description}</p>
          {typicalFindings.length > 0 && (
            <div>
              <p className="font-medium mb-1">Typical findings:</p>
              <ul className="list-disc list-inside space-y-0.5 text-muted-foreground">
                {typicalFindings.slice(0, 4).map((f) => (
                  <li key={f}>{f}</li>
                ))}
              </ul>
            </div>
          )}
        </TooltipContent>
      </Tooltip>
    </TooltipProvider>
  );
}
