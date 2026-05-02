/**
 * CaseDashboards — native React replacement for the Grafana iframe embed.
 *
 * Two inner tabs:
 *   - Statistics: bar charts + timeline table
 *   - Network Graph: Cytoscape.js entity graph
 *
 * No Docker, no iframe, no boot sequence. Data loads via TanStack Query on mount.
 */

import { useState } from "react";
import { BarChart3, Network } from "lucide-react";

import { Tabs, TabsList, TabsTrigger, TabsContent } from "@/components/ui/tabs";
import { CaseStatsCharts } from "@/components/case-stats-charts";
import { CaseNetworkGraph } from "@/components/case-network-graph";

interface CaseDashboardsProps {
  caseId: string;
}

export function CaseDashboards({ caseId }: CaseDashboardsProps) {
  const [activeTab, setActiveTab] = useState<"statistics" | "network">("statistics");

  return (
    <Tabs
      value={activeTab}
      onValueChange={(v) => setActiveTab(v as "statistics" | "network")}
      className="w-full"
    >
      <TabsList className="mb-2">
        <TabsTrigger value="statistics">
          <BarChart3 className="h-3.5 w-3.5 mr-1.5" />
          Statistics
        </TabsTrigger>
        <TabsTrigger value="network">
          <Network className="h-3.5 w-3.5 mr-1.5" />
          Network Graph
        </TabsTrigger>
      </TabsList>

      <TabsContent value="statistics" className="mt-0">
        <CaseStatsCharts caseId={caseId} />
      </TabsContent>

      <TabsContent value="network" className="mt-0">
        <CaseNetworkGraph caseId={caseId} />
      </TabsContent>
    </Tabs>
  );
}
