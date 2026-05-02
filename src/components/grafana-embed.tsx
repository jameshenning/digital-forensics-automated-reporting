/**
 * GrafanaEmbed — seamless iframe wrapper for embedded Grafana dashboards.
 *
 * Automatically enables Grafana (first time), starts the Docker container,
 * and polls until the dashboard is ready. The user just clicks the tab.
 */

import { useState, useEffect, useRef } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { Loader2, AlertCircle, ExternalLink } from "lucide-react";

import {
  grafanaStatus,
  grafanaStart,
  grafanaSetSettings,
} from "@/lib/bindings";
import { getToken } from "@/lib/session";
import { queryKeys } from "@/lib/query";
import { toastError } from "@/lib/error-toast";

import { Button } from "@/components/ui/button";

// ---------------------------------------------------------------------------
// Props
// ---------------------------------------------------------------------------

interface GrafanaEmbedProps {
  /** Grafana dashboard UID. */
  dashboardUid: string;
  /** Optional case ID to scope the dashboard. */
  caseId?: string;
  /** Theme to pass to Grafana. */
  theme?: "light" | "dark";
}

// ---------------------------------------------------------------------------
// Component
// ---------------------------------------------------------------------------

export function GrafanaEmbed({ dashboardUid, caseId, theme = "dark" }: GrafanaEmbedProps) {
  const token = getToken() ?? "";
  const queryClient = useQueryClient();
  const [bootPhase, setBootPhase] = useState<
    "checking" | "enabling" | "starting" | "polling" | "ready" | "error"
  >("checking");
  const [errorMsg, setErrorMsg] = useState<string | null>(null);
  const bootStarted = useRef(false);

  const { data: status } = useQuery({
    queryKey: queryKeys.grafana.settings,
    queryFn: () => grafanaStatus({ token }),
    enabled: !!token,
    refetchInterval: bootPhase === "polling" ? 2000 : false,
    refetchOnWindowFocus: false,
  });

  const enableMutation = useMutation({
    mutationFn: () => grafanaSetSettings({ token, input: { enabled: true } }),
    onSuccess: () => {
      void queryClient.invalidateQueries({ queryKey: queryKeys.grafana.settings });
    },
    onError: (err: unknown) => {
      const msg =
        (err as { message?: string })?.message ?? "Failed to enable Grafana.";
      setErrorMsg(msg);
      setBootPhase("error");
      toastError(err);
    },
  });

  const startMutation = useMutation({
    mutationFn: () => grafanaStart({ token }),
    onSuccess: () => {
      setBootPhase("polling");
      void queryClient.invalidateQueries({ queryKey: queryKeys.grafana.settings });
    },
    onError: (err: unknown) => {
      const msg = (err as { message?: string })?.message ?? "";
      if (
        msg.toLowerCase().includes("docker") ||
        msg.toLowerCase().includes("not found")
      ) {
        setErrorMsg(
          "Docker is not installed or not running. Install Docker Desktop to use Grafana dashboards."
        );
      } else {
        setErrorMsg(msg);
      }
      setBootPhase("error");
      toastError(err);
    },
  });

  // Orchestrate the boot sequence
  useEffect(() => {
    if (!status || bootPhase === "ready" || bootPhase === "error") return;

    // 1. Not enabled → enable it
    if (!status.enabled) {
      if (bootPhase === "checking" && !bootStarted.current) {
        bootStarted.current = true;
        setBootPhase("enabling");
        enableMutation.mutate();
      }
      return;
    }

    // 2. Docker not available → show clear error immediately
    if (!status.docker_available) {
      if (bootPhase === "checking" || bootPhase === "enabling") {
        setErrorMsg(
          "Docker is not installed or not running. Install Docker Desktop to use Grafana dashboards."
        );
        setBootPhase("error");
      }
      return;
    }

    // 3. Enabled but not running → start it
    if (!status.running) {
      if (bootPhase === "checking" || bootPhase === "enabling") {
        setBootPhase("starting");
        startMutation.mutate();
      }
      // If already polling, keep waiting for the container to come up
      return;
    }

    // 3. Running → show dashboard
    setBootPhase("ready");
  }, [status?.enabled, status?.running, bootPhase]);

  // Build iframe URL the moment the container is running
  const iframeUrl = (() => {
    if (!status?.running) return null;
    const params = new URLSearchParams({ kiosk: "tv", theme });
    if (caseId) params.set("var-caseId", caseId);
    return `http://localhost:3099/d/${dashboardUid}?${params.toString()}`;
  })();

  // -------------------------------------------------------------------------
  // Render
  // -------------------------------------------------------------------------

  if (bootPhase === "error") {
    return (
      <div className="rounded-lg border border-dashed p-8 text-center">
        <AlertCircle className="h-8 w-8 mx-auto text-destructive/70 mb-2" />
        <p className="text-sm font-medium">Could not start Grafana</p>
        {errorMsg && (
          <p className="text-xs text-muted-foreground mt-1 max-w-sm mx-auto">
            {errorMsg}
          </p>
        )}
        <Button
          size="sm"
          variant="outline"
          className="mt-3"
          onClick={() => {
            bootStarted.current = false;
            setBootPhase("checking");
            setErrorMsg(null);
            void queryClient.invalidateQueries({
              queryKey: queryKeys.grafana.settings,
            });
          }}
        >
          Retry
        </Button>
      </div>
    );
  }

  if (!iframeUrl) {
    const label =
      bootPhase === "enabling"
        ? "Enabling Grafana…"
        : bootPhase === "starting"
          ? "Starting Grafana container…"
          : bootPhase === "polling"
            ? "Waiting for Grafana to respond…"
            : "Checking Grafana status…";

    return (
      <div className="rounded-lg border border-dashed p-8 text-center">
        <Loader2 className="h-8 w-8 mx-auto text-muted-foreground animate-spin mb-2" />
        <p className="text-sm font-medium">{label}</p>
        <p className="text-xs text-muted-foreground mt-1">
          This may take 10–30 seconds on first launch.
        </p>
      </div>
    );
  }

  return (
    <div className="space-y-2">
      <div className="flex items-center justify-between">
        <p className="text-xs text-muted-foreground">
          Powered by Grafana · localhost:3099
        </p>
        <Button
          size="sm"
          variant="ghost"
          onClick={() => window.open(iframeUrl, "_blank")}
        >
          <ExternalLink className="h-3.5 w-3.5 mr-1" />
          Open in Grafana
        </Button>
      </div>
      <iframe
        src={iframeUrl}
        title="Grafana Dashboard"
        className="w-full rounded-md border"
        style={{ height: "70vh", minHeight: 500 }}
        sandbox="allow-scripts allow-same-origin allow-popups"
      />
    </div>
  );
}
