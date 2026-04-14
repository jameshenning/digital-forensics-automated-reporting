/**
 * DriveScanButton — invokes drive_scan for a case's evidence_drive_path.
 *
 * Flow:
 *   1. Button click → progress toast.
 *   2. On success → opens a summary dialog with file_count, total_bytes,
 *      and top extensions.
 *   3. On DriveScanTooLarge → toastError with count.
 *   4. If evidence_drive_path is null → button is disabled with a tooltip.
 */

import React from "react";
import { useMutation } from "@tanstack/react-query";
import { HardDrive, Loader2 } from "lucide-react";
import { toast } from "sonner";

import { driveScan, type DriveScanResult } from "@/lib/bindings";
import { getToken } from "@/lib/session";
import { toastError } from "@/lib/error-toast";

import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
  DialogFooter,
} from "@/components/ui/dialog";
import {
  Tooltip,
  TooltipContent,
  TooltipProvider,
  TooltipTrigger,
} from "@/components/ui/tooltip";

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function fmtBytes(bytes: number): string {
  if (bytes >= 1e9) return `${(bytes / 1e9).toFixed(2)} GB`;
  if (bytes >= 1e6) return `${(bytes / 1e6).toFixed(1)} MB`;
  if (bytes >= 1e3) return `${(bytes / 1e3).toFixed(0)} KB`;
  return `${bytes} B`;
}

// ---------------------------------------------------------------------------
// Props
// ---------------------------------------------------------------------------

interface DriveScanButtonProps {
  caseId: string;
  drivePath: string | null;
}

// ---------------------------------------------------------------------------
// Result dialog
// ---------------------------------------------------------------------------

interface ScanResultDialogProps {
  open: boolean;
  result: DriveScanResult | null;
  onClose: () => void;
}

function ScanResultDialog({ open, result, onClose }: ScanResultDialogProps) {
  if (!result) return null;

  const topExts = Object.entries(result.top_extensions)
    .sort(([, a], [, b]) => b - a)
    .slice(0, 10);

  return (
    <Dialog open={open} onOpenChange={(isOpen) => { if (!isOpen) onClose(); }}>
      <DialogContent className="max-w-md">
        <DialogHeader>
          <div className="flex items-center gap-2">
            <HardDrive className="h-5 w-5 text-primary shrink-0" />
            <DialogTitle>Drive Scan Results</DialogTitle>
          </div>
        </DialogHeader>

        <div className="space-y-4 text-sm">
          <div className="grid grid-cols-2 gap-3">
            <div>
              <p className="text-xs font-medium text-muted-foreground uppercase tracking-wide mb-0.5">
                Root
              </p>
              <p className="font-mono text-xs">{result.root}</p>
            </div>
            <div>
              <p className="text-xs font-medium text-muted-foreground uppercase tracking-wide mb-0.5">
                File count
              </p>
              <p className="font-semibold">{result.file_count.toLocaleString()}</p>
            </div>
            <div>
              <p className="text-xs font-medium text-muted-foreground uppercase tracking-wide mb-0.5">
                Total size
              </p>
              <p className="font-semibold">{fmtBytes(result.total_bytes)}</p>
            </div>
          </div>

          {topExts.length > 0 && (
            <div>
              <p className="text-xs font-medium text-muted-foreground uppercase tracking-wide mb-1.5">
                Top file extensions
              </p>
              <div className="flex flex-wrap gap-1.5">
                {topExts.map(([ext, count]) => (
                  <Badge key={ext} variant="secondary" className="font-mono text-xs">
                    {ext || "(no ext)"}{" "}
                    <span className="ml-1 text-muted-foreground">
                      {count.toLocaleString()}
                    </span>
                  </Badge>
                ))}
              </div>
            </div>
          )}
        </div>

        <DialogFooter>
          <Button onClick={onClose}>Close</Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}

// ---------------------------------------------------------------------------
// Main component
// ---------------------------------------------------------------------------

export function DriveScanButton({ caseId, drivePath }: DriveScanButtonProps) {
  const token = getToken() ?? "";
  const [resultOpen, setResultOpen] = React.useState(false);
  const [scanResult, setScanResult] = React.useState<DriveScanResult | null>(null);
  const toastId = React.useRef<string | number | null>(null);

  const scanMutation = useMutation({
    mutationFn: () => {
      if (!drivePath) throw new Error("No drive path configured for this case.");
      toastId.current = toast.loading("Scanning drive...");
      return driveScan({ token, case_id: caseId, path: drivePath });
    },
    onSuccess: (result) => {
      if (toastId.current !== null) toast.dismiss(toastId.current);
      setScanResult(result);
      setResultOpen(true);
    },
    onError: (err) => {
      if (toastId.current !== null) toast.dismiss(toastId.current);
      toastError(err);
    },
  });

  const hasDrive = drivePath !== null && drivePath.trim().length > 0;

  const button = (
    <Button
      size="sm"
      variant="outline"
      disabled={!hasDrive || scanMutation.isPending}
      onClick={() => scanMutation.mutate()}
      aria-label={hasDrive ? "Scan evidence drive" : "No evidence drive configured"}
    >
      {scanMutation.isPending ? (
        <Loader2 className="h-4 w-4 mr-1 animate-spin" />
      ) : (
        <HardDrive className="h-4 w-4 mr-1" />
      )}
      Scan Drive
    </Button>
  );

  return (
    <>
      {!hasDrive ? (
        <TooltipProvider>
          <Tooltip>
            <TooltipTrigger asChild>
              <span tabIndex={0} className="inline-flex">
                {button}
              </span>
            </TooltipTrigger>
            <TooltipContent>
              Set an evidence drive path on this case to enable drive scanning
            </TooltipContent>
          </Tooltip>
        </TooltipProvider>
      ) : (
        button
      )}

      <ScanResultDialog
        open={resultOpen}
        result={scanResult}
        onClose={() => setResultOpen(false)}
      />
    </>
  );
}
