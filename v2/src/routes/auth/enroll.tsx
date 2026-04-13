/**
 * MFA enrollment screen.
 *
 * Protected route (requireAuthBeforeLoad).
 *
 * Flow:
 *   1. On mount, call auth_mfa_enroll_start — get provisioning URI + 10 recovery codes.
 *   2. Display QR code (qrcode.react) + fallback otpauth:// URL.
 *   3. Display the 10 recovery codes with copy + download buttons.
 *      Warn clearly: codes are shown ONCE.
 *   4. User enters a TOTP code from their authenticator app to confirm.
 *   5. Call auth_mfa_enroll_confirm({ code }) → redirect to /settings/security.
 *
 * Recovery code copy uses navigator.clipboard.writeText inside a click handler
 * (not auto-copied on mount — Chromium blocks that).
 */

import {
  createFileRoute,
  useNavigate,
} from "@tanstack/react-router";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { useForm } from "react-hook-form";
import { zodResolver } from "@hookform/resolvers/zod";
import { z } from "zod";
import { QRCodeSVG } from "qrcode.react";
import { Copy, Download, ShieldPlus } from "lucide-react";

import { authMfaEnrollStart, authMfaEnrollConfirm } from "@/lib/bindings";
import { getToken } from "@/lib/session";
import { queryKeys } from "@/lib/query";
import { toastError, toastSuccess } from "@/lib/error-toast";
import { requireAuthBeforeLoad } from "@/lib/auth-guard";

import { Button } from "@/components/ui/button";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Alert, AlertDescription } from "@/components/ui/alert";
import { Separator } from "@/components/ui/separator";
import { Badge } from "@/components/ui/badge";

export const Route = createFileRoute("/auth/enroll")({
  beforeLoad: requireAuthBeforeLoad,
  component: EnrollPage,
});

// ---------------------------------------------------------------------------
// Confirm form schema
// ---------------------------------------------------------------------------

const confirmSchema = z.object({
  code: z
    .string()
    .transform((v) => v.replace(/\s/g, ""))
    .pipe(
      z
        .string()
        .length(6, "TOTP code must be 6 digits")
        .regex(/^\d+$/, "TOTP code must be digits only")
    ),
});

type ConfirmFormValues = z.infer<typeof confirmSchema>;

// ---------------------------------------------------------------------------
// Component
// ---------------------------------------------------------------------------

function EnrollPage() {
  const navigate = useNavigate();
  const queryClient = useQueryClient();

  // Fetch enrollment data once on mount — recovery codes are shown ONCE
  const { data: enrollment, isLoading, error } = useQuery({
    queryKey: queryKeys.mfaEnrollment,
    queryFn: () => {
      const token = getToken();
      if (!token) throw new Error("No session token");
      return authMfaEnrollStart({ token });
    },
    staleTime: Infinity, // Never re-fetch — codes are single-use
    retry: false,
  });

  const {
    register,
    handleSubmit,
    formState: { errors },
  } = useForm<ConfirmFormValues>({
    resolver: zodResolver(confirmSchema),
  });

  const confirmMutation = useMutation({
    mutationFn: (code: string) => {
      const token = getToken();
      if (!token) throw new Error("No session token");
      return authMfaEnrollConfirm({ token, code });
    },
    onSuccess: () => {
      // Remove enrollment query from cache — codes must never be re-shown
      queryClient.removeQueries({ queryKey: queryKeys.mfaEnrollment });
      // Refresh session + security posture
      void queryClient.invalidateQueries({ queryKey: queryKeys.currentUser });
      void queryClient.invalidateQueries({ queryKey: queryKeys.securityPosture });
      toastSuccess("MFA enabled successfully.");
      void navigate({ to: "/settings/security" });
    },
    onError: toastError,
  });

  const onSubmit = handleSubmit((values) => {
    confirmMutation.mutate(values.code);
  });

  // ---------------------------------------------------------------------------
  // Clipboard helpers (must be inside click handlers for Chromium to allow)
  // ---------------------------------------------------------------------------

  function copyUri() {
    if (!enrollment) return;
    navigator.clipboard.writeText(enrollment.provisioning_uri).then(
      () => toastSuccess("Secret URI copied to clipboard."),
      () => toastError({ message: "Clipboard copy failed." })
    );
  }

  function copyCodes() {
    if (!enrollment) return;
    const text = enrollment.recovery_codes.join("\n");
    navigator.clipboard.writeText(text).then(
      () => toastSuccess("Recovery codes copied to clipboard."),
      () => toastError({ message: "Clipboard copy failed." })
    );
  }

  function downloadCodes() {
    if (!enrollment) return;
    const text = [
      "DFARS Desktop — MFA Recovery Codes",
      "Keep these codes safe. Each can only be used once.",
      "",
      ...enrollment.recovery_codes,
    ].join("\n");
    const blob = new Blob([text], { type: "text/plain" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = "dfars-recovery-codes.txt";
    a.click();
    URL.revokeObjectURL(url);
  }

  // ---------------------------------------------------------------------------
  // Render states
  // ---------------------------------------------------------------------------

  if (isLoading) {
    return (
      <div className="flex min-h-screen items-center justify-center bg-background">
        <p className="text-muted-foreground">Generating MFA enrollment...</p>
      </div>
    );
  }

  if (error || !enrollment) {
    return (
      <div className="flex min-h-screen items-center justify-center bg-background p-8">
        <Alert variant="destructive" className="max-w-md">
          <AlertDescription>
            Failed to start MFA enrollment. Please try again from the security
            settings page.
          </AlertDescription>
        </Alert>
      </div>
    );
  }

  return (
    <div className="flex min-h-screen items-center justify-center bg-background p-8">
      <Card className="w-full max-w-lg">
        <CardHeader>
          <div className="flex items-center gap-2">
            <ShieldPlus className="h-5 w-5 text-primary" />
            <CardTitle>Enable Two-Factor Authentication</CardTitle>
          </div>
          <CardDescription>
            Follow the steps below to add a second factor to your account.
          </CardDescription>
        </CardHeader>

        <CardContent className="flex flex-col gap-6">
          {/* Step 1: QR Code */}
          <section className="flex flex-col gap-3">
            <div className="flex items-center gap-2">
              <Badge variant="secondary">Step 1</Badge>
              <span className="text-sm font-medium">
                Scan the QR code in your authenticator app
              </span>
            </div>
            <ol className="list-decimal list-inside text-sm text-muted-foreground space-y-1 ml-1">
              <li>Open Google Authenticator, Authy, 1Password, or Bitwarden</li>
              <li>Tap "Add account" or the + icon</li>
              <li>Scan the QR code below — or enter the URI manually</li>
            </ol>

            <div className="flex justify-center">
              <div className="rounded-lg border bg-white p-3">
                <QRCodeSVG
                  value={enrollment.provisioning_uri}
                  size={200}
                  level="M"
                />
              </div>
            </div>

            <div className="flex flex-col gap-1.5">
              <Label htmlFor="provisioning-uri" className="text-xs text-muted-foreground">
                Manual entry URI (if you cannot scan the QR code)
              </Label>
              <div className="flex gap-2">
                <Input
                  id="provisioning-uri"
                  readOnly
                  value={enrollment.provisioning_uri}
                  className="font-mono text-xs"
                />
                <Button type="button" variant="outline" size="icon" onClick={copyUri}>
                  <Copy className="h-4 w-4" />
                  <span className="sr-only">Copy URI</span>
                </Button>
              </div>
            </div>
          </section>

          <Separator />

          {/* Step 2: Recovery codes */}
          <section className="flex flex-col gap-3">
            <div className="flex items-center gap-2">
              <Badge variant="secondary">Step 2</Badge>
              <span className="text-sm font-medium">
                Save your recovery codes
              </span>
            </div>

            <Alert className="border-amber-500/50 bg-amber-500/10">
              <AlertDescription className="text-amber-700 dark:text-amber-400">
                <strong>These codes are shown once and never again.</strong>{" "}
                Save them somewhere safe. Each code can only be used once to
                sign in if you lose access to your authenticator app.
              </AlertDescription>
            </Alert>

            <div className="rounded-md border bg-muted/40 p-3">
              <ul className="grid grid-cols-2 gap-1">
                {enrollment.recovery_codes.map((code, i) => (
                  <li
                    key={i}
                    className="font-mono text-sm text-center py-0.5 select-all"
                  >
                    {code}
                  </li>
                ))}
              </ul>
            </div>

            <div className="flex gap-2">
              <Button type="button" variant="outline" size="sm" onClick={copyCodes}>
                <Copy className="h-4 w-4" />
                Copy codes
              </Button>
              <Button type="button" variant="outline" size="sm" onClick={downloadCodes}>
                <Download className="h-4 w-4" />
                Download .txt
              </Button>
            </div>
          </section>

          <Separator />

          {/* Step 3: Confirm */}
          <section className="flex flex-col gap-3">
            <div className="flex items-center gap-2">
              <Badge variant="secondary">Step 3</Badge>
              <span className="text-sm font-medium">
                Confirm with a code from your app
              </span>
            </div>

            <form onSubmit={onSubmit} className="flex flex-col gap-3">
              <div className="flex flex-col gap-1.5">
                <Label htmlFor="confirm-code">
                  Enter the 6-digit code from your authenticator
                </Label>
                <Input
                  id="confirm-code"
                  type="text"
                  inputMode="numeric"
                  autoComplete="one-time-code"
                  placeholder="000000"
                  className="text-center font-mono text-xl tracking-widest max-w-[160px]"
                  {...register("code")}
                />
                {errors.code && (
                  <p className="text-sm text-destructive">
                    {errors.code.message}
                  </p>
                )}
                <p className="text-xs text-muted-foreground">
                  Codes refresh every 30 seconds. If verification fails, wait
                  for the next code.
                </p>
              </div>

              <div className="flex gap-2">
                <Button
                  type="submit"
                  disabled={confirmMutation.isPending}
                >
                  {confirmMutation.isPending ? "Verifying..." : "Verify & Enable MFA"}
                </Button>
                <Button
                  type="button"
                  variant="outline"
                  onClick={() => void navigate({ to: "/settings/security" })}
                >
                  Cancel
                </Button>
              </div>
            </form>
          </section>
        </CardContent>
      </Card>
    </div>
  );
}
