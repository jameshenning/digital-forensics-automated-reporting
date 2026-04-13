/**
 * MFA verify screen (TOTP or recovery code).
 *
 * Reads pending_token from typed search params — search params survive a
 * page refresh and avoid the ambiguity of location.state.
 *
 * On submit, calls auth_verify_mfa({ pending_token, code }).
 * On success, store session token and navigate to /dashboard.
 * On InvalidMfaCode, show inline error.
 * On NoRecoveryCodesRemaining, show a distinct banner + back-to-login link.
 */

import { createFileRoute, Link, useNavigate } from "@tanstack/react-router";
import { useForm } from "react-hook-form";
import { zodResolver } from "@hookform/resolvers/zod";
import { z } from "zod";
import { useMutation, useQueryClient } from "@tanstack/react-query";
import { useState } from "react";
import { ShieldCheck, AlertTriangle } from "lucide-react";

import { authVerifyMfa } from "@/lib/bindings";
import { setToken } from "@/lib/session";
import { queryKeys } from "@/lib/query";
import { toastError } from "@/lib/error-toast";

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

// ---------------------------------------------------------------------------
// Search param schema — typed by TanStack Router
// ---------------------------------------------------------------------------

const mfaSearchSchema = z.object({
  pending_token: z.string(),
});

export const Route = createFileRoute("/auth/mfa")({
  validateSearch: mfaSearchSchema,
  component: MfaPage,
});

// ---------------------------------------------------------------------------
// Form schemas
// ---------------------------------------------------------------------------

/** TOTP: exactly 6 digits (spaces stripped) */
const totpSchema = z.object({
  code: z
    .string()
    .transform((v) => v.replace(/\s/g, ""))
    .pipe(z.string().length(6, "TOTP code must be 6 digits").regex(/^\d+$/, "TOTP code must be digits only")),
});

/** Recovery code: xxxxx-xxxxx pattern */
const recoverySchema = z.object({
  code: z
    .string()
    .regex(
      /^[0-9a-fA-F]{5}-[0-9a-fA-F]{5}$/,
      "Recovery code format: xxxxx-xxxxx"
    ),
});

type TotpFormValues = z.infer<typeof totpSchema>;
type RecoveryFormValues = z.infer<typeof recoverySchema>;

// ---------------------------------------------------------------------------
// Component
// ---------------------------------------------------------------------------

function MfaPage() {
  const { pending_token } = Route.useSearch();
  const navigate = useNavigate();
  const queryClient = useQueryClient();
  const [useRecovery, setUseRecovery] = useState(false);
  const [noCodesRemaining, setNoCodesRemaining] = useState(false);
  const [invalidCode, setInvalidCode] = useState(false);

  const totpForm = useForm<TotpFormValues>({
    resolver: zodResolver(totpSchema),
  });

  const recoveryForm = useForm<RecoveryFormValues>({
    resolver: zodResolver(recoverySchema),
  });

  const mutation = useMutation({
    mutationFn: (code: string) =>
      authVerifyMfa({ pending_token, code }),
    onSuccess: (session) => {
      setToken(session.token);
      queryClient.setQueryData(queryKeys.currentUser, session);
      void navigate({ to: "/dashboard" });
    },
    onError: (err: unknown) => {
      const appErr = err as { code?: string };
      if (appErr?.code === "InvalidMfaCode") {
        setInvalidCode(true);
      } else if (appErr?.code === "NoRecoveryCodesRemaining") {
        setNoCodesRemaining(true);
      } else {
        toastError(err);
      }
    },
  });

  const onTotpSubmit = totpForm.handleSubmit((values) => {
    setInvalidCode(false);
    mutation.mutate(values.code);
  });

  const onRecoverySubmit = recoveryForm.handleSubmit((values) => {
    setInvalidCode(false);
    mutation.mutate(values.code);
  });

  function toggleMode() {
    setUseRecovery((prev) => !prev);
    setInvalidCode(false);
    totpForm.reset();
    recoveryForm.reset();
  }

  if (noCodesRemaining) {
    return (
      <div className="flex min-h-screen items-center justify-center bg-background p-8">
        <Card className="w-full max-w-sm">
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              <AlertTriangle className="h-5 w-5 text-destructive" />
              No Recovery Codes Left
            </CardTitle>
          </CardHeader>
          <CardContent className="flex flex-col gap-4">
            <Alert variant="destructive">
              <AlertDescription>
                All recovery codes have been used. You cannot sign in without a
                working authenticator app. Contact your administrator if you
                need to regain access.
              </AlertDescription>
            </Alert>
            <Button variant="outline" asChild>
              <Link to="/auth/login">Back to Sign In</Link>
            </Button>
          </CardContent>
        </Card>
      </div>
    );
  }

  return (
    <div className="flex min-h-screen items-center justify-center bg-background p-8">
      <Card className="w-full max-w-sm">
        <CardHeader>
          <div className="flex items-center gap-2">
            <ShieldCheck className="h-5 w-5 text-primary" />
            <CardTitle>Two-Factor Authentication</CardTitle>
          </div>
          <CardDescription>
            {useRecovery
              ? "Enter one of your recovery codes to continue."
              : "Enter the 6-digit code from your authenticator app to continue."}
          </CardDescription>
        </CardHeader>

        <CardContent className="flex flex-col gap-4">
          {!useRecovery ? (
            <form onSubmit={onTotpSubmit} className="flex flex-col gap-4">
              <div className="flex flex-col gap-1.5">
                <Label htmlFor="totp-code">Authenticator code</Label>
                <Input
                  id="totp-code"
                  type="text"
                  inputMode="numeric"
                  autoComplete="one-time-code"
                  placeholder="000000"
                  autoFocus
                  className="text-center font-mono text-xl tracking-widest"
                  {...totpForm.register("code")}
                />
                {totpForm.formState.errors.code && (
                  <p className="text-sm text-destructive">
                    {totpForm.formState.errors.code.message}
                  </p>
                )}
                {invalidCode && (
                  <p className="text-sm text-destructive">
                    Code not recognised. Check your authenticator app and try
                    again.
                  </p>
                )}
              </div>

              <Button
                type="submit"
                className="w-full"
                disabled={mutation.isPending}
              >
                {mutation.isPending ? "Verifying..." : "Verify & Sign In"}
              </Button>
            </form>
          ) : (
            <form onSubmit={onRecoverySubmit} className="flex flex-col gap-4">
              <div className="flex flex-col gap-1.5">
                <Label htmlFor="recovery-code">Recovery code</Label>
                <Input
                  id="recovery-code"
                  type="text"
                  autoComplete="off"
                  placeholder="xxxxx-xxxxx"
                  autoFocus
                  className="text-center font-mono"
                  {...recoveryForm.register("code")}
                />
                {recoveryForm.formState.errors.code && (
                  <p className="text-sm text-destructive">
                    {recoveryForm.formState.errors.code.message}
                  </p>
                )}
                {invalidCode && (
                  <p className="text-sm text-destructive">
                    Recovery code not recognised or already used.
                  </p>
                )}
                <p className="text-xs text-muted-foreground">
                  Each recovery code can only be used once.
                </p>
              </div>

              <Button
                type="submit"
                className="w-full"
                disabled={mutation.isPending}
              >
                {mutation.isPending ? "Verifying..." : "Verify & Sign In"}
              </Button>
            </form>
          )}

          <div className="flex flex-col items-center gap-2 text-sm">
            <button
              type="button"
              onClick={toggleMode}
              className="text-primary underline-offset-4 hover:underline"
            >
              {useRecovery
                ? "Use authenticator code instead"
                : "Use a recovery code instead"}
            </button>
            <Link
              to="/auth/login"
              className="text-muted-foreground hover:underline"
            >
              Cancel and sign out
            </Link>
          </div>
        </CardContent>
      </Card>
    </div>
  );
}
