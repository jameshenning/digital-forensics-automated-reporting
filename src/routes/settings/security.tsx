/**
 * Security settings page.
 *
 * Protected route (requireAuthBeforeLoad).
 *
 * Sections:
 *   - Security posture warning banner (SEC-1 SHOULD-DO 6)
 *   - Current user + MFA status + enroll/disable buttons
 *   - Recovery codes remaining count + low-code warning
 *   - Change password dialog (Shadcn Dialog)
 *   - API tokens list + create-token dialog (plaintext shown once)
 */

import {
  createFileRoute,
  Link,
} from "@tanstack/react-router";
import {
  useQuery,
  useMutation,
  useQueryClient,
} from "@tanstack/react-query";
import { useForm } from "react-hook-form";
import { zodResolver } from "@hookform/resolvers/zod";
import { z } from "zod";
import { useState } from "react";
import {
  ShieldCheck,
  ShieldOff,
  KeyRound,
  Plus,
  Trash2,
  Copy,
  AlertTriangle,
  ShieldAlert,
  RefreshCw,
  ArrowDownToLine,
} from "lucide-react";

import {
  authChangePassword,
  authMfaDisable,
  authTokensList,
  authTokensCreate,
  authTokensRevoke,
  settingsGetSecurityPosture,
  settingsCheckForUpdates,
} from "@/lib/bindings";
import type { UpdateCheckResult } from "@/lib/bindings";
import { useSession } from "@/lib/session";
import { getToken } from "@/lib/session";
import { queryKeys } from "@/lib/query";
import { toastError, toastSuccess } from "@/lib/error-toast";
import { requireAuthBeforeLoad } from "@/lib/auth-guard";
import { openUrl } from "@tauri-apps/plugin-opener";

import { SettingsHeader } from "@/components/settings-header";
import { Button } from "@/components/ui/button";
import {
  Card,
  CardContent,
  CardHeader,
  CardTitle,
  CardDescription,
} from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Badge } from "@/components/ui/badge";
import { Alert, AlertDescription } from "@/components/ui/alert";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
  DialogTrigger,
} from "@/components/ui/dialog";

export const Route = createFileRoute("/settings/security")({
  beforeLoad: requireAuthBeforeLoad,
  component: SecurityPage,
});

// ---------------------------------------------------------------------------
// Validation schemas
// ---------------------------------------------------------------------------

const changePasswordSchema = z
  .object({
    old_password: z.string().min(1, "Current password is required"),
    new_password: z
      .string()
      .min(10, "New password must be at least 10 characters")
      .max(1024, "Password is too long"),
    confirm_password: z.string(),
  })
  .refine((d) => d.new_password === d.confirm_password, {
    message: "Passwords do not match",
    path: ["confirm_password"],
  });

const disableMfaSchema = z.object({
  password: z.string().min(1, "Password is required to disable MFA"),
});

const createTokenSchema = z.object({
  name: z
    .string()
    .min(1, "Token name is required")
    .max(100, "Token name is too long"),
});

type ChangePasswordValues = z.infer<typeof changePasswordSchema>;
type DisableMfaValues = z.infer<typeof disableMfaSchema>;
type CreateTokenValues = z.infer<typeof createTokenSchema>;

// ---------------------------------------------------------------------------
// Sub-components
// ---------------------------------------------------------------------------

function ChangePasswordDialog() {
  const [open, setOpen] = useState(false);
  const {
    register,
    handleSubmit,
    reset,
    formState: { errors },
  } = useForm<ChangePasswordValues>({
    resolver: zodResolver(changePasswordSchema),
  });

  const mutation = useMutation({
    mutationFn: (values: ChangePasswordValues) => {
      const token = getToken();
      if (!token) throw new Error("No session token");
      return authChangePassword({
        token,
        old_password: values.old_password,
        new_password: values.new_password,
      });
    },
    onSuccess: () => {
      toastSuccess("Password changed successfully.");
      reset();
      setOpen(false);
    },
    onError: toastError,
  });

  return (
    <Dialog open={open} onOpenChange={setOpen}>
      <DialogTrigger asChild>
        <Button variant="outline" size="sm">
          <KeyRound className="h-4 w-4" />
          Change Password
        </Button>
      </DialogTrigger>
      <DialogContent>
        <DialogHeader>
          <DialogTitle>Change Password</DialogTitle>
          <DialogDescription>
            Enter your current password and a new one. Minimum 12 characters.
          </DialogDescription>
        </DialogHeader>
        <form
          onSubmit={handleSubmit((v) => mutation.mutate(v))}
          className="flex flex-col gap-4"
        >
          <div className="flex flex-col gap-1.5">
            <Label htmlFor="cp-old">Current password</Label>
            <Input
              id="cp-old"
              type="password"
              autoComplete="current-password"
              {...register("old_password")}
            />
            {errors.old_password && (
              <p className="text-sm text-destructive">
                {errors.old_password.message}
              </p>
            )}
          </div>
          <div className="flex flex-col gap-1.5">
            <Label htmlFor="cp-new">New password</Label>
            <Input
              id="cp-new"
              type="password"
              autoComplete="new-password"
              {...register("new_password")}
            />
            {errors.new_password && (
              <p className="text-sm text-destructive">
                {errors.new_password.message}
              </p>
            )}
          </div>
          <div className="flex flex-col gap-1.5">
            <Label htmlFor="cp-confirm">Confirm new password</Label>
            <Input
              id="cp-confirm"
              type="password"
              autoComplete="new-password"
              {...register("confirm_password")}
            />
            {errors.confirm_password && (
              <p className="text-sm text-destructive">
                {errors.confirm_password.message}
              </p>
            )}
          </div>
          <DialogFooter>
            <Button
              type="button"
              variant="outline"
              onClick={() => { setOpen(false); reset(); }}
            >
              Cancel
            </Button>
            <Button type="submit" disabled={mutation.isPending}>
              {mutation.isPending ? "Saving..." : "Change Password"}
            </Button>
          </DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  );
}

function DisableMfaDialog() {
  const [open, setOpen] = useState(false);
  const queryClient = useQueryClient();
  const {
    register,
    handleSubmit,
    reset,
    formState: { errors },
  } = useForm<DisableMfaValues>({
    resolver: zodResolver(disableMfaSchema),
  });

  const mutation = useMutation({
    mutationFn: (values: DisableMfaValues) => {
      const token = getToken();
      if (!token) throw new Error("No session token");
      return authMfaDisable({ token, password: values.password });
    },
    onSuccess: () => {
      void queryClient.invalidateQueries({ queryKey: queryKeys.currentUser });
      void queryClient.invalidateQueries({ queryKey: queryKeys.securityPosture });
      toastSuccess("MFA disabled.");
      reset();
      setOpen(false);
    },
    onError: toastError,
  });

  return (
    <Dialog open={open} onOpenChange={setOpen}>
      <DialogTrigger asChild>
        <Button variant="destructive" size="sm">
          <ShieldOff className="h-4 w-4" />
          Disable MFA
        </Button>
      </DialogTrigger>
      <DialogContent>
        <DialogHeader>
          <DialogTitle>Disable Multi-Factor Authentication</DialogTitle>
          <DialogDescription>
            Confirm your password to disable MFA. Your recovery codes will
            also be revoked.
          </DialogDescription>
        </DialogHeader>
        <form
          onSubmit={handleSubmit((v) => mutation.mutate(v))}
          className="flex flex-col gap-4"
        >
          <div className="flex flex-col gap-1.5">
            <Label htmlFor="dm-password">Current password</Label>
            <Input
              id="dm-password"
              type="password"
              autoComplete="current-password"
              autoFocus
              {...register("password")}
            />
            {errors.password && (
              <p className="text-sm text-destructive">
                {errors.password.message}
              </p>
            )}
          </div>
          <DialogFooter>
            <Button
              type="button"
              variant="outline"
              onClick={() => { setOpen(false); reset(); }}
            >
              Cancel
            </Button>
            <Button
              type="submit"
              variant="destructive"
              disabled={mutation.isPending}
            >
              {mutation.isPending ? "Disabling..." : "Disable MFA"}
            </Button>
          </DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  );
}

interface CreateTokenDialogProps {
  sessionToken: string;
}

function CreateTokenDialog({ sessionToken }: CreateTokenDialogProps) {
  const [open, setOpen] = useState(false);
  const [plaintext, setPlaintext] = useState<string | null>(null);
  const queryClient = useQueryClient();

  const {
    register,
    handleSubmit,
    reset,
    formState: { errors },
  } = useForm<CreateTokenValues>({
    resolver: zodResolver(createTokenSchema),
  });

  const mutation = useMutation({
    mutationFn: (values: CreateTokenValues) =>
      authTokensCreate({ token: sessionToken, name: values.name }),
    onSuccess: (newToken) => {
      void queryClient.invalidateQueries({ queryKey: queryKeys.tokensList });
      setPlaintext(newToken.plaintext);
      reset();
    },
    onError: toastError,
  });

  function copyPlaintext() {
    if (!plaintext) return;
    navigator.clipboard.writeText(plaintext).then(
      () => toastSuccess("Token copied to clipboard."),
      () => toastError({ message: "Clipboard copy failed." })
    );
  }

  function handleClose(isOpen: boolean) {
    if (!isOpen) {
      setPlaintext(null);
      reset();
    }
    setOpen(isOpen);
  }

  return (
    <Dialog open={open} onOpenChange={handleClose}>
      <DialogTrigger asChild>
        <Button size="sm">
          <Plus className="h-4 w-4" />
          Create Token
        </Button>
      </DialogTrigger>
      <DialogContent>
        <DialogHeader>
          <DialogTitle>Create API Token</DialogTitle>
          <DialogDescription>
            Bearer tokens for the DFARS REST API. The plaintext is shown only
            once at creation.
          </DialogDescription>
        </DialogHeader>

        {plaintext ? (
          <div className="flex flex-col gap-4">
            <Alert className="border-amber-500/50 bg-amber-500/10">
              <AlertDescription className="text-amber-700 dark:text-amber-400">
                <strong>Copy this token now.</strong> It will not be shown
                again.
              </AlertDescription>
            </Alert>
            <div className="flex gap-2">
              <Input
                readOnly
                value={plaintext}
                className="font-mono text-xs"
              />
              <Button type="button" variant="outline" size="icon" onClick={copyPlaintext}>
                <Copy className="h-4 w-4" />
                <span className="sr-only">Copy token</span>
              </Button>
            </div>
            <DialogFooter>
              <Button onClick={() => handleClose(false)}>Done</Button>
            </DialogFooter>
          </div>
        ) : (
          <form
            onSubmit={handleSubmit((v) => mutation.mutate(v))}
            className="flex flex-col gap-4"
          >
            <div className="flex flex-col gap-1.5">
              <Label htmlFor="token-name">Token name</Label>
              <Input
                id="token-name"
                type="text"
                placeholder="e.g. Agent Zero Plugin"
                autoFocus
                {...register("name")}
              />
              {errors.name && (
                <p className="text-sm text-destructive">{errors.name.message}</p>
              )}
            </div>
            <DialogFooter>
              <Button
                type="button"
                variant="outline"
                onClick={() => handleClose(false)}
              >
                Cancel
              </Button>
              <Button type="submit" disabled={mutation.isPending}>
                {mutation.isPending ? "Creating..." : "Generate Token"}
              </Button>
            </DialogFooter>
          </form>
        )}
      </DialogContent>
    </Dialog>
  );
}

// ---------------------------------------------------------------------------
// Updates section
// ---------------------------------------------------------------------------

const GITHUB_RELEASES_URL =
  "https://github.com/jameshenning/digital-forensics-automated-reporting/releases";

/**
 * Pill component for displaying the update-check result inline.
 * Colors match UpdateStatus semantics.
 */
function UpdateStatusPill({
  result,
  checkedAt,
}: {
  result: UpdateCheckResult;
  checkedAt: Date;
}) {
  const pillClasses: Record<string, string> = {
    UpToDate:
      "inline-flex items-center gap-1.5 rounded-full px-2.5 py-0.5 text-xs font-medium bg-green-500/15 text-green-700 dark:text-green-400 border border-green-500/30",
    UpdateAvailable:
      "inline-flex items-center gap-1.5 rounded-full px-2.5 py-0.5 text-xs font-medium bg-amber-500/15 text-amber-700 dark:text-amber-400 border border-amber-500/30",
    NotConfigured:
      "inline-flex items-center gap-1.5 rounded-full px-2.5 py-0.5 text-xs font-medium bg-muted text-muted-foreground border",
    NetworkError:
      "inline-flex items-center gap-1.5 rounded-full px-2.5 py-0.5 text-xs font-medium bg-destructive/15 text-destructive border border-destructive/30",
  };

  const labelMap: Record<string, string> = {
    UpToDate: "You're on the latest version",
    UpdateAvailable: `Update available: v${result.available_version ?? "?"}`,
    NotConfigured: "Update server not configured",
    NetworkError: "Network error — try again later",
  };

  return (
    <div className="flex flex-col gap-2">
      <div className="flex flex-wrap items-center gap-3">
        <span className={pillClasses[result.status]}>
          {labelMap[result.status]}
        </span>
        <span className="text-xs text-muted-foreground">
          Checked at {checkedAt.toLocaleTimeString()}
        </span>
      </div>

      {result.status === "UpdateAvailable" && (
        <Button
          size="sm"
          className="w-fit"
          onClick={() => void openUrl(GITHUB_RELEASES_URL)}
        >
          <ArrowDownToLine className="h-4 w-4" />
          Download from GitHub Releases
        </Button>
      )}

      {result.status === "NotConfigured" && (
        <p className="text-xs text-muted-foreground">
          Auto-update hosting is not configured for v2.0.0. Download newer
          versions manually from{" "}
          <button
            type="button"
            className="underline underline-offset-2 hover:text-foreground transition-colors"
            onClick={() => void openUrl(GITHUB_RELEASES_URL)}
          >
            GitHub Releases
          </button>
          .
        </p>
      )}
    </div>
  );
}

function UpdatesSection() {
  const token = getToken() ?? "";
  const [checkResult, setCheckResult] = useState<UpdateCheckResult | null>(
    null
  );
  const [checkedAt, setCheckedAt] = useState<Date | null>(null);

  const checkMutation = useMutation({
    mutationFn: () => settingsCheckForUpdates({ token }),
    onSuccess: (result) => {
      setCheckResult(result);
      setCheckedAt(new Date());
    },
    onError: (err) => {
      // Surface transport-level errors that didn't reach the Rust handler.
      // The Rust handler itself returns UpdateCheckResult, not an error,
      // so this path is only for Tauri IPC failures.
      toastError(err);
    },
  });

  return (
    <Card>
      <CardHeader>
        <CardTitle className="flex items-center gap-2 text-base">
          <RefreshCw className="h-4 w-4" />
          Updates
        </CardTitle>
        <CardDescription>
          Check for new versions of DFARS Desktop. Automatic background checks
          are disabled by design — forensic tools should not produce unexpected
          outbound traffic. Click the button below when you want to check.
        </CardDescription>
      </CardHeader>
      <CardContent className="flex flex-col gap-4">
        <div className="flex items-center gap-3">
          <Button
            size="sm"
            variant="outline"
            disabled={checkMutation.isPending}
            onClick={() => checkMutation.mutate()}
          >
            {checkMutation.isPending ? (
              <>
                <RefreshCw className="h-4 w-4 animate-spin" />
                Checking for updates…
              </>
            ) : (
              <>
                <RefreshCw className="h-4 w-4" />
                Check for updates
              </>
            )}
          </Button>
        </div>

        {checkResult !== null && checkedAt !== null && (
          <UpdateStatusPill result={checkResult} checkedAt={checkedAt} />
        )}
      </CardContent>
    </Card>
  );
}

// ---------------------------------------------------------------------------
// Main page
// ---------------------------------------------------------------------------

function SecurityPage() {
  const { session } = useSession();
  const queryClient = useQueryClient();

  const token = getToken() ?? "";

  const { data: posture } = useQuery({
    queryKey: queryKeys.securityPosture,
    queryFn: () => settingsGetSecurityPosture({ token }),
    enabled: !!token,
    refetchOnWindowFocus: false,
  });

  const { data: apiTokens } = useQuery({
    queryKey: queryKeys.tokensList,
    queryFn: () => authTokensList({ token }),
    enabled: !!token,
    refetchOnWindowFocus: false,
  });

  const revokeMutation = useMutation({
    mutationFn: (id: string) => authTokensRevoke({ token, id }),
    onSuccess: () => {
      void queryClient.invalidateQueries({ queryKey: queryKeys.tokensList });
      toastSuccess("Token revoked.");
    },
    onError: toastError,
  });

  if (!session) return null;

  return (
    <div className="min-h-screen bg-background">
      <SettingsHeader username={session.username} />

      <main className="mx-auto max-w-3xl px-6 py-8 flex flex-col gap-6">
        {/* Security posture warning banner (SEC-1 SHOULD-DO 6) */}
        {posture && posture.key_source !== "keyring" && (
          <Alert className="border-amber-500/50 bg-amber-500/10">
            <ShieldAlert className="h-4 w-4 text-amber-600" />
            <AlertDescription className="text-amber-700 dark:text-amber-400">
              <strong>Encryption key stored in file, not Windows Credential Manager.</strong>{" "}
              Your encryption key is stored in a file ({posture.key_source === "keyfile" ? "%APPDATA%\\DFARS\\.keyfile" : "a new generated file"}),
              which is less secure than Windows Credential Manager. Consider upgrading to keyring
              storage by re-running the app after ensuring Windows Credential Manager is available.
            </AlertDescription>
          </Alert>
        )}

        {/* Password section */}
        <Card>
          <CardHeader>
            <CardTitle className="flex items-center gap-2 text-base">
              <KeyRound className="h-4 w-4" />
              Password
            </CardTitle>
            <CardDescription>
              Signed in as{" "}
              <code className="font-mono">{session.username}</code>. Your
              password is hashed locally with Argon2id.
            </CardDescription>
          </CardHeader>
          <CardContent>
            <ChangePasswordDialog />
          </CardContent>
        </Card>

        {/* MFA section */}
        <Card>
          <CardHeader>
            <CardTitle className="flex items-center gap-2 text-base">
              <ShieldCheck className="h-4 w-4" />
              Two-Factor Authentication (TOTP)
            </CardTitle>
          </CardHeader>
          <CardContent className="flex flex-col gap-4">
            {posture?.mfa_enabled || session.mfa_enabled ? (
              <>
                <div className="flex items-center gap-3">
                  <Badge className="bg-green-500/20 text-green-700 dark:text-green-400 border-green-500/30">
                    Enabled
                  </Badge>
                  <span className="text-sm text-muted-foreground">
                    {posture?.recovery_codes_remaining ?? 0} unused recovery
                    code
                    {(posture?.recovery_codes_remaining ?? 0) !== 1 ? "s" : ""}{" "}
                    remaining
                  </span>
                </div>

                <p className="text-sm text-muted-foreground">
                  Each sign-in requires both your password and a 6-digit code
                  from your authenticator app. Recovery codes let you sign in
                  if you lose your device.
                </p>

                {(posture?.recovery_codes_remaining ?? 10) < 3 && (
                  <Alert className="border-amber-500/50 bg-amber-500/10">
                    <AlertTriangle className="h-4 w-4 text-amber-600" />
                    <AlertDescription className="text-amber-700 dark:text-amber-400">
                      Only {posture?.recovery_codes_remaining} recovery code
                      {posture?.recovery_codes_remaining !== 1 ? "s" : ""}{" "}
                      left. Disable and re-enroll MFA to generate a fresh
                      batch.
                    </AlertDescription>
                  </Alert>
                )}

                <DisableMfaDialog />
              </>
            ) : (
              <>
                <div className="flex items-center gap-2">
                  <Badge variant="secondary">Not enabled</Badge>
                </div>
                <p className="text-sm text-muted-foreground">
                  Add a second factor to protect your account even if your
                  password is leaked. Use any TOTP-compatible authenticator app
                  (Google Authenticator, Microsoft Authenticator, Authy,
                  1Password, Bitwarden).
                </p>
                <Button asChild>
                  <Link to="/auth/enroll">
                    <ShieldCheck className="h-4 w-4" />
                    Enable MFA
                  </Link>
                </Button>
              </>
            )}
          </CardContent>
        </Card>

        {/* API Tokens section */}
        <Card>
          <CardHeader>
            <div className="flex items-center justify-between">
              <div>
                <CardTitle className="flex items-center gap-2 text-base">
                  <KeyRound className="h-4 w-4" />
                  API Tokens
                </CardTitle>
                <CardDescription>
                  Bearer tokens for the DFARS REST API at{" "}
                  <code>/api/v1</code>. Use these to let Agent Zero or other
                  tools push case data into DFARS. Plaintext is shown only
                  once at creation.
                </CardDescription>
              </div>
              <CreateTokenDialog sessionToken={token} />
            </div>
          </CardHeader>
          <CardContent>
            {!apiTokens || apiTokens.length === 0 ? (
              <p className="text-sm text-muted-foreground italic">
                No API tokens yet.
              </p>
            ) : (
              <div className="rounded-md border overflow-hidden">
                <table className="w-full text-sm">
                  <thead className="bg-muted/50">
                    <tr>
                      <th className="text-left px-4 py-2 font-medium">Name</th>
                      <th className="text-left px-4 py-2 font-medium">Preview</th>
                      <th className="text-left px-4 py-2 font-medium">Created</th>
                      <th className="text-left px-4 py-2 font-medium">Last Used</th>
                      <th className="px-4 py-2"></th>
                    </tr>
                  </thead>
                  <tbody>
                    {apiTokens.map((t) => (
                      <tr key={t.id} className="border-t">
                        <td className="px-4 py-2">{t.name}</td>
                        <td className="px-4 py-2">
                          <code className="font-mono text-xs">{t.preview}…</code>
                        </td>
                        <td className="px-4 py-2 text-muted-foreground text-xs">
                          {t.created_at.slice(0, 16)}
                        </td>
                        <td className="px-4 py-2 text-muted-foreground text-xs">
                          {t.last_used_at ? t.last_used_at.slice(0, 16) : "—"}
                        </td>
                        <td className="px-4 py-2">
                          <Button
                            variant="ghost"
                            size="sm"
                            className="text-destructive hover:text-destructive"
                            disabled={revokeMutation.isPending}
                            onClick={() => {
                              if (
                                window.confirm(
                                  `Revoke token "${t.name}"? Any integration using it will stop working.`
                                )
                              ) {
                                revokeMutation.mutate(t.id);
                              }
                            }}
                          >
                            <Trash2 className="h-4 w-4" />
                            <span className="sr-only">Revoke</span>
                          </Button>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </CardContent>
        </Card>

        {/* Updates section (Phase 6 — SEC-8 SHOULD-DO 3) */}
        <UpdatesSection />
      </main>
    </div>
  );
}
