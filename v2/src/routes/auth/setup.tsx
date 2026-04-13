/**
 * First-run setup screen.
 *
 * Renders when no account exists yet.  On submit, calls auth_setup_first_run.
 * If UserAlreadyExists is returned (race or repeat visit), redirects to /auth/login.
 * On success, stores the session token and redirects to /dashboard.
 *
 * Password policy: minimum 12 characters (spec §7, v2-migration-spec.md).
 */

import { createFileRoute, useNavigate } from "@tanstack/react-router";
import { useForm } from "react-hook-form";
import { zodResolver } from "@hookform/resolvers/zod";
import { z } from "zod";
import { useMutation, useQueryClient } from "@tanstack/react-query";
import { ShieldCheck } from "lucide-react";

import { authSetupFirstRun } from "@/lib/bindings";
import { setToken } from "@/lib/session";
import { queryKeys } from "@/lib/query";
import { toastError, toastSuccess } from "@/lib/error-toast";

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

export const Route = createFileRoute("/auth/setup")({
  component: SetupPage,
});

// ---------------------------------------------------------------------------
// Validation schema
// ---------------------------------------------------------------------------

const setupSchema = z
  .object({
    username: z
      .string()
      .min(3, "Username must be at least 3 characters")
      .max(64, "Username must be at most 64 characters")
      .regex(
        /^[A-Za-z0-9._-]+$/,
        "Username may only contain letters, digits, '.', '_', or '-'"
      ),
    password: z
      .string()
      .min(10, "Password must be at least 10 characters")
      .max(1024, "Password is too long"),
    confirm_password: z.string(),
  })
  .refine((data) => data.password === data.confirm_password, {
    message: "Passwords do not match",
    path: ["confirm_password"],
  });

type SetupFormValues = z.infer<typeof setupSchema>;

// ---------------------------------------------------------------------------
// Component
// ---------------------------------------------------------------------------

function SetupPage() {
  const navigate = useNavigate();
  const queryClient = useQueryClient();

  const {
    register,
    handleSubmit,
    formState: { errors, isSubmitting },
  } = useForm<SetupFormValues>({
    resolver: zodResolver(setupSchema),
  });

  const mutation = useMutation({
    mutationFn: (values: SetupFormValues) =>
      authSetupFirstRun({
        username: values.username,
        password: values.password,
      }),
    onSuccess: (session) => {
      setToken(session.token);
      queryClient.setQueryData(queryKeys.currentUser, session);
      toastSuccess("Account created. Welcome to DFARS Desktop.");
      void navigate({ to: "/dashboard" });
    },
    onError: (err: unknown) => {
      const appErr = err as { code?: string };
      if (appErr?.code === "UserAlreadyExists") {
        void navigate({ to: "/auth/login" });
      } else {
        toastError(err);
      }
    },
  });

  const onSubmit = handleSubmit((values) => {
    mutation.mutate(values);
  });

  return (
    <div className="flex min-h-screen items-center justify-center bg-background p-8">
      <Card className="w-full max-w-md">
        <CardHeader>
          <div className="flex items-center gap-2">
            <ShieldCheck className="h-5 w-5 text-primary" />
            <CardTitle>Create Your Account</CardTitle>
          </div>
          <CardDescription>
            Welcome to DFARS Desktop. This one-time setup creates the account
            you will use to sign in. Your credentials are stored locally and
            never leave this machine.
          </CardDescription>
        </CardHeader>

        <CardContent>
          <form onSubmit={onSubmit} className="flex flex-col gap-4">
            <div className="flex flex-col gap-1.5">
              <Label htmlFor="username">Username</Label>
              <Input
                id="username"
                type="text"
                autoFocus
                autoComplete="username"
                {...register("username")}
              />
              {errors.username && (
                <p className="text-sm text-destructive">
                  {errors.username.message}
                </p>
              )}
              <p className="text-xs text-muted-foreground">
                3–64 characters. Letters, digits, <code>.</code>,{" "}
                <code>_</code>, <code>-</code>.
              </p>
            </div>

            <div className="flex flex-col gap-1.5">
              <Label htmlFor="password">Password</Label>
              <Input
                id="password"
                type="password"
                autoComplete="new-password"
                {...register("password")}
              />
              {errors.password && (
                <p className="text-sm text-destructive">
                  {errors.password.message}
                </p>
              )}
              <p className="text-xs text-muted-foreground">
                Minimum 12 characters. A passphrase is better than a short
                complex password.
              </p>
            </div>

            <div className="flex flex-col gap-1.5">
              <Label htmlFor="confirm_password">Confirm Password</Label>
              <Input
                id="confirm_password"
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

            <Alert variant="destructive" className="bg-destructive/10">
              <AlertDescription>
                <strong>No password recovery.</strong> If you forget this
                password and have not enabled multi-factor authentication, your
                forensic data cannot be recovered. Store it somewhere safe.
              </AlertDescription>
            </Alert>

            <Button
              type="submit"
              className="w-full"
              disabled={isSubmitting || mutation.isPending}
            >
              {mutation.isPending ? "Creating account..." : "Create Account & Continue"}
            </Button>
          </form>
        </CardContent>
      </Card>
    </div>
  );
}
