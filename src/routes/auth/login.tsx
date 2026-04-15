/**
 * Login screen — replaces the Phase 0 placeholder.
 *
 * Flow:
 *   - Success (no MFA):  store token → /dashboard
 *   - MfaRequired:       navigate to /auth/mfa?pending_token=...
 *   - AccountLocked:     show countdown, disable submit until it reaches zero
 *   - Any other error:   sonner toast
 *
 * Session token is stored in sessionStorage via setToken().
 * NO HTTP cookies anywhere in this file.
 */

import { createFileRoute, useNavigate, Link } from "@tanstack/react-router";
import { useForm } from "react-hook-form";
import { zodResolver } from "@hookform/resolvers/zod";
import { z } from "zod";
import { useMutation, useQueryClient } from "@tanstack/react-query";
import { useEffect, useRef, useState } from "react";
import { ShieldAlert, LockKeyhole } from "lucide-react";

import { authLogin } from "@/lib/bindings";
import { setToken } from "@/lib/session";
import { queryKeys } from "@/lib/query";
import { toastError } from "@/lib/error-toast";

import { Button } from "@/components/ui/button";
import {
  Card,
  CardContent,
  CardDescription,
  CardFooter,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Alert, AlertDescription } from "@/components/ui/alert";

export const Route = createFileRoute("/auth/login")({
  component: LoginPage,
});

// ---------------------------------------------------------------------------
// Validation schema
// ---------------------------------------------------------------------------

const loginSchema = z.object({
  username: z.string().min(1, "Username is required"),
  password: z.string().min(1, "Password is required"),
});

type LoginFormValues = z.infer<typeof loginSchema>;

// ---------------------------------------------------------------------------
// Lockout countdown hook
// ---------------------------------------------------------------------------

function useCountdown(initialSeconds: number | null) {
  const [remaining, setRemaining] = useState<number | null>(initialSeconds);
  const intervalRef = useRef<ReturnType<typeof setInterval> | null>(null);

  useEffect(() => {
    if (initialSeconds === null || initialSeconds <= 0) {
      setRemaining(null);
      return;
    }
    setRemaining(initialSeconds);
    intervalRef.current = setInterval(() => {
      setRemaining((prev) => {
        if (prev === null || prev <= 1) {
          if (intervalRef.current) clearInterval(intervalRef.current);
          return null;
        }
        return prev - 1;
      });
    }, 1000);
    return () => {
      if (intervalRef.current) clearInterval(intervalRef.current);
    };
  }, [initialSeconds]);

  return remaining;
}

function humanizeLockout(seconds: number): string {
  const mins = Math.floor(seconds / 60);
  const secs = seconds % 60;
  if (mins > 0) {
    return `${mins} minute${mins !== 1 ? "s" : ""} ${secs} second${secs !== 1 ? "s" : ""}`;
  }
  return `${secs} second${secs !== 1 ? "s" : ""}`;
}

// ---------------------------------------------------------------------------
// Component
// ---------------------------------------------------------------------------

function LoginPage() {
  const navigate = useNavigate();
  const queryClient = useQueryClient();
  const [lockoutSeconds, setLockoutSeconds] = useState<number | null>(null);
  const countdown = useCountdown(lockoutSeconds);

  const {
    register,
    handleSubmit,
    formState: { errors },
  } = useForm<LoginFormValues>({
    resolver: zodResolver(loginSchema),
  });

  const mutation = useMutation({
    mutationFn: (values: LoginFormValues) =>
      authLogin({ username: values.username, password: values.password }),
    onSuccess: (result) => {
      if (result.status === "Success" && result.session) {
        setToken(result.session.token);
        queryClient.setQueryData(queryKeys.currentUser, result.session);
        void navigate({ to: "/dashboard" });
      } else if (result.status === "MfaRequired" && result.pending_token) {
        void navigate({
          to: "/auth/mfa",
          search: { pending_token: result.pending_token },
        });
      } else if (result.status === "AccountLocked") {
        setLockoutSeconds(result.seconds_remaining ?? 300);
      }
    },
    onError: (err: unknown) => {
      const appErr = err as { code?: string; seconds_remaining?: number };
      if (appErr?.code === "AccountLocked") {
        setLockoutSeconds(appErr.seconds_remaining ?? 300);
      } else {
        toastError(err);
      }
    },
  });

  const onSubmit = handleSubmit((values) => {
    mutation.mutate(values);
  });

  const isLocked = countdown !== null && countdown > 0;

  return (
    <div className="flex min-h-screen items-center justify-center bg-background p-8">
      <Card className="w-full max-w-sm">
        <CardHeader>
          <div className="flex items-center gap-2">
            <LockKeyhole className="h-5 w-5 text-primary" />
            <CardTitle>Sign In</CardTitle>
          </div>
          <CardDescription>DFARS Desktop</CardDescription>
        </CardHeader>

        <CardContent>
          {isLocked && (
            <Alert className="mb-4 border-destructive/50 bg-destructive/10">
              <ShieldAlert className="h-4 w-4 text-destructive" />
              <AlertDescription className="text-destructive">
                Account locked. Please wait{" "}
                <strong>{humanizeLockout(countdown)}</strong> before trying
                again.
              </AlertDescription>
            </Alert>
          )}

          <form onSubmit={onSubmit} className="flex flex-col gap-4">
            <div className="flex flex-col gap-1.5">
              <Label htmlFor="username">Username</Label>
              <Input
                id="username"
                type="text"
                autoFocus={!isLocked}
                autoComplete="username"
                disabled={isLocked}
                {...register("username")}
              />
              {errors.username && (
                <p className="text-sm text-destructive">
                  {errors.username.message}
                </p>
              )}
            </div>

            <div className="flex flex-col gap-1.5">
              <Label htmlFor="password">Password</Label>
              <Input
                id="password"
                type="password"
                autoComplete="current-password"
                disabled={isLocked}
                {...register("password")}
              />
              {errors.password && (
                <p className="text-sm text-destructive">
                  {errors.password.message}
                </p>
              )}
            </div>

            <Button
              type="submit"
              className="w-full"
              disabled={isLocked || mutation.isPending}
            >
              {mutation.isPending ? "Signing in..." : "Sign In"}
            </Button>
          </form>
        </CardContent>

        <CardFooter className="flex flex-col items-start gap-2">
          <p className="text-xs text-muted-foreground">
            DFARS Desktop stores credentials locally. After 5 failed attempts,
            the account is locked for 5 minutes.
          </p>
          <p className="text-xs text-muted-foreground">
            First-time install?{" "}
            <Link
              to="/auth/setup"
              className="font-medium text-primary underline underline-offset-2 hover:text-primary/80"
            >
              Set up your account
            </Link>
          </p>
        </CardFooter>
      </Card>
    </div>
  );
}
