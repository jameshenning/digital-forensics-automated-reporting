/**
 * SessionLockProvider — auto-lock after user inactivity.
 *
 * Monitors mouse/keyboard/touch events across the whole document.
 * After `IDLE_TIMEOUT_MS` of inactivity, a full-screen lock overlay
 * appears requiring password re-authentication (and MFA if enabled).
 *
 * The lock screen does NOT log the user out — the backend session
 * remains valid.  This gives the user a chance to unlock before the
 * backend's 30-minute inactivity expiry evicts the session.
 */

import React, { createContext, useContext, useEffect, useRef, useState, useCallback } from "react";
import { Timer } from "lucide-react";
import { useMutation } from "@tanstack/react-query";
import { LockKeyhole, ShieldAlert } from "lucide-react";

import { useQuery } from "@tanstack/react-query";
import { authLogin, authVerifyMfa, settingsGetIdleTimeout } from "@/lib/bindings";
import { useSession, getToken } from "@/lib/session";
import { queryKeys } from "@/lib/query";
import { toastError } from "@/lib/error-toast";
import type { SessionInfo } from "@/lib/bindings";

import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Alert, AlertDescription } from "@/components/ui/alert";

// ---------------------------------------------------------------------------
// Config
// ---------------------------------------------------------------------------

/** Default idle timeout before auto-lock — 5 minutes. */
const DEFAULT_IDLE_TIMEOUT_MS = 5 * 60 * 1000;

/** Events that count as user activity. */
const ACTIVITY_EVENTS = ["mousedown", "keydown", "touchstart", "scroll", "mousemove"];

// ---------------------------------------------------------------------------
// Context
// ---------------------------------------------------------------------------

interface SessionLockContextValue {
  /** Manually trigger the lock screen (e.g. from a menu). */
  lock: () => void;
  /** Reset the idle timer (e.g. after a successful protected action). */
  resetIdleTimer: () => void;
}

const SessionLockContext = createContext<SessionLockContextValue | null>(null);

export function useSessionLock(): SessionLockContextValue {
  const ctx = useContext(SessionLockContext);
  if (!ctx) {
    throw new Error("useSessionLock must be used inside SessionLockProvider");
  }
  return ctx;
}

// ---------------------------------------------------------------------------
// Provider
// ---------------------------------------------------------------------------

interface SessionLockProviderProps {
  children: React.ReactNode;
}

export function SessionLockProvider({ children }: SessionLockProviderProps) {
  const { session } = useSession();
  const [locked, setLocked] = useState(false);
  const [mfaToken, setMfaToken] = useState<string | null>(null);
  const timerRef = useRef<ReturnType<typeof setTimeout> | null>(null);
  const lastActivityRef = useRef<number>(Date.now());

  const isAuthenticated = !!session;
  const token = getToken() ?? "";

  // Fetch configured idle timeout from backend
  const { data: configuredTimeoutSeconds } = useQuery({
    queryKey: queryKeys.idleTimeout.settings,
    queryFn: () => settingsGetIdleTimeout({ token }),
    enabled: !!token,
    refetchOnWindowFocus: false,
  });

  const idleTimeoutMs =
    configuredTimeoutSeconds !== undefined
      ? configuredTimeoutSeconds * 1000
      : DEFAULT_IDLE_TIMEOUT_MS;

  const clearTimer = useCallback(() => {
    if (timerRef.current) {
      clearTimeout(timerRef.current);
      timerRef.current = null;
    }
  }, []);

  const startTimer = useCallback(() => {
    clearTimer();
    timerRef.current = setTimeout(() => {
      setLocked(true);
    }, idleTimeoutMs);
  }, [clearTimer, idleTimeoutMs]);

  const resetIdleTimer = useCallback(() => {
    if (!isAuthenticated || locked) return;
    lastActivityRef.current = Date.now();
    startTimer();
  }, [isAuthenticated, locked, startTimer]);

  const lock = useCallback(() => {
    if (!isAuthenticated) return;
    setLocked(true);
  }, [isAuthenticated]);

  // Listen for activity events
  useEffect(() => {
    if (!isAuthenticated || locked) {
      clearTimer();
      return;
    }

    const onActivity = () => {
      resetIdleTimer();
    };

    // Throttle mousemove to avoid excessive timer resets
    let throttleTimer: ReturnType<typeof setTimeout> | null = null;
    const onMouseMove = () => {
      if (throttleTimer) return;
      throttleTimer = setTimeout(() => {
        throttleTimer = null;
      }, 1000);
      resetIdleTimer();
    };

    ACTIVITY_EVENTS.forEach((evt) => {
      if (evt === "mousemove") {
        document.addEventListener(evt, onMouseMove);
      } else {
        document.addEventListener(evt, onActivity);
      }
    });

    startTimer();

    return () => {
      clearTimer();
      ACTIVITY_EVENTS.forEach((evt) => {
        if (evt === "mousemove") {
          document.removeEventListener(evt, onMouseMove);
        } else {
          document.removeEventListener(evt, onActivity);
        }
      });
      if (throttleTimer) clearTimeout(throttleTimer);
    };
  }, [isAuthenticated, locked, resetIdleTimer, startTimer, clearTimer]);

  const handleUnlock = useCallback(() => {
    setLocked(false);
    setMfaToken(null);
    startTimer();
  }, [startTimer]);

  return (
    <SessionLockContext.Provider value={{ lock, resetIdleTimer }}>
      {children}
      {locked && (
        <LockScreen
          session={session}
          mfaToken={mfaToken}
          onMfaRequired={setMfaToken}
          onUnlock={handleUnlock}
        />
      )}
    </SessionLockContext.Provider>
  );
}

// ---------------------------------------------------------------------------
// LockScreen
// ---------------------------------------------------------------------------

interface LockScreenProps {
  session: SessionInfo | null;
  mfaToken: string | null;
  onMfaRequired: (token: string) => void;
  onUnlock: () => void;
}

/** Backend session inactivity timeout in milliseconds (30 minutes). */
const BACKEND_SESSION_TIMEOUT_MS = 30 * 60 * 1000;

function humanizeMinutes(ms: number): string {
  if (ms <= 0) return "0m";
  const mins = Math.floor(ms / 60000);
  const secs = Math.floor((ms % 60000) / 1000);
  if (mins > 0) return `${mins}m ${secs}s`;
  return `${secs}s`;
}

function LockScreen({ session, mfaToken, onMfaRequired, onUnlock }: LockScreenProps) {
  const [password, setPassword] = useState("");
  const [mfaCode, setMfaCode] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [timeRemaining, setTimeRemaining] = useState(BACKEND_SESSION_TIMEOUT_MS);
  const intervalRef = useRef<ReturnType<typeof setInterval> | null>(null);

  const loginMutation = useMutation({
    mutationFn: () =>
      authLogin({
        username: session?.username ?? "",
        password,
      }),
    onSuccess: (result) => {
      if (result.status === "Success") {
        onUnlock();
      } else if (result.status === "MfaRequired" && result.pending_token) {
        setError(null);
        onMfaRequired(result.pending_token);
      } else if (result.status === "AccountLocked") {
        setError("Account is temporarily locked due to failed attempts.");
      }
    },
    onError: (err: unknown) => {
      const appErr = err as { code?: string; message?: string };
      if (appErr?.code === "AccountLocked") {
        setError("Account is temporarily locked due to failed attempts.");
      } else if (appErr?.code === "InvalidCredentials") {
        setError("Incorrect password.");
      } else {
        toastError(err);
      }
    },
  });

  const mfaMutation = useMutation({
    mutationFn: () =>
      authVerifyMfa({
        pending_token: mfaToken ?? "",
        code: mfaCode,
        use_recovery: false,
      }),
    onSuccess: () => {
      onUnlock();
    },
    onError: (err: unknown) => {
      const appErr = err as { code?: string };
      if (appErr?.code === "InvalidMfaCode") {
        setError("Invalid MFA code.");
      } else if (appErr?.code === "MfaLockout") {
        setError("Too many failed MFA attempts. Please log in again.");
      } else {
        toastError(err);
      }
    },
  });

  // Countdown timer for backend session expiry
  useEffect(() => {
    const update = () => {
      setTimeRemaining((prev) => Math.max(0, prev - 1000));
    };
    intervalRef.current = setInterval(update, 1000);
    return () => {
      if (intervalRef.current) clearInterval(intervalRef.current);
    };
  }, []);

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    setError(null);
    if (mfaToken) {
      if (!mfaCode.trim()) return;
      mfaMutation.mutate();
    } else {
      if (!password.trim()) return;
      loginMutation.mutate();
    }
  };

  const isPending = loginMutation.isPending || mfaMutation.isPending;
  const sessionExpired = timeRemaining <= 0;

  return (
    <div className="fixed inset-0 z-[100] flex items-center justify-center bg-background/80 backdrop-blur-sm">
      <Card className="w-full max-w-sm">
        <CardHeader>
          <div className="flex items-center gap-2">
            <LockKeyhole className="h-5 w-5 text-primary" />
            <CardTitle>Session Locked</CardTitle>
          </div>
          <CardDescription>
            Your session was locked due to inactivity.
            {session && (
              <span>
                {" "}
                Unlock to continue as <strong>{session.username}</strong>.
              </span>
            )}
            {!sessionExpired ? (
              <span className="flex items-center gap-1 mt-1 text-xs text-warning">
                <Timer className="h-3 w-3" />
                Session expires in ~{humanizeMinutes(timeRemaining)}
              </span>
            ) : (
              <span className="flex items-center gap-1 mt-1 text-xs text-destructive">
                <Timer className="h-3 w-3" />
                Session expired — full sign-in required
              </span>
            )}
          </CardDescription>
        </CardHeader>

        <CardContent>
          {error && (
            <Alert className="mb-4 border-destructive/50 bg-destructive/10">
              <ShieldAlert className="h-4 w-4 text-destructive" />
              <AlertDescription className="text-destructive">
                {error}
              </AlertDescription>
            </Alert>
          )}

          <form onSubmit={handleSubmit} className="flex flex-col gap-4">
            {!mfaToken ? (
              <div className="flex flex-col gap-1.5">
                <Label htmlFor="lock-password">Password</Label>
                <Input
                  id="lock-password"
                  type="password"
                  autoFocus
                  autoComplete="current-password"
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                />
              </div>
            ) : (
              <div className="flex flex-col gap-1.5">
                <Label htmlFor="lock-mfa">MFA Code</Label>
                <Input
                  id="lock-mfa"
                  type="text"
                  inputMode="numeric"
                  autoFocus
                  autoComplete="one-time-code"
                  value={mfaCode}
                  onChange={(e) => setMfaCode(e.target.value)}
                  placeholder="Enter 6-digit code"
                />
              </div>
            )}

            <Button type="submit" className="w-full" disabled={isPending}>
              {isPending
                ? mfaToken
                  ? "Verifying…"
                  : "Unlocking…"
                : mfaToken
                  ? "Verify MFA"
                  : "Unlock"}
            </Button>
          </form>
        </CardContent>
      </Card>
    </div>
  );
}
