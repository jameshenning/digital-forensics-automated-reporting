/**
 * Session token management.
 *
 * Token lives in sessionStorage (cleared when the Tauri WebView closes,
 * i.e. on app exit) + React/TanStack Query cache.
 *
 * NO HTTP cookies.  See v2-migration-spec.md §7 and sec-1-auth-architecture-review.md §2.5.
 */

import { useQuery, useQueryClient } from "@tanstack/react-query";
import { authCurrentUser, type SessionInfo } from "@/lib/bindings";
import { queryKeys } from "@/lib/query";

// ---------------------------------------------------------------------------
// Storage key
// ---------------------------------------------------------------------------

const SESSION_KEY = "dfars_session_token";

// ---------------------------------------------------------------------------
// Raw storage helpers — used only by this module and auth routes
// ---------------------------------------------------------------------------

export function getToken(): string | null {
  return sessionStorage.getItem(SESSION_KEY);
}

export function setToken(token: string): void {
  sessionStorage.setItem(SESSION_KEY, token);
}

export function clearToken(): void {
  sessionStorage.removeItem(SESSION_KEY);
}

// ---------------------------------------------------------------------------
// useSession hook
// ---------------------------------------------------------------------------

export interface UseSessionResult {
  /** The authenticated session, or null when unauthenticated / loading. */
  session: SessionInfo | null;
  /** True while the initial auth_current_user call is in-flight. */
  loading: boolean;
  /**
   * Re-validates the stored token against the backend.
   * Call after login or any event that may have changed session state.
   */
  refresh: () => void;
  /**
   * Clears the stored token and removes the session from the query cache.
   * Does NOT call auth_logout — callers that want server-side invalidation
   * must call authLogout() from bindings.ts before calling clear().
   */
  clear: () => void;
}

export function useSession(): UseSessionResult {
  const queryClient = useQueryClient();
  const token = getToken();

  const { data, isLoading } = useQuery<SessionInfo | null>({
    queryKey: queryKeys.currentUser,
    queryFn: async (): Promise<SessionInfo | null> => {
      const t = getToken();
      if (!t) return null;
      try {
        return await authCurrentUser({ token: t });
      } catch (err) {
        // Only treat Unauthorized as "session gone". Any other error
        // (Db, Io, Crypto, Internal, transient IPC hiccup, etc.) must NOT
        // silently clear the session and bounce the user to login — that
        // masks the real bug and confuses the investigator. Re-throw so the
        // query enters error state and the caller can decide how to handle.
        //
        // Previous behavior (pre-v2.0.0-rc.2): catch-all `clearToken()` on
        // any error. Caused "click case → bounce to login" symptom because
        // any non-auth query failure invalidated `currentUser`, refetch
        // ran, case_get parse error here bubbled to this catch, session
        // was cleared, and RequireAuth redirected to login.
        const code = (err as { code?: string })?.code;
        if (code === "Unauthorized") {
          clearToken();
          return null;
        }
        throw err;
      }
    },
    // Retry once in case of transient IPC hiccup; don't retry on auth errors
    retry: false,
    // Don't re-fetch on window focus — desktop app, no background tabs
    refetchOnWindowFocus: false,
    // Keep the session fresh: re-validate every 5 minutes
    refetchInterval: 5 * 60 * 1000,
    // If there's no token at all, skip the network call entirely
    enabled: token !== null,
  });

  function refresh(): void {
    void queryClient.invalidateQueries({ queryKey: queryKeys.currentUser });
  }

  function clear(): void {
    clearToken();
    queryClient.setQueryData(queryKeys.currentUser, null);
    void queryClient.invalidateQueries({ queryKey: queryKeys.currentUser });
  }

  return {
    session: data ?? null,
    loading: isLoading,
    refresh,
    clear,
  };
}
