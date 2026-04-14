/**
 * Auth guard utilities for TanStack Router.
 *
 * Two mechanisms are provided:
 *
 * 1. `requireAuthBeforeLoad` — a TanStack Router `beforeLoad` function.
 *    Use this in route definitions for the primary guard.
 *
 * 2. `<RequireAuth>` — a JSX wrapper that redirects at render time.
 *    Use as a defensive fallback if a route's beforeLoad is skipped
 *    (e.g. during hot-reload in dev or if a nested route forgets its guard).
 *
 * Both redirect to /auth/login if no valid session token is present in
 * sessionStorage.  They do NOT call authCurrentUser — that network call
 * lives in useSession() and is always warm from the TanStack Query cache.
 * The beforeLoad guard uses the token's presence as a fast gate; the full
 * validation happens reactively via the useSession() refetchInterval.
 */

import React from "react";
import { redirect } from "@tanstack/react-router";
import { getToken } from "@/lib/session";
import { useSession } from "@/lib/session";

// ---------------------------------------------------------------------------
// 1. beforeLoad helper — use in route definitions
// ---------------------------------------------------------------------------

/**
 * Drop-in `beforeLoad` function for protected TanStack Router routes.
 *
 * @example
 * export const Route = createFileRoute('/settings/security')({
 *   beforeLoad: requireAuthBeforeLoad,
 *   component: SecurityPage,
 * });
 */
export function requireAuthBeforeLoad(): void {
  const token = getToken();
  if (!token) {
    throw redirect({ to: "/auth/login" });
  }
}

// ---------------------------------------------------------------------------
// 2. <RequireAuth> JSX wrapper — defensive fallback
// ---------------------------------------------------------------------------

interface RequireAuthProps {
  children: React.ReactNode;
}

/**
 * Renders children only when there is a verified session.
 * While loading, renders nothing.  When unauthenticated, navigates to /auth/login.
 *
 * Prefer `requireAuthBeforeLoad` in route definitions over this component —
 * the beforeLoad guard fires before the component tree mounts, avoiding a
 * flash of unauthenticated content.  This wrapper is a safety net.
 */
export function RequireAuth({ children }: RequireAuthProps): React.ReactNode {
  const { session, loading } = useSession();

  if (loading) {
    // Avoid flash of redirect while the session query is still in-flight
    return null;
  }

  if (!session) {
    throw redirect({ to: "/auth/login" });
  }

  return <>{children}</>;
}
