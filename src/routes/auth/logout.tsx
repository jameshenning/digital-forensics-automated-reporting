/**
 * Logout route.
 *
 * Calls auth_logout (server-side token invalidation), then clears the local
 * session token and redirects to /auth/login.  No interactive UI — just a
 * "Logging out..." status text while the IPC call is in-flight.
 *
 * Using a loader (beforeLoad) rather than useEffect ensures the logout fires
 * before the component mounts.  TanStack Router's beforeLoad is synchronous
 * for the redirect path; we fire-and-forget the async logout and redirect
 * immediately since the in-memory session map on the Rust side will expire
 * anyway.
 */

import { createFileRoute, redirect } from "@tanstack/react-router";
import { authLogout } from "@/lib/bindings";
import { getToken, clearToken } from "@/lib/session";

export const Route = createFileRoute("/auth/logout")({
  beforeLoad: () => {
    const token = getToken();
    if (token) {
      // Fire-and-forget: we clear client-side immediately and let the Rust
      // side invalidate async.  This keeps the logout redirect instant.
      authLogout({ token }).catch(() => {
        // Ignore — if the IPC call fails the session was already invalid
      });
      clearToken();
    }
    throw redirect({ to: "/auth/login" });
  },
  component: LogoutPage,
});

/**
 * This component should never render because beforeLoad always redirects,
 * but it satisfies the TanStack Router requirement for a component.
 */
function LogoutPage() {
  return (
    <div className="flex min-h-screen items-center justify-center bg-background">
      <p className="text-muted-foreground">Logging out...</p>
    </div>
  );
}
