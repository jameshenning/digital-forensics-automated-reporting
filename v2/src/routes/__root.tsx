/**
 * Root route layout.
 *
 * QueryClientProvider lives in main.tsx.
 * This root component adds:
 *   - <Toaster /> from sonner (Shadcn-recommended toaster for error-toast.ts)
 *   - TanStack Router devtools in development only
 *
 * Auth state is NOT managed here via React Context.  The TanStack Query cache
 * of auth_current_user (queryKeys.currentUser) is the single source of truth,
 * accessed via useSession() from lib/session.ts.
 */

import { createRootRoute, Outlet } from "@tanstack/react-router";
import { TanStackRouterDevtools } from "@tanstack/router-devtools";
import { Toaster } from "sonner";

export const Route = createRootRoute({
  component: () => (
    <>
      <Outlet />
      <Toaster richColors position="top-right" />
      {import.meta.env.DEV && <TanStackRouterDevtools />}
    </>
  ),
});
