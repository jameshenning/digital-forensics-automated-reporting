/**
 * Root route — no UI, just a redirect.
 *
 * Single-user desktop app: there is no value in a branded landing page, so
 * `/` resolves to either the dashboard (if a session token is present) or
 * the login page (if not). The dashboard route has its own auth guard that
 * will bounce back to login if the token is invalid or expired, so we
 * don't need to double-check here.
 */

import { createFileRoute, redirect } from "@tanstack/react-router";
import { getToken } from "@/lib/session";

export const Route = createFileRoute("/")({
  beforeLoad: () => {
    if (getToken()) {
      throw redirect({ to: "/dashboard" });
    }
    throw redirect({ to: "/auth/login" });
  },
});
