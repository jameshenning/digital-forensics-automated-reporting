/**
 * Dashboard — Phase 1 minimal version.
 *
 * Protected by requireAuthBeforeLoad.  Shows the authenticated user's name,
 * links to Security settings, and a Log out button.
 *
 * The body is a placeholder — Phase 2 will add case list and CRUD.
 */

import { createFileRoute, Link, useNavigate } from "@tanstack/react-router";
import { LayoutDashboard, ShieldCheck, LogOut } from "lucide-react";

import { useSession } from "@/lib/session";
import { requireAuthBeforeLoad } from "@/lib/auth-guard";
import { authLogout } from "@/lib/bindings";
import { getToken, clearToken } from "@/lib/session";
import { useQueryClient } from "@tanstack/react-query";
import { queryKeys } from "@/lib/query";

import { Button } from "@/components/ui/button";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";

export const Route = createFileRoute("/dashboard")({
  beforeLoad: requireAuthBeforeLoad,
  component: DashboardPage,
});

function DashboardPage() {
  const { session } = useSession();
  const navigate = useNavigate();
  const queryClient = useQueryClient();

  async function handleLogout() {
    const token = getToken();
    if (token) {
      try {
        await authLogout({ token });
      } catch {
        // Ignore — session may already be expired
      }
    }
    clearToken();
    queryClient.setQueryData(queryKeys.currentUser, null);
    void queryClient.invalidateQueries({ queryKey: queryKeys.currentUser });
    void navigate({ to: "/auth/login" });
  }

  return (
    <div className="min-h-screen bg-background">
      {/* Header */}
      <header className="border-b">
        <div className="mx-auto max-w-5xl px-6 py-4 flex items-center justify-between">
          <div className="flex items-center gap-2">
            <LayoutDashboard className="h-5 w-5 text-primary" />
            <span className="text-lg font-semibold">DFARS Desktop</span>
          </div>
          <nav className="flex items-center gap-3">
            {session && (
              <span className="text-sm text-muted-foreground">
                {session.username}
              </span>
            )}
            <Button variant="ghost" size="sm" asChild>
              <Link to="/settings/security">
                <ShieldCheck className="h-4 w-4" />
                Settings
              </Link>
            </Button>
            <Button variant="outline" size="sm" onClick={() => void handleLogout()}>
              <LogOut className="h-4 w-4" />
              Log out
            </Button>
          </nav>
        </div>
      </header>

      {/* Body — Phase 2 placeholder */}
      <main className="mx-auto max-w-5xl px-6 py-12">
        <Card className="w-full max-w-lg mx-auto">
          <CardHeader>
            <CardTitle>Dashboard</CardTitle>
            <CardDescription>Phase 2 content coming soon</CardDescription>
          </CardHeader>
          <CardContent>
            <p className="text-sm text-muted-foreground">
              Cases, evidence, chain-of-custody, and link analysis will appear
              here in Phase 2.
            </p>
          </CardContent>
        </Card>
      </main>
    </div>
  );
}
