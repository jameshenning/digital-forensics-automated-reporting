/**
 * SettingsHeader — shared header for all /settings/* routes.
 *
 * Renders a consistent banner with tabbed navigation between the sub-pages
 * (Security, Integrations, ...) plus a "signed in as" chip, Dashboard
 * button, and Log out button. Extracted so every settings page has the
 * same look and every sub-page is reachable from every other — the prior
 * layout made Integrations orphaned (reachable only from the Security
 * back-button, which itself didn't exist on the Security page).
 *
 * The active tab highlights based on the current route path.
 */

import { Link, useNavigate, useRouterState } from "@tanstack/react-router";
import { ShieldCheck, Plug } from "lucide-react";

import { Button } from "@/components/ui/button";
import { cn } from "@/lib/utils";

interface SettingsHeaderProps {
  /** Currently-signed-in username — rendered in the "Signed in as" chip. */
  username: string;
}

interface Tab {
  to: "/settings/security" | "/settings/integrations";
  label: string;
  icon: React.ComponentType<{ className?: string }>;
}

const TABS: Tab[] = [
  { to: "/settings/security", label: "Security", icon: ShieldCheck },
  { to: "/settings/integrations", label: "Integrations", icon: Plug },
];

export function SettingsHeader({ username }: SettingsHeaderProps) {
  const navigate = useNavigate();
  const currentPath = useRouterState({
    select: (s) => s.location.pathname,
  });

  return (
    <header className="border-b">
      <div className="mx-auto max-w-3xl px-6 py-3 flex items-center justify-between gap-4">
        <nav aria-label="Settings sections" className="flex items-center gap-1">
          {TABS.map((tab) => {
            const isActive = currentPath === tab.to;
            const Icon = tab.icon;
            return (
              <Link
                key={tab.to}
                to={tab.to}
                className={cn(
                  "inline-flex items-center gap-1.5 rounded-md px-3 py-1.5 text-sm font-medium transition-colors",
                  isActive
                    ? "bg-primary text-primary-foreground"
                    : "text-muted-foreground hover:bg-muted hover:text-foreground",
                )}
                aria-current={isActive ? "page" : undefined}
              >
                <Icon className="h-4 w-4" />
                {tab.label}
              </Link>
            );
          })}
        </nav>
        <div className="flex items-center gap-3">
          <span className="text-sm text-muted-foreground hidden sm:inline">
            Signed in as <code className="font-mono">{username}</code>
          </span>
          <Button variant="ghost" size="sm" asChild>
            <Link to="/dashboard">Dashboard</Link>
          </Button>
          <Button
            variant="outline"
            size="sm"
            onClick={() => void navigate({ to: "/auth/logout" })}
          >
            Log out
          </Button>
        </div>
      </div>
    </header>
  );
}
