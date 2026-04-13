import { createFileRoute, Link } from "@tanstack/react-router";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";

export const Route = createFileRoute("/auth/login")({
  component: LoginPage,
});

function LoginPage() {
  // TODO Phase 1: wire up auth_login Tauri command via TanStack Query mutation
  return (
    <div className="flex min-h-screen items-center justify-center bg-background p-8">
      <Card className="w-full max-w-sm">
        <CardHeader>
          <CardTitle>Sign in</CardTitle>
          <CardDescription>DFARS Desktop — Phase 0 placeholder</CardDescription>
        </CardHeader>
        <CardContent className="flex flex-col gap-3">
          <Input type="text" placeholder="Username" disabled />
          <Input type="password" placeholder="Password" disabled />
          <Button disabled>Sign in</Button>
          <Button variant="ghost" asChild>
            <Link to="/">Back to home</Link>
          </Button>
        </CardContent>
      </Card>
    </div>
  );
}
