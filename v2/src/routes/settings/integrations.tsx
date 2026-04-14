/**
 * /settings/integrations — route definition only.
 *
 * The component is provided by `integrations.lazy.tsx` via TanStack Router's
 * file-based lazy route convention (`createLazyFileRoute`). This file only
 * registers the beforeLoad auth guard so the redirect runs eagerly on
 * navigation while the heavy Agent Zero + SMTP form code is deferred to a
 * separate chunk that loads only when the user visits this page.
 *
 * SEC-4 §2.3 and SEC-4 §2.14 enforcement lives in the component file.
 */

import { createFileRoute } from "@tanstack/react-router";
import { requireAuthBeforeLoad } from "@/lib/auth-guard";

export const Route = createFileRoute("/settings/integrations")({
  beforeLoad: requireAuthBeforeLoad,
});
