import React from "react";
import ReactDOM from "react-dom/client";
import { RouterProvider, createRouter } from "@tanstack/react-router";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { ReactQueryDevtools } from "@tanstack/react-query-devtools";

import { routeTree } from "./routeTree.gen";
import { debugLogFrontend } from "./lib/bindings";
import "./styles/globals.css";

// Global error bridge → Rust tracing log. Captures any frontend error/rejection
// so we can diagnose "blank screen" or "nothing happens" bugs without devtools.
// Fire-and-forget — don't await, don't re-throw on failure.
function forwardToRustLog(level: "error" | "warn" | "info", message: string): void {
  try {
    void debugLogFrontend({ level, message }).catch(() => {});
  } catch {
    // swallow — diagnostics must never crash the app
  }
}

window.addEventListener("error", (ev) => {
  const msg = `window.onerror: ${ev.message} @ ${ev.filename}:${ev.lineno}:${ev.colno} | ${ev.error?.stack ?? "(no stack)"}`;
  forwardToRustLog("error", msg);
});

window.addEventListener("unhandledrejection", (ev) => {
  const reason = ev.reason;
  let msg = "unhandledrejection: ";
  if (reason instanceof Error) {
    msg += `${reason.name}: ${reason.message}\n${reason.stack ?? "(no stack)"}`;
  } else {
    try {
      msg += JSON.stringify(reason);
    } catch {
      msg += String(reason);
    }
  }
  forwardToRustLog("error", msg);
});

// Startup breadcrumb so we can confirm the bridge is wired.
forwardToRustLog("info", "frontend bridge wired");

// TanStack Router instance
const router = createRouter({ routeTree });

// Register the router for type safety
declare module "@tanstack/react-router" {
  interface Register {
    router: typeof router;
  }
}

// TanStack Query client — desktop app defaults: no CDN, offline-first
const queryClient = new QueryClient({
  defaultOptions: {
    queries: {
      retry: 1,
      refetchOnWindowFocus: false,
    },
  },
});

ReactDOM.createRoot(document.getElementById("root") as HTMLElement).render(
  <React.StrictMode>
    <QueryClientProvider client={queryClient}>
      <RouterProvider router={router} />
      {import.meta.env.DEV && <ReactQueryDevtools initialIsOpen={false} />}
    </QueryClientProvider>
  </React.StrictMode>,
);
