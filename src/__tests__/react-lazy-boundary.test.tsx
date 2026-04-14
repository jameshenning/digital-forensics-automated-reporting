/**
 * Suspense boundary smoke tests for Phase 6 lazy-loaded components.
 *
 * Strategy:
 *   - Each test creates a trivial lazy-wrapped component that either:
 *       a) yields synchronously (Promise.resolve) to test the resolved state, or
 *       b) never resolves (new Promise(() => {})) to test the fallback state.
 *   - We do NOT import the real GraphCanvas / CrimeLineCanvas / ReportDialog
 *     through these tests — those components depend on cytoscape / vis-timeline
 *     which cannot run in jsdom (the dedicated component tests in
 *     graph-canvas.test.tsx / crime-line-canvas.test.tsx cover that).
 *   - What we DO verify: the Suspense boundary renders the fallback while
 *     the lazy chunk is pending, and renders the resolved content when done.
 *
 * These tests confirm the lazy() + Suspense wiring pattern is correct at the
 * React level, without needing the actual heavy dependencies.
 */

import { describe, it, expect } from "vitest";
import { render, screen, waitFor, act } from "@testing-library/react";
import React, { lazy, Suspense } from "react";

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/**
 * Creates a lazy component that resolves immediately with a simple div.
 * This tests the "chunk loads successfully" path.
 */
function makeSyncLazy(testId: string) {
  // Explicitly type the module shape to satisfy the lazy() overload.
  const mod: { default: React.ComponentType } = {
    default: function ResolvedComponent() {
      return React.createElement("div", { "data-testid": testId }, "Loaded");
    },
  };
  return lazy(() => Promise.resolve(mod));
}

/**
 * Creates a lazy component whose chunk never resolves.
 * This tests the "chunk still loading — show fallback" path.
 */
function makePendingLazy() {
  return lazy(() => new Promise<{ default: React.ComponentType }>(() => {}));
}

function FallbackSkeleton({ testId }: { testId: string }) {
  return React.createElement("div", { "data-testid": testId }, "Loading...");
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe("Suspense boundary — fallback while chunk is loading", () => {
  it("renders the fallback immediately when the lazy chunk is pending", () => {
    const LazyComp = makePendingLazy();

    render(
      React.createElement(
        Suspense,
        {
          fallback: React.createElement(FallbackSkeleton, {
            testId: "graph-skeleton",
          }),
        },
        React.createElement(LazyComp)
      )
    );

    // Fallback must be immediately visible
    expect(screen.getByTestId("graph-skeleton")).toBeInTheDocument();
    expect(screen.getByTestId("graph-skeleton").textContent).toBe("Loading...");
  });

  it("does not render the lazy component content while chunk is pending", () => {
    const LazyComp = makePendingLazy();

    render(
      React.createElement(
        Suspense,
        {
          fallback: React.createElement(FallbackSkeleton, {
            testId: "crime-line-skeleton",
          }),
        },
        React.createElement(LazyComp)
      )
    );

    // The resolved content is not present during the loading state
    expect(screen.queryByText("Loaded")).not.toBeInTheDocument();
  });
});

describe("Suspense boundary — resolved content after chunk loads", () => {
  it("renders the lazy component content after the chunk resolves", async () => {
    const LazyComp = makeSyncLazy("lazy-graph-content");

    await act(async () => {
      render(
        React.createElement(
          Suspense,
          {
            fallback: React.createElement(FallbackSkeleton, {
              testId: "graph-loading",
            }),
          },
          React.createElement(LazyComp)
        )
      );
    });

    await waitFor(() => {
      expect(screen.getByTestId("lazy-graph-content")).toBeInTheDocument();
    });
    expect(screen.getByTestId("lazy-graph-content").textContent).toBe("Loaded");
  });

  it("removes the fallback skeleton once the chunk resolves", async () => {
    const LazyComp = makeSyncLazy("lazy-crime-line-content");

    await act(async () => {
      render(
        React.createElement(
          Suspense,
          {
            fallback: React.createElement(FallbackSkeleton, {
              testId: "crime-line-loading",
            }),
          },
          React.createElement(LazyComp)
        )
      );
    });

    await waitFor(() => {
      expect(
        screen.queryByTestId("crime-line-loading")
      ).not.toBeInTheDocument();
    });
  });

  it("renders a null fallback (ReportDialog pattern) without throwing", async () => {
    const LazyComp = makeSyncLazy("lazy-report-dialog");

    await act(async () => {
      render(
        // null fallback is what we use for ReportDialog — the dialog portal
        // is not visible until `open` is true anyway.
        React.createElement(
          Suspense,
          { fallback: null },
          React.createElement(LazyComp)
        )
      );
    });

    await waitFor(() => {
      expect(screen.getByTestId("lazy-report-dialog")).toBeInTheDocument();
    });
  });

  it("multiple Suspense boundaries are independent — each shows its own fallback", () => {
    const LazyNeverResolves1 = makePendingLazy();
    const LazyNeverResolves2 = makePendingLazy();

    render(
      React.createElement(
        React.Fragment,
        null,
        React.createElement(
          Suspense,
          {
            fallback: React.createElement(FallbackSkeleton, {
              testId: "boundary-1",
            }),
          },
          React.createElement(LazyNeverResolves1)
        ),
        React.createElement(
          Suspense,
          {
            fallback: React.createElement(FallbackSkeleton, {
              testId: "boundary-2",
            }),
          },
          React.createElement(LazyNeverResolves2)
        )
      )
    );

    expect(screen.getByTestId("boundary-1")).toBeInTheDocument();
    expect(screen.getByTestId("boundary-2")).toBeInTheDocument();
  });
});
