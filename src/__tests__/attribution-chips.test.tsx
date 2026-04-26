/**
 * Render tests for AttributionChips — Phase B (migration 0008).
 *
 * The component renders confidence/verification/author chips when the
 * underlying record carries Phase B attribution metadata, and renders
 * absolutely nothing for v1 rows where every field is null/undefined.
 * That zero-render path is load-bearing: every list of identifiers/links
 * is dominated (in v1 cases) by rows with no attribution, so the chip
 * component must not pollute the layout.
 */

import { describe, it, expect } from "vitest";
import { render, screen } from "@testing-library/react";
import React from "react";

import { AttributionChips } from "@/components/attribution-chips";

describe("AttributionChips", () => {
  it("renders nothing when no attribution metadata is present (v1 row)", () => {
    const { container } = render(
      React.createElement(AttributionChips, {
        confidence: null,
        verification: null,
        attributedBy: null,
        basis: null,
      })
    );
    expect(container.firstChild).toBeNull();
  });

  it("renders 'author not recorded' fallback when only confidence is set", () => {
    render(
      React.createElement(AttributionChips, {
        confidence: "Medium",
        verification: null,
        attributedBy: null,
        basis: null,
      })
    );
    expect(screen.getByText(/Confidence: Medium/i)).toBeInTheDocument();
    expect(screen.getByText(/author not recorded/i)).toBeInTheDocument();
  });

  it("renders all three chips + basis line when full attribution is provided", () => {
    render(
      React.createElement(AttributionChips, {
        confidence: "High",
        verification: "Confirmed",
        attributedBy: "J. Smith",
        basis: "Self-reported in intake form 2026-04-10",
      })
    );
    expect(screen.getByText(/Confidence: High/i)).toBeInTheDocument();
    expect(screen.getByText(/^Confirmed$/i)).toBeInTheDocument();
    expect(screen.getByText(/by J\. Smith/i)).toBeInTheDocument();
    expect(
      screen.getByText(/Self-reported in intake form 2026-04-10/i)
    ).toBeInTheDocument();
  });

  it("treats blank-string attributedBy as not recorded", () => {
    // Whitespace-only author is normalized to "not recorded" — empty form
    // submissions get coerced this way before they round-trip back from
    // the DB (Rust normalize_optional collapses ""/"  " to NULL on the
    // wire), but we want the UI to be defensive against any direct
    // pass-through too.
    render(
      React.createElement(AttributionChips, {
        confidence: "Low",
        verification: "Unverified",
        attributedBy: "   ",
        basis: null,
      })
    );
    expect(screen.getByText(/author not recorded/i)).toBeInTheDocument();
  });
});
