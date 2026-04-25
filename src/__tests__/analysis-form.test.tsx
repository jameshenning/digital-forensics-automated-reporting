/**
 * Render tests for AnalysisForm — covers the new validation fields
 * added in the Phase A migration (created_by, method_reference,
 * tool_version, alternatives_considered).
 *
 * Strategy: render in isolation (no IPC mocking needed — form just
 * collects values and calls onSubmit), drive inputs via fireEvent,
 * assert the onSubmit call shape matches what the panel's
 * formValuesToInput mapper expects.
 */

import { describe, it, expect, vi } from "vitest";
import { render, screen, fireEvent, waitFor } from "@testing-library/react";
import React from "react";

import { AnalysisForm } from "@/components/analysis-form";
import type { Evidence } from "@/lib/bindings";

const NO_EVIDENCE: Evidence[] = [];

describe("AnalysisForm — validation fields (migration 0007)", () => {
  it("renders the Author field with a soft '(recommended)' suffix", () => {
    const onSubmit = vi.fn();
    render(
      React.createElement(AnalysisForm, {
        evidenceList: NO_EVIDENCE,
        isPending: false,
        onSubmit,
        onCancel: () => {},
      })
    );

    // The Author label exists. We use getByLabelText for stability —
    // there are also case-insensitive "author" mentions in the
    // FormDescription that getByText would match ambiguously.
    expect(screen.getByLabelText(/Author/i)).toBeInTheDocument();
    expect(screen.getByText(/\(recommended\)/i)).toBeInTheDocument();
  });

  it("hides the validation & methodology section by default (collapsed disclosure)", () => {
    render(
      React.createElement(AnalysisForm, {
        evidenceList: NO_EVIDENCE,
        isPending: false,
        onSubmit: () => {},
        onCancel: () => {},
      })
    );

    // The summary is always visible
    const summary = screen.getByText(/Validation & methodology/i);
    expect(summary).toBeInTheDocument();

    // The inner labels exist in the DOM but their <details> parent
    // is not "open" — a `<details>` element exposes `open=false` by
    // default. We assert by checking the parent's `open` prop is
    // falsy.
    const detailsElement = summary.closest("details");
    expect(detailsElement).not.toBeNull();
    expect(detailsElement!.hasAttribute("open")).toBe(false);
  });

  it("submits with all four validation fields populated when filled", async () => {
    const onSubmit = vi.fn();
    render(
      React.createElement(AnalysisForm, {
        evidenceList: NO_EVIDENCE,
        isPending: false,
        onSubmit,
        onCancel: () => {},
      })
    );

    // Fill required fields
    const findingInput = screen.getByLabelText(/Finding/i);
    fireEvent.change(findingInput, {
      target: { value: "Artifact consistent with baseline" },
    });

    // Author
    const authorInput = screen.getByLabelText(/Author/i);
    fireEvent.change(authorInput, { target: { value: "J. Henning" } });

    // Open the advanced section
    const summary = screen.getByText(/Validation & methodology/i);
    fireEvent.click(summary);

    // Method + tool + alternatives
    const methodInput = screen.getByLabelText(/Method reference/i);
    fireEvent.change(methodInput, {
      target: { value: "NIST SP 800-86 §5.2" },
    });
    const toolInput = screen.getByLabelText(/Tool \+ version/i);
    fireEvent.change(toolInput, { target: { value: "exiftool 12.76" } });
    const altInput = screen.getByLabelText(/Alternative explanations/i);
    fireEvent.change(altInput, {
      target: { value: "Ruled out file corruption by SHA256 match" },
    });

    fireEvent.click(screen.getByRole("button", { name: /Add Note/i }));

    await waitFor(() => expect(onSubmit).toHaveBeenCalled());
    const submitted = onSubmit.mock.calls[0][0] as Record<string, unknown>;
    expect(submitted.finding).toBe("Artifact consistent with baseline");
    expect(submitted.created_by).toBe("J. Henning");
    expect(submitted.method_reference).toBe("NIST SP 800-86 §5.2");
    expect(submitted.tool_version).toBe("exiftool 12.76");
    expect(submitted.alternatives_considered).toBe(
      "Ruled out file corruption by SHA256 match"
    );
  });

  it("submits with empty validation fields when only finding is filled (v1-style note)", async () => {
    const onSubmit = vi.fn();
    render(
      React.createElement(AnalysisForm, {
        evidenceList: NO_EVIDENCE,
        isPending: false,
        onSubmit,
        onCancel: () => {},
      })
    );

    fireEvent.change(screen.getByLabelText(/Finding/i), {
      target: { value: "Quick observation" },
    });
    fireEvent.click(screen.getByRole("button", { name: /Add Note/i }));

    await waitFor(() => expect(onSubmit).toHaveBeenCalled());
    const submitted = onSubmit.mock.calls[0][0] as Record<string, unknown>;
    expect(submitted.finding).toBe("Quick observation");
    expect(submitted.created_by).toBe("");
    expect(submitted.method_reference).toBe("");
    expect(submitted.tool_version).toBe("");
    expect(submitted.alternatives_considered).toBe("");
  });
});
