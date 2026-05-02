/**
 * Tests for DashboardCharts component.
 */

import { describe, it, expect } from "vitest";
import { render, screen } from "@testing-library/react";
import { DashboardCharts } from "@/components/dashboard-charts";
import type { CaseStats } from "@/lib/bindings";

const MOCK_STATS: CaseStats = {
  status_counts: [
    { status: "Active", count: 12 },
    { status: "Pending", count: 5 },
    { status: "Closed", count: 3 },
  ],
  priority_counts: [
    { priority: "High", count: 8 },
    { priority: "Medium", count: 7 },
    { priority: "Low", count: 5 },
  ],
  monthly_counts: [
    { month: "2026-01", count: 2 },
    { month: "2026-02", count: 5 },
    { month: "2026-03", count: 8 },
    { month: "2026-04", count: 5 },
  ],
};

describe("DashboardCharts", () => {
  it("renders skeleton when loading", () => {
    const { container } = render(<DashboardCharts stats={undefined} isLoading />);
    expect(container.querySelectorAll(".animate-pulse").length).toBeGreaterThan(0);
  });

  it("renders empty state when no data", () => {
    render(
      <DashboardCharts
        stats={{
          status_counts: [],
          priority_counts: [],
          monthly_counts: [],
        }}
        isLoading={false}
      />
    );
    expect(screen.getByText("No chart data available")).toBeInTheDocument();
  });

  it("renders status distribution bars", () => {
    render(<DashboardCharts stats={MOCK_STATS} isLoading={false} />);
    expect(screen.getByText("Status Distribution")).toBeInTheDocument();
    expect(screen.getByText("Active")).toBeInTheDocument();
    expect(screen.getByText("12")).toBeInTheDocument();
    expect(screen.getByText("Pending")).toBeInTheDocument();
    expect(screen.getAllByText("5").length).toBe(2); // Pending=5 and Low=5
    expect(screen.getByText("Closed")).toBeInTheDocument();
    expect(screen.getByText("3")).toBeInTheDocument();
  });

  it("renders priority distribution bars", () => {
    render(<DashboardCharts stats={MOCK_STATS} isLoading={false} />);
    expect(screen.getByText("Priority Distribution")).toBeInTheDocument();
    expect(screen.getByText("High")).toBeInTheDocument();
    expect(screen.getByText("Medium")).toBeInTheDocument();
    expect(screen.getByText("Low")).toBeInTheDocument();
  });

  it("renders cases-over-time SVG chart", () => {
    render(<DashboardCharts stats={MOCK_STATS} isLoading={false} />);
    expect(screen.getByText("Cases Over Time")).toBeInTheDocument();
    const svg = document.querySelector("svg");
    expect(svg).toBeInTheDocument();
  });
});
