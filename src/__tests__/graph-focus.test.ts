/**
 * Pure-function tests for src/lib/graph-focus.ts.
 *
 * Verifies BFS k-hop neighborhood and shortest-path on a small fixture
 * mirroring a typical case shape (persons + a shared identifier node).
 */

import { describe, it, expect } from "vitest";
import {
  computeNeighborhood,
  computeShortestPath,
  pathEdgeKeys,
} from "@/lib/graph-focus";

// Graph:
//   alice ──── shared_email ──── bob ──── carol
//                                  │
//                                  └── ev1
//   isolated  (disconnected)
const EDGES = [
  { source: "alice", target: "shared_email" },
  { source: "bob", target: "shared_email" },
  { source: "bob", target: "carol" },
  { source: "bob", target: "ev1" },
];

describe("computeNeighborhood", () => {
  it("returns just the center for hops=0", () => {
    expect([...computeNeighborhood(EDGES, "alice", 0)]).toEqual(["alice"]);
  });

  it("expands one hop", () => {
    const result = computeNeighborhood(EDGES, "alice", 1);
    expect([...result].sort()).toEqual(["alice", "shared_email"]);
  });

  it("expands two hops — picks up bob through the shared identifier", () => {
    const result = computeNeighborhood(EDGES, "alice", 2);
    expect([...result].sort()).toEqual(["alice", "bob", "shared_email"]);
  });

  it("expands three hops — picks up bob's neighborhood", () => {
    const result = computeNeighborhood(EDGES, "alice", 3);
    expect([...result].sort()).toEqual([
      "alice",
      "bob",
      "carol",
      "ev1",
      "shared_email",
    ]);
  });

  it("does not over-expand past the connected component", () => {
    const result = computeNeighborhood(EDGES, "alice", 99);
    expect(result.has("isolated")).toBe(false);
  });

  it("isolated node returns just itself", () => {
    expect([...computeNeighborhood(EDGES, "isolated", 3)]).toEqual([
      "isolated",
    ]);
  });
});

describe("computeShortestPath", () => {
  it("returns [source] when source === target", () => {
    expect(computeShortestPath(EDGES, "alice", "alice")).toEqual(["alice"]);
  });

  it("finds the shortest path via the shared identifier", () => {
    expect(computeShortestPath(EDGES, "alice", "bob")).toEqual([
      "alice",
      "shared_email",
      "bob",
    ]);
  });

  it("finds longer paths", () => {
    expect(computeShortestPath(EDGES, "alice", "carol")).toEqual([
      "alice",
      "shared_email",
      "bob",
      "carol",
    ]);
  });

  it("works on undirected edges (target → source still finds the path)", () => {
    expect(computeShortestPath(EDGES, "carol", "alice")).toEqual([
      "carol",
      "bob",
      "shared_email",
      "alice",
    ]);
  });

  it("returns null when disconnected", () => {
    expect(computeShortestPath(EDGES, "alice", "isolated")).toBeNull();
  });

  it("returns null for unknown node ids", () => {
    expect(computeShortestPath(EDGES, "alice", "ghost")).toBeNull();
    expect(computeShortestPath(EDGES, "ghost", "alice")).toBeNull();
  });
});

describe("pathEdgeKeys", () => {
  it("returns direction-agnostic keys for the edges along a path", () => {
    const path = ["alice", "shared_email", "bob"];
    const keys = pathEdgeKeys(path);
    expect(keys.size).toBe(2);
    expect(keys.has("alice|shared_email")).toBe(true);
    expect(keys.has("bob|shared_email")).toBe(true);
  });

  it("returns empty set for a single-node path", () => {
    expect(pathEdgeKeys(["alice"]).size).toBe(0);
  });
});
