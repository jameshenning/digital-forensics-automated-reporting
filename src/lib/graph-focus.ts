/**
 * Pure helpers for the link-analysis graph "focus" feature (link analysis #3).
 *
 * The two questions investigators ask of a link analysis graph that the
 * unfocused topology view cannot answer:
 *
 *   1. "How is X connected to Y?" — shortest path between two nodes
 *   2. "What is X's immediate world?" — k-hop neighborhood from one node
 *
 * Cytoscape ships `aStar()` and `openNeighborhood()` which we use at
 * render time, but those methods need a live cytoscape instance. The
 * pure functions in this file mirror the same logic against a plain
 * edge list so they can be unit-tested without spinning up a DOM.
 *
 * BOTH functions treat edges as undirected — directional links in
 * `entity_links` still have a real arrow on the canvas, but for
 * "is X reachable from Y" purposes a one-way arrow connects in either
 * direction (an investigator looking at "Alice paid Bob" still wants
 * to discover that link when starting from Bob).
 */

export interface FocusEdge {
  source: string;
  target: string;
}

export type GraphFocus =
  | {
      kind: "path";
      /** Set first, before target. Always non-null when path mode is active. */
      source: string;
      /** Null while the user is in "pick the second endpoint" state. */
      target: string | null;
    }
  | {
      kind: "neighborhood";
      center: string;
      /** Number of edge hops to expand. Bounded UI-side to {1,2,3}. */
      hops: number;
    };

/** Build an undirected adjacency list. O(E). */
function adjacency(edges: ReadonlyArray<FocusEdge>): Map<string, Set<string>> {
  const adj = new Map<string, Set<string>>();
  for (const e of edges) {
    if (!adj.has(e.source)) adj.set(e.source, new Set());
    if (!adj.has(e.target)) adj.set(e.target, new Set());
    adj.get(e.source)!.add(e.target);
    adj.get(e.target)!.add(e.source);
  }
  return adj;
}

/**
 * Compute the set of node ids within `hops` undirected edges of `center`.
 * Always includes `center` itself. Returns an empty set if `center` has
 * no entry in the adjacency list (the node is isolated and `hops > 0`
 * doesn't reach anyone) — though `center` itself is always present.
 *
 * Hops below 1 collapse to {center}.
 */
export function computeNeighborhood(
  edges: ReadonlyArray<FocusEdge>,
  center: string,
  hops: number,
): Set<string> {
  const visited = new Set<string>([center]);
  if (hops < 1) return visited;
  const adj = adjacency(edges);
  let frontier: Set<string> = new Set([center]);
  for (let i = 0; i < hops; i++) {
    const next = new Set<string>();
    for (const node of frontier) {
      const neighbors = adj.get(node);
      if (!neighbors) continue;
      for (const n of neighbors) {
        if (!visited.has(n)) {
          visited.add(n);
          next.add(n);
        }
      }
    }
    if (next.size === 0) break;
    frontier = next;
  }
  return visited;
}

/**
 * BFS shortest (undirected) path from `source` to `target`.
 * Returns the ordered list of node ids on the path including both
 * endpoints, or `null` if disconnected. Returns `[source]` if
 * `source === target`.
 */
export function computeShortestPath(
  edges: ReadonlyArray<FocusEdge>,
  source: string,
  target: string,
): string[] | null {
  if (source === target) return [source];
  const adj = adjacency(edges);
  if (!adj.has(source) || !adj.has(target)) return null;

  const parent = new Map<string, string>();
  const queue: string[] = [source];
  const visited = new Set<string>([source]);

  while (queue.length > 0) {
    const node = queue.shift()!;
    if (node === target) {
      // Reconstruct path
      const path: string[] = [target];
      let cur = target;
      while (cur !== source) {
        const p = parent.get(cur);
        if (p === undefined) return null; // shouldn't happen
        path.push(p);
        cur = p;
      }
      return path.reverse();
    }
    const neighbors = adj.get(node);
    if (!neighbors) continue;
    for (const n of neighbors) {
      if (!visited.has(n)) {
        visited.add(n);
        parent.set(n, node);
        queue.push(n);
      }
    }
  }
  return null;
}

/**
 * Convert a node-id list (from `computeShortestPath`) into the set of
 * EDGE-key strings on that path. Edge keys are `"a|b"` with sorted
 * endpoints so the lookup is direction-agnostic. Used by the renderer
 * to decide which edges to highlight along with the nodes.
 */
export function pathEdgeKeys(nodePath: ReadonlyArray<string>): Set<string> {
  const keys = new Set<string>();
  for (let i = 0; i < nodePath.length - 1; i++) {
    const a = nodePath[i];
    const b = nodePath[i + 1];
    keys.add(a < b ? `${a}|${b}` : `${b}|${a}`);
  }
  return keys;
}

export function edgeKey(source: string, target: string): string {
  return source < target ? `${source}|${target}` : `${target}|${source}`;
}
