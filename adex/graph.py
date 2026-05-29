"""Tiny directed-graph helper used by chain inference.

No `networkx` dependency on purpose — the graphs we build for one
domain enum are small enough (hundreds of nodes, low-thousands of edges)
that a hand-rolled adjacency-list BFS is faster than pulling in a dep
and gives us full control of edge metadata.
"""

from __future__ import annotations

from collections import deque
from collections.abc import Iterable

from adex.findings import Edge


class Graph:
    def __init__(self) -> None:
        self._adj: dict[str, list[Edge]] = {}
        self.labels: dict[str, str] = {}

    def add_edge(self, e: Edge) -> None:
        self._adj.setdefault(e.src, []).append(e)
        self._adj.setdefault(e.dst, [])
        if e.dst_label and e.dst not in self.labels:
            self.labels[e.dst] = e.dst_label

    def add_edges(self, edges: Iterable[Edge]) -> None:
        for e in edges:
            self.add_edge(e)

    def nodes(self) -> list[str]:
        return list(self._adj.keys())

    def neighbors(self, node: str) -> list[Edge]:
        return list(self._adj.get(node, []))

    def label_for(self, node: str) -> str:
        return self.labels.get(node, node)

    def bfs_paths(self, src: str, sink: str, max_depth: int = 6,
                  max_paths: int = 3) -> list[list[Edge]]:
        """Return up to `max_paths` shortest edge paths from src to sink.

        BFS keeps multiple parents at the shortest depth, then expands all
        path reconstructions. Loop avoidance: a path may not revisit a node.
        """
        if src == sink:
            return [[]]
        if src not in self._adj:
            return []

        # Standard BFS recording parent edges; allow multiple parents at the
        # earliest discovery depth.
        depth = {src: 0}
        parents: dict[str, list[Edge]] = {}
        queue: deque[str] = deque([src])
        while queue:
            node = queue.popleft()
            d = depth[node]
            if d >= max_depth:
                continue
            for edge in self._adj.get(node, []):
                nxt = edge.dst
                if nxt == src:
                    continue
                if nxt not in depth:
                    depth[nxt] = d + 1
                    parents[nxt] = [edge]
                    queue.append(nxt)
                elif depth[nxt] == d + 1:
                    parents[nxt].append(edge)

        if sink not in depth:
            return []

        # Reconstruct paths by walking parents backwards, depth-first
        results: list[list[Edge]] = []

        def walk(node: str, path: list[Edge]) -> None:
            if len(results) >= max_paths:
                return
            if node == src:
                results.append(list(reversed(path)))
                return
            for edge in parents.get(node, []):
                if any(e is edge for e in path):
                    continue
                if edge.src == node:
                    continue
                # Avoid revisiting nodes already in this path
                visited = {e.dst for e in path}
                visited.add(node)
                if edge.src in visited and edge.src != src:
                    continue
                path.append(edge)
                walk(edge.src, path)
                path.pop()

        walk(sink, [])
        return results

    def find_paths(self, sources: Iterable[str], sinks: Iterable[str],
                   max_depth: int = 6, max_paths_per_pair: int = 1) -> list[list[Edge]]:
        """Return shortest paths from any source to any sink, deduplicated."""
        seen_keys: set[tuple] = set()
        out: list[list[Edge]] = []
        for s in sources:
            if s not in self._adj:
                continue
            for t in sinks:
                paths = self.bfs_paths(s, t, max_depth=max_depth,
                                       max_paths=max_paths_per_pair)
                for p in paths:
                    key = tuple((e.src, e.dst, e.type) for e in p)
                    if key in seen_keys:
                        continue
                    seen_keys.add(key)
                    out.append(p)
        out.sort(key=lambda p: (len(p), sum(e.cost for e in p)))
        return out
