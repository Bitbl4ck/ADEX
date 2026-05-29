"""Risk scoring — produce a Top-K dangerous-principal table.

Given the chain graph, score each node by:
  outbound_dangerous_edges + (100 / (1 + min_path_length_to_any_sink))

The result becomes a single MEDIUM finding so it appears prominently in
reports without being lost as one of many criticals.
"""

from __future__ import annotations

from adex.findings import Finding, Severity
from adex.graph import Graph

DANGEROUS_EDGE_TYPES = {
    "GenericAll", "GenericWrite", "WriteDACL", "WriteOwner",
    "DCSync", "RBCDWritable", "KeyCredentialWrite", "ESC1", "ESC8",
    "ResetPassword", "AddMember", "AddSelf",
}


def compute_risk(graph: Graph, sinks: dict[str, str], top_k: int = 10) -> Finding | None:
    if not graph.nodes():
        return None
    sink_set = set(sinks.keys())
    scores: list[tuple[str, str, int, float]] = []
    for node in graph.nodes():
        out_edges = [e for e in graph.neighbors(node) if e.type in DANGEROUS_EDGE_TYPES]
        out_count = len(out_edges)
        # Distance to nearest sink (cap at depth 6)
        dist = _min_path_len(graph, node, sink_set)
        proximity = 100 / (1 + dist) if dist >= 0 else 0
        score = out_count + proximity
        if score == 0:
            continue
        label = graph.label_for(node) or node
        scores.append((node, label, out_count, score))

    if not scores:
        return None

    scores.sort(key=lambda x: x[3], reverse=True)
    top = scores[:top_k]
    table = [
        {"node": label, "outboundDangerousEdges": count, "score": round(score, 1)}
        for (_node, label, count, score) in top
    ]
    return Finding(
        severity=Severity.MEDIUM,
        module="risk",
        title=f"Top {len(top)} highest-risk principals",
        description=(
            "Ranked by outbound dangerous-rights edges and graph proximity to "
            "high-value targets. Useful for prioritising where to push next."
        ),
        evidence={"ranking": table},
    )


def _min_path_len(graph: Graph, src: str, sinks: set[str], max_depth: int = 6) -> int:
    if src in sinks:
        return 0
    from collections import deque
    seen = {src}
    queue: deque[tuple[str, int]] = deque([(src, 0)])
    while queue:
        node, d = queue.popleft()
        if d >= max_depth:
            continue
        for edge in graph.neighbors(node):
            nxt = edge.dst
            if nxt in seen:
                continue
            if nxt in sinks:
                return d + 1
            seen.add(nxt)
            queue.append((nxt, d + 1))
    return -1
