"""Attack-chain inference.

Runs after enum modules. Reads the structured `Edge` list emitted by every
finding, builds a directed graph, and computes shortest paths from the
bound principal (and its transitive groups) to high-value sinks.

Each path becomes a CRITICAL finding with the per-edge recipes concatenated.
"""

from __future__ import annotations

from collections.abc import Iterable

from ldap3 import SUBTREE, Connection

from adex.findings import Edge, Finding, Severity
from adex.graph import Graph

# Edges that imply "you become the dst" once traversed.
TAKEOVER_EDGES = {
    "GenericAll", "GenericWrite", "WriteDACL", "WriteOwner",
    "ResetPassword", "KeyCredentialWrite", "AddSelf", "AddMember",
    "Kerberoast", "ASREPRoast", "RBCDInbound", "RBCDWritable", "ESC1",
    "OwnsCert", "GMSAReadable",
}

# Edge types that grant authentication-as-anyone — once you have the
# capability you can mint a cert / TGT for any user. The chain analyzer
# auto-wires these to every sink (DA, EA, krbtgt, DCs, AdminSDHolder)
# at zero cost so the BFS finds an ESC1-template-or-DCSync path that
# actually lands on a privileged group.
ANY_USER_WIN_EDGES = {
    "ESC1", "ESC2", "ESC3", "ESC5", "ESC8", "ESC9",
    "ESC11", "ESC13", "ESC15", "DCSync",
}


def resolve_sinks(conn: Connection, base_dn: str) -> dict[str, str]:
    """Return {sid_or_dn: human_label} for high-value targets in this domain."""
    sinks: dict[str, str] = {}

    privileged_groups = [
        "Domain Admins", "Enterprise Admins", "Schema Admins",
        "Administrators", "Account Operators", "Backup Operators",
    ]
    for sam in privileged_groups:
        conn.search(
            base_dn,
            f"(&(objectClass=group)(sAMAccountName={sam}))",
            search_scope=SUBTREE,
            attributes=["objectSid", "distinguishedName"],
        )
        if conn.entries:
            sid = str(conn.entries[0]["objectSid"]) if conn.entries[0]["objectSid"] else None
            if sid:
                sinks[sid] = sam
                sinks[conn.entries[0].entry_dn] = sam  # also keyed by DN

    # krbtgt
    conn.search(base_dn, "(&(objectClass=user)(sAMAccountName=krbtgt))",
                search_scope=SUBTREE, attributes=["objectSid", "distinguishedName"])
    if conn.entries and conn.entries[0]["objectSid"]:
        sinks[str(conn.entries[0]["objectSid"])] = "krbtgt"

    # Domain controllers
    conn.search(base_dn, "(&(objectClass=computer)"
                "(userAccountControl:1.2.840.113556.1.4.803:=8192))",
                search_scope=SUBTREE,
                attributes=["objectSid", "sAMAccountName", "distinguishedName"])
    for entry in conn.entries:
        sid = str(entry["objectSid"]) if entry["objectSid"] else None
        sam = str(entry["sAMAccountName"]) if entry["sAMAccountName"] else "DC"
        if sid:
            sinks[sid] = f"DC: {sam}"

    # AdminSDHolder (object-DN sink — represents persistent priv via SDProp)
    sinks[f"CN=AdminSDHolder,CN=System,{base_dn}"] = "AdminSDHolder"

    return sinks


def render_path(path: list[Edge], graph: Graph) -> str:
    if not path:
        return "(empty)"
    parts = [graph.label_for(path[0].src) or path[0].src[:24]]
    for e in path:
        parts.append(f" --[{e.type}]--> ")
        parts.append(graph.label_for(e.dst) or e.dst[:60])
    return "".join(parts)


def collect_recipes(path: list[Edge]) -> list[str]:
    """Concatenate per-edge recipes from the originating findings — but here
    we only have edges, not the findings, so emit a generic per-edge hint."""
    out: list[str] = []
    for e in path:
        ctx = e.context or {}
        out.append(f"# Step: {e.type} on {e.dst_label or e.dst}")
        # Hint per type — the originating finding has the parameterised recipe.
        if e.type == "Kerberoast":
            out.append("# See the matching 'Kerberoastable user' finding for the full command.")
        elif e.type == "ASREPRoast":
            out.append("# See the matching 'AS-REP roastable' finding.")
        elif e.type == "ESC1":
            out.append(f"# See the ADCS ESC1 finding for template '{ctx.get('template','?')}'.")
        elif e.type in {"GenericAll", "GenericWrite", "ResetPassword"}:
            out.append("# See the matching ACL finding for the bloodyAD/certipy command.")
        elif e.type == "RBCDWritable":
            out.append("# See the RBCD finding for the addcomputer + bloodyAD chain.")
        elif e.type == "DCSync":
            out.append("# See the DCSync finding for the secretsdump command.")
    return out


def compute_chains(edges: Iterable[Edge], sources: set[str],
                   sinks: dict[str, str],
                   max_depth: int = 6, top_k: int = 5) -> tuple[Graph, list[Finding]]:
    edges = list(edges)
    g = Graph()
    g.add_edges(edges)
    # Set labels for sinks so paths print nicely
    for node, label in sinks.items():
        g.labels.setdefault(node, label)

    # Auto-wire "win" edges (ESC*, DCSync) to every sink so BFS doesn't
    # dead-end at synthetic ESC nodes. Cost 0 so the path length reflects
    # only the real attack hops.
    win_dsts = {e.dst for e in edges if e.type in ANY_USER_WIN_EDGES}
    for src_node in win_dsts:
        for sink_node, sink_label in sinks.items():
            g.add_edge(Edge(src=src_node, dst=sink_node,
                            type="AddMember",  # any takeover edge is fine
                            dst_label=sink_label, cost=0))

    paths = g.find_paths(sources, sinks.keys(), max_depth=max_depth + 1,
                         max_paths_per_pair=1)
    paths = paths[:top_k]

    findings: list[Finding] = []
    for path in paths:
        sink_node = path[-1].dst
        sink_label = sinks.get(sink_node, g.label_for(sink_node))
        findings.append(Finding(
            severity=Severity.CRITICAL,
            module="chain",
            title=f"Path to {sink_label} ({len(path)} hop{'s' if len(path) != 1 else ''})",
            description=(
                "ADEX inferred a privilege-escalation chain from your current "
                "principal to a high-value target by stitching together edges "
                "emitted by the enum modules."
            ),
            target=sink_label,
            evidence={
                "render": render_path(path, g),
                "edges": [e.to_dict() for e in path],
                "hops": len(path),
            },
            recipe=collect_recipes(path),
            references=[
                "https://github.com/SpecterOps/BloodHound — for an interactive view of the same edges",
            ],
        ))
    return g, findings
