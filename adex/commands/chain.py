"""`adex chain` — recompute attack chains from a saved JSON snapshot.

Useful for "what-if" scenarios: without re-running enum, ask ADEX
to walk the saved findings' edges and tell you the path to a chosen target.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from rich.console import Console

from adex.chain import compute_chains
from adex.exit_codes import ExitCode, from_findings
from adex.findings import Edge, Finding, FindingCollector, Severity
from adex.modules.base import ME_NODE
from adex.output import print_findings_console, print_summary, write_outputs


def add_parser(subparsers, common) -> None:
    p = subparsers.add_parser(
        "chain",
        help="Compute attack-path chains from a saved enum JSON report",
    )
    p.add_argument("--input", required=True, help="Path to an ADEX JSON report")
    p.add_argument("--target", action="append",
                   help="Target node label or SID (repeatable). "
                   "Defaults to common privileged groups + krbtgt + DCs.")
    p.add_argument("--source", action="append",
                   help="Override source node (repeatable). Defaults to ME.")
    p.add_argument("--top-k", type=int, default=5,
                   help="Maximum number of paths to print (default: 5)")
    p.add_argument("--max-depth", type=int, default=6,
                   help="Maximum path length to search (default: 6)")
    p.add_argument("-o", "--output", help="Write report files (.json/.html/.txt)")
    p.add_argument("-f", "--format", default="all",
                   choices=["all", "html", "json", "txt"])
    p.set_defaults(handler=handle)


def _load_findings(path: str) -> list[Finding]:
    data = json.loads(Path(path).read_text())
    return [Finding.from_dict(f) for f in data.get("findings", [])]


DEFAULT_TARGETS = [
    "Domain Admins", "Enterprise Admins", "Schema Admins",
    "krbtgt", "AdminSDHolder",
]


def handle(args: argparse.Namespace) -> int:
    console = Console()
    findings = _load_findings(args.input)
    edges: list[Edge] = []
    for f in findings:
        edges.extend(f.edges)

    # Build label table from all edges
    labels: dict[str, str] = {}
    for e in edges:
        if e.dst_label and e.dst not in labels:
            labels[e.dst] = e.dst_label

    # Sinks: by default the common targets, matched on label
    targets = args.target or DEFAULT_TARGETS
    sinks: dict[str, str] = {}
    for node, label in labels.items():
        if any(t.lower() == label.lower() or t.lower() in label.lower() for t in targets):
            sinks[node] = label
    if not sinks:
        console.print(f"[yellow]no nodes match target(s): {targets}[/yellow]")
        return int(ExitCode.SUCCESS)

    sources = set(args.source or [ME_NODE])

    _graph, chain_findings = compute_chains(edges, sources, sinks,
                                            max_depth=args.max_depth,
                                            top_k=args.top_k)
    collector = FindingCollector()
    collector.extend(chain_findings)

    print_summary(collector.all(), console)
    console.print()
    print_findings_console(collector.all(), Severity.LOW, console)

    if args.output:
        written = write_outputs(args.output, collector.all(), [args.format])
        for p in written:
            console.print(f"[green]wrote[/green] {p}")

    return from_findings(collector.all(), Severity.HIGH)
