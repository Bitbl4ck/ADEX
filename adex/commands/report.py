"""`adex report` — convert and diff scan reports."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from rich.console import Console

from adex.exit_codes import ExitCode
from adex.findings import Finding
from adex.output import write_outputs


def add_parser(subparsers, common) -> None:
    p = subparsers.add_parser("report", help="Report utilities — convert formats, diff scans")
    sub = p.add_subparsers(dest="report_cmd", required=True)

    pc = sub.add_parser("convert", help="Convert a ADEX JSON report to HTML/TXT")
    pc.add_argument("--input", required=True, help="Path to JSON report")
    pc.add_argument("--output", required=True, help="Output base name")
    pc.add_argument("-f", "--format", default="all",
                    choices=["all", "html", "txt", "json"])
    pc.set_defaults(handler=handle_convert)

    pd = sub.add_parser("diff", help="Compare two ADEX JSON reports")
    pd.add_argument("--baseline", required=True)
    pd.add_argument("--current", required=True)
    pd.add_argument("--output", required=True, help="Output base for delta files")
    pd.add_argument("-f", "--format", default="all",
                    choices=["all", "html", "txt", "json"])
    pd.set_defaults(handler=handle_diff)


def _load_findings(path: str) -> list[Finding]:
    data = json.loads(Path(path).read_text())
    return [Finding.from_dict(f) for f in data.get("findings", [])]


def handle_convert(args: argparse.Namespace) -> int:
    console = Console()
    findings = _load_findings(args.input)
    written = write_outputs(args.output, findings, [args.format])
    for p in written:
        console.print(f"[green]wrote[/green] {p}")
    return int(ExitCode.SUCCESS)


def handle_diff(args: argparse.Namespace) -> int:
    console = Console()
    baseline = {f.fingerprint(): f for f in _load_findings(args.baseline)}
    current = {f.fingerprint(): f for f in _load_findings(args.current)}
    new = [f for fp, f in current.items() if fp not in baseline]
    resolved = [f for fp, f in baseline.items() if fp not in current]

    console.print(f"[bold]Diff:[/bold] {len(new)} new, {len(resolved)} resolved, "
                  f"{len(current) - len(new)} unchanged")

    # Tag findings so the renderer makes the delta obvious
    for f in new:
        f.evidence = {**(f.evidence or {}), "_delta": "new"}
    for f in resolved:
        f.evidence = {**(f.evidence or {}), "_delta": "resolved"}

    combined = new + resolved
    written = write_outputs(args.output, combined, [args.format],
                            extra={"delta": {"new": len(new), "resolved": len(resolved)}})
    for p in written:
        console.print(f"[green]wrote[/green] {p}")
    return int(ExitCode.SUCCESS) if not new else int(ExitCode.FINDINGS)


def handle(args: argparse.Namespace) -> int:  # pragma: no cover - dispatcher
    return args.handler(args)
