"""Console + JSON/HTML/TXT renderers for Findings."""

from __future__ import annotations

import json
from collections.abc import Iterable
from datetime import datetime, timezone
from pathlib import Path

from jinja2 import Environment, PackageLoader, select_autoescape
from rich.console import Console
from rich.table import Table

from adex.findings import Finding, Severity
from adex.version import __version__

SEVERITY_COLORS = {
    Severity.CRITICAL: "bold red",
    Severity.HIGH: "red",
    Severity.MEDIUM: "yellow",
    Severity.LOW: "blue",
    Severity.INFO: "dim",
}


def print_findings_console(findings: Iterable[Finding], min_severity: Severity = Severity.LOW,
                           console: Console | None = None) -> None:
    console = console or Console()
    items = sorted(
        [f for f in findings if f.severity >= min_severity],
        key=lambda f: (-int(f.severity), f.module, f.title),
    )
    if not items:
        console.print("[dim]no findings at or above the selected severity[/dim]")
        return
    table = Table(show_lines=False, header_style="bold")
    table.add_column("Severity", no_wrap=True)
    table.add_column("Module", no_wrap=True)
    table.add_column("Title")
    table.add_column("Target", overflow="fold")
    for f in items:
        sev_style = SEVERITY_COLORS.get(f.severity, "")
        table.add_row(
            f"[{sev_style}]{f.severity.name}[/{sev_style}]" if sev_style else f.severity.name,
            f.module,
            f.title,
            f.target,
        )
    console.print(table)


def print_summary(findings: Iterable[Finding], console: Console | None = None) -> None:
    console = console or Console()
    counts = {s: 0 for s in Severity}
    for f in findings:
        counts[f.severity] += 1
    parts = []
    for s in (Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO):
        style = SEVERITY_COLORS.get(s, "")
        parts.append(f"[{style}]{counts[s]} {s.name}[/{style}]" if style else f"{counts[s]} {s.name}")
    console.print("Summary: " + "  ".join(parts))


def _payload(findings: Iterable[Finding], extra: dict | None = None) -> dict:
    items = list(findings)
    payload = {
        "tool": "adex",
        "version": __version__,
        "generated": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "count": len(items),
        "findings": [f.to_dict() for f in items],
    }
    if extra:
        payload.update(extra)
    return payload


def write_json(path: str | Path, findings: Iterable[Finding], extra: dict | None = None) -> Path:
    p = Path(path)
    p.write_text(json.dumps(_payload(findings, extra), indent=2))
    return p


def write_txt(path: str | Path, findings: Iterable[Finding]) -> Path:
    p = Path(path)
    items = sorted(list(findings), key=lambda f: (-int(f.severity), f.module, f.title))
    lines = []
    lines.append(f"# ADEX {__version__} report")
    lines.append(f"# Generated: {datetime.now(timezone.utc).isoformat(timespec='seconds')}")
    lines.append(f"# Findings: {len(items)}")
    lines.append("")
    for f in items:
        prefix = f"({f.domain_context}) " if f.domain_context else ""
        lines.append(f"[{f.severity.name}] {prefix}({f.module}) {f.title}")
        if f.target:
            lines.append(f"  target: {f.target}")
        if f.description:
            lines.append(f"  desc:   {f.description}")
        for k, v in (f.evidence or {}).items():
            lines.append(f"  {k}: {v}")
        if f.recipe:
            lines.append("  recipe:")
            for cmd in f.recipe:
                lines.append(f"    {cmd}")
        for r in f.references or []:
            lines.append(f"  ref: {r}")
        lines.append("")
    p.write_text("\n".join(lines))
    return p


def _jinja_env() -> Environment:
    return Environment(
        loader=PackageLoader("adex", "templates"),
        autoescape=select_autoescape(["html", "j2"]),
    )


def write_html(path: str | Path, findings: Iterable[Finding], extra: dict | None = None) -> Path:
    p = Path(path)
    env = _jinja_env()
    tpl = env.get_template("report.html.j2")
    items = sorted(list(findings), key=lambda f: (-int(f.severity), f.module, f.title))
    counts = {s.name: 0 for s in Severity}
    for f in items:
        counts[f.severity.name] += 1
    rendered = tpl.render(
        tool="adex",
        version=__version__,
        generated=datetime.now(timezone.utc).isoformat(timespec="seconds"),
        findings=[f.to_dict() for f in items],
        counts=counts,
        total=len(items),
        extra=extra or {},
    )
    p.write_text(rendered)
    return p


def write_outputs(base: str, findings: Iterable[Finding], formats: list[str],
                  extra: dict | None = None) -> list[Path]:
    """Write any combination of json/html/txt files using `base` as stem."""
    items = list(findings)
    written = []
    if "all" in formats:
        formats = ["json", "html", "txt"]
    if "json" in formats:
        written.append(write_json(f"{base}.json", items, extra))
    if "html" in formats:
        written.append(write_html(f"{base}.html", items, extra))
    if "txt" in formats:
        written.append(write_txt(f"{base}.txt", items))
    return written
