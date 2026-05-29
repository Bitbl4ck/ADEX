from __future__ import annotations

from adex.findings import Severity


def parse_min_severity(value: str | None, verbose: bool) -> Severity:
    if verbose:
        return Severity.INFO
    if not value:
        return Severity.LOW
    return Severity.parse(value)


def parse_module_list(value: str | None) -> list[str] | None:
    if not value:
        return None
    return [p.strip() for p in value.split(",") if p.strip()]
