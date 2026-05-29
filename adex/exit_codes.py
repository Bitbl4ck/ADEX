from __future__ import annotations

from collections.abc import Iterable
from enum import IntEnum

from adex.findings import Finding, Severity


class ExitCode(IntEnum):
    SUCCESS = 0
    FINDINGS = 1
    AUTH_FAIL = 2
    NET_FAIL = 3


def from_findings(findings: Iterable[Finding], threshold: Severity = Severity.HIGH) -> int:
    for f in findings:
        if f.severity >= threshold:
            return int(ExitCode.FINDINGS)
    return int(ExitCode.SUCCESS)
