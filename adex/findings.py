from __future__ import annotations

import hashlib
from collections.abc import Iterable, Iterator
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from enum import IntEnum


class Severity(IntEnum):
    INFO = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4

    @classmethod
    def parse(cls, value: str | int | Severity) -> Severity:
        if isinstance(value, Severity):
            return value
        if isinstance(value, int):
            return Severity(value)
        return cls[value.strip().upper()]

    def __str__(self) -> str:
        return self.name


# Edge types — keep this list explicit so chain.py can switch on it.
EDGE_TYPES = {
    "GenericAll",
    "GenericWrite",
    "WriteDACL",
    "WriteOwner",
    "WriteSPN",
    "AddSelf",
    "DCSync",
    "Kerberoast",
    "ASREPRoast",
    "RBCDInbound",       # target ALREADY allows controlled principal to delegate
    "RBCDWritable",      # principal can WRITE msDS-AllowedToActOnBehalfOf...
    "KeyCredentialWrite",
    "ESC1",
    "ESC2",
    "ESC3",
    "ESC4",
    "ESC5",
    "ESC6",
    "ESC7",
    "ESC8",
    "ESC9",
    "ESC11",
    "ESC13",
    "ESC15",
    "Unconstrained",
    "ConstrainedDelegation",
    "ResetPassword",
    "AddMember",
    "OwnsCert",
    "GMSAReadable",
}


@dataclass
class Edge:
    """A single capability edge in the AD attack graph.

    `src` is the SID of the principal that has the capability.
    `dst` is a SID for principals/groups, or a DN for objects without a SID
    (template DNs, AdminSDHolder, etc.).
    """
    src: str
    dst: str
    type: str
    dst_label: str = ""
    cost: int = 1
    context: dict = field(default_factory=dict)

    def __post_init__(self) -> None:
        if self.type not in EDGE_TYPES:
            raise ValueError(f"unknown edge type: {self.type!r}")

    def to_dict(self) -> dict:
        return asdict(self)

    @classmethod
    def from_dict(cls, d: dict) -> Edge:
        return cls(**d)


@dataclass
class Finding:
    severity: Severity
    module: str
    title: str
    description: str = ""
    target: str = ""
    evidence: dict = field(default_factory=dict)
    references: list[str] = field(default_factory=list)
    recipe: list[str] = field(default_factory=list)
    edges: list[Edge] = field(default_factory=list)
    domain_context: str = ""
    timestamp: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat(timespec="seconds")
    )

    def fingerprint(self) -> str:
        """Stable identity for diffing across scans."""
        h = hashlib.sha1()
        h.update(self.module.encode())
        h.update(b"\x00")
        h.update(self.title.encode())
        h.update(b"\x00")
        h.update(self.target.encode())
        h.update(b"\x00")
        h.update(self.domain_context.encode())
        return h.hexdigest()[:16]

    def to_dict(self) -> dict:
        d = asdict(self)
        d["severity"] = self.severity.name
        d["fingerprint"] = self.fingerprint()
        return d

    @classmethod
    def from_dict(cls, d: dict) -> Finding:
        data = dict(d)
        data.pop("fingerprint", None)
        sev = data.get("severity")
        if isinstance(sev, str):
            data["severity"] = Severity[sev]
        edges_raw = data.get("edges") or []
        data["edges"] = [Edge.from_dict(e) if isinstance(e, dict) else e for e in edges_raw]
        return cls(**data)


class FindingCollector:
    def __init__(self) -> None:
        self._items: list[Finding] = []

    def add(self, f: Finding) -> None:
        self._items.append(f)

    def extend(self, fs: Iterable[Finding]) -> None:
        self._items.extend(fs)

    def __iter__(self) -> Iterator[Finding]:
        return iter(self._items)

    def __len__(self) -> int:
        return len(self._items)

    def filtered(self, min_severity: Severity = Severity.LOW) -> list[Finding]:
        return [f for f in self._items if f.severity >= min_severity]

    def by_severity(self) -> dict[str, int]:
        out = {s.name: 0 for s in Severity}
        for f in self._items:
            out[f.severity.name] += 1
        return out

    def all(self) -> list[Finding]:
        return list(self._items)

    def all_edges(self) -> list[Edge]:
        out: list[Edge] = []
        for f in self._items:
            out.extend(f.edges)
        return out
