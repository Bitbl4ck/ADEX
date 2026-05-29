"""Module ABC and the runtime context passed to every module."""

from __future__ import annotations

import logging
from abc import ABC, abstractmethod
from dataclasses import dataclass, field

from ldap3 import Connection

from adex.auth import Auth
from adex.findings import Finding

# Synthetic graph node representing "the bound principal" — used as the
# `src` of every edge a module emits. The chain analyzer adds zero-cost
# edges from ME to each of the principal's actual SIDs (own + tokenGroups)
# so paths that need to be reachable through any group still resolve.
ME_NODE = "ME"


@dataclass
class RunContext:
    conn: Connection
    auth: Auth
    base_dn: str
    dc: str
    use_ldaps: bool
    log: logging.Logger
    principal_sids: set[str] = field(default_factory=set)
    me_node: str = ME_NODE
    domain_context: str = ""  # tag findings when --map-trusts traverses domains


class ModuleBase(ABC):
    name: str = ""
    description: str = ""
    opsec_safe: bool = True
    implemented: bool = True

    @abstractmethod
    def run(self, ctx: RunContext) -> list[Finding]:
        ...
