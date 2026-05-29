"""Module: rights — DCSync, dangerous ACLs on privileged objects.

Emits structured `Edge`s and ready-to-paste recipes so the chain analyzer
can stitch ACL findings into full attack paths.
"""

from __future__ import annotations

from ldap3 import SUBTREE

from adex import recipes
from adex.findings import Edge, Finding, Severity
from adex.modules.base import ModuleBase, RunContext
from adex.utils import (
    DANGEROUS_WRITE_RIGHTS,
    DCSYNC_RIGHT_GUIDS,
    GENERIC_ALL,
    fetch_security_descriptor,
    find_dangerous_aces,
    find_extended_rights,
)

PRIV_GROUP_SAMS = [
    "Domain Admins",
    "Enterprise Admins",
    "Schema Admins",
    "Account Operators",
    "Backup Operators",
    "Server Operators",
    "Print Operators",
    "DnsAdmins",
]


def _edge_type_for_mask(mask: int) -> str:
    if mask & GENERIC_ALL:
        return "GenericAll"
    if mask & 0x00040000:
        return "WriteDACL"
    if mask & 0x00080000:
        return "WriteOwner"
    return "GenericWrite"


class RightsModule(ModuleBase):
    name = "rights"
    description = "DCSync, dangerous ACLs (WriteDACL/WriteOwner/GenericAll) on privileged objects"
    opsec_safe = True

    def run(self, ctx: RunContext) -> list[Finding]:
        sids = ctx.principal_sids
        if not sids:
            ctx.log.warning("rights: principal SIDs not resolved")
            return []
        findings: list[Finding] = []
        findings.extend(self._dcsync(ctx, sids))
        findings.extend(self._adminsdholder(ctx, sids))
        findings.extend(self._priv_groups(ctx, sids))
        findings.extend(self._admincount_users(ctx, sids))
        return findings

    def _dcsync(self, ctx: RunContext, sids: set[str]) -> list[Finding]:
        sd = fetch_security_descriptor(ctx.conn, ctx.base_dn)
        if not sd:
            return []
        hits = find_extended_rights(sd, sids, DCSYNC_RIGHT_GUIDS.keys())
        if not hits:
            return []
        rights_by_sid: dict[str, list[str]] = {}
        for h in hits:
            rights_by_sid.setdefault(h["sid"], []).append(DCSYNC_RIGHT_GUIDS[h["right"]])
        out = []
        username, password, nt_hash = ctx.auth.username, ctx.auth.password, ctx.auth.nt_hash
        for sid, rights in rights_by_sid.items():
            has_get = any(r == "DS-Replication-Get-Changes" for r in rights)
            has_all = any(r == "DS-Replication-Get-Changes-All" for r in rights)
            if has_get and has_all:
                out.append(Finding(
                    severity=Severity.CRITICAL,
                    module=self.name,
                    title="DCSync rights granted to current principal",
                    description=(
                        "Principal has both DS-Replication-Get-Changes and -All on the "
                        "domain head — full DCSync (secretsdump) is possible."
                    ),
                    target=ctx.base_dn,
                    evidence={"sid": sid, "rights": rights},
                    recipe=recipes.dcsync(ctx.auth.domain, ctx.dc, username or "",
                                          password, nt_hash),
                    edges=[Edge(src=ctx.me_node, dst=ctx.base_dn,
                                type="DCSync", dst_label="Domain (DCSync)", cost=1)],
                    references=["https://www.thehacker.recipes/ad/movement/credentials/dumping/dcsync"],
                    domain_context=ctx.domain_context,
                ))
            else:
                out.append(Finding(
                    severity=Severity.HIGH,
                    module=self.name,
                    title="Partial replication right granted to principal",
                    description="Has one but not both DCSync rights — review.",
                    target=ctx.base_dn,
                    evidence={"sid": sid, "rights": rights},
                    domain_context=ctx.domain_context,
                ))
        return out

    def _adminsdholder(self, ctx: RunContext, sids: set[str]) -> list[Finding]:
        dn = f"CN=AdminSDHolder,CN=System,{ctx.base_dn}"
        sd = fetch_security_descriptor(ctx.conn, dn)
        if not sd:
            return []
        aces = find_dangerous_aces(sd, sids, DANGEROUS_WRITE_RIGHTS)
        out = []
        for a in aces:
            out.append(Finding(
                severity=Severity.CRITICAL,
                module=self.name,
                title="Dangerous write right on AdminSDHolder",
                description=(
                    "AdminSDHolder template propagates to all protected groups every hour. "
                    "Write access = persistent admin in <1h."
                ),
                target=dn,
                evidence={"sid": a["sid"], "mask": hex(a["mask"]), "guid": a["guid"]},
                edges=[Edge(src=ctx.me_node, dst=dn,
                            type=_edge_type_for_mask(a["mask"]),
                            dst_label="AdminSDHolder", cost=2)],
                references=["https://adsecurity.org/?p=1906"],
                domain_context=ctx.domain_context,
            ))
        return out

    def _priv_groups(self, ctx: RunContext, sids: set[str]) -> list[Finding]:
        out: list[Finding] = []
        username, password, nt_hash = ctx.auth.username, ctx.auth.password, ctx.auth.nt_hash
        for sam in PRIV_GROUP_SAMS:
            ctx.conn.search(
                ctx.base_dn,
                f"(&(objectClass=group)(sAMAccountName={sam}))",
                search_scope=SUBTREE,
                attributes=["distinguishedName", "objectSid"],
            )
            if not ctx.conn.entries:
                continue
            dn = ctx.conn.entries[0].entry_dn
            grp_sid = str(ctx.conn.entries[0]["objectSid"]) if ctx.conn.entries[0]["objectSid"] else dn
            sd = fetch_security_descriptor(ctx.conn, dn)
            if not sd:
                continue
            aces = find_dangerous_aces(sd, sids, DANGEROUS_WRITE_RIGHTS)
            for a in aces:
                out.append(Finding(
                    severity=Severity.CRITICAL,
                    module=self.name,
                    title=f"Dangerous write right on {sam}",
                    description=f"Add yourself to {sam} → game over.",
                    target=dn,
                    evidence={"sid": a["sid"], "mask": hex(a["mask"]), "guid": a["guid"]},
                    recipe=recipes.add_member(sam, username or "<you>",
                                              ctx.auth.domain, ctx.dc,
                                              username or "", password, nt_hash),
                    edges=[Edge(src=ctx.me_node, dst=grp_sid,
                                type=_edge_type_for_mask(a["mask"]),
                                dst_label=sam, cost=1)],
                    domain_context=ctx.domain_context,
                ))
        return out

    def _admincount_users(self, ctx: RunContext, sids: set[str]) -> list[Finding]:
        ctx.conn.search(
            ctx.base_dn,
            "(&(objectCategory=person)(objectClass=user)(adminCount=1))",
            search_scope=SUBTREE,
            attributes=["distinguishedName", "sAMAccountName", "objectSid"],
            paged_size=200,
        )
        out: list[Finding] = []
        username, password, nt_hash = ctx.auth.username, ctx.auth.password, ctx.auth.nt_hash
        for entry in ctx.conn.entries:
            dn = entry.entry_dn
            sam = str(entry["sAMAccountName"])
            target_sid = str(entry["objectSid"]) if entry["objectSid"] else dn
            sd = fetch_security_descriptor(ctx.conn, dn)
            if not sd:
                continue
            aces = find_dangerous_aces(sd, sids, DANGEROUS_WRITE_RIGHTS)
            for a in aces:
                out.append(Finding(
                    severity=Severity.HIGH,
                    module=self.name,
                    title=f"Dangerous write right on protected user {sam}",
                    description="Principal can take over a protected (adminCount=1) account.",
                    target=dn,
                    evidence={"sid": a["sid"], "mask": hex(a["mask"]), "guid": a["guid"]},
                    recipe=recipes.genericwrite_password_reset(
                        dn, sam, ctx.auth.domain, ctx.dc,
                        username or "", password, nt_hash),
                    edges=[Edge(src=ctx.me_node, dst=target_sid,
                                type=_edge_type_for_mask(a["mask"]),
                                dst_label=sam, cost=1)],
                    domain_context=ctx.domain_context,
                ))
        return out
