"""Module: delegation — unconstrained, constrained, RBCD."""

from __future__ import annotations

from ldap3 import SUBTREE
from ldap3.protocol.formatters.formatters import format_sid

from adex import recipes
from adex.findings import Edge, Finding, Severity
from adex.modules.base import ModuleBase, RunContext
from adex.utils import (
    DANGEROUS_WRITE_RIGHTS,
    fetch_security_descriptor,
    find_dangerous_aces,
)

# UF flags
UF_TRUSTED_FOR_DELEGATION = 0x80000          # unconstrained
UF_TRUSTED_TO_AUTH_FOR_DELEGATION = 0x1000000  # constrained-with-protocol-transition
UF_SERVER_TRUST_ACCOUNT = 0x2000              # DC


class DelegationModule(ModuleBase):
    name = "delegation"
    description = "Unconstrained, constrained, RBCD"
    opsec_safe = True

    def run(self, ctx: RunContext) -> list[Finding]:
        out: list[Finding] = []
        out.extend(self._unconstrained(ctx))
        out.extend(self._constrained(ctx))
        out.extend(self._rbcd_inbound(ctx))
        out.extend(self._rbcd_writable(ctx))
        return out

    # ---- Unconstrained ----

    def _unconstrained(self, ctx: RunContext) -> list[Finding]:
        flt = (f"(&(|(objectClass=computer)(objectClass=user))"
               f"(userAccountControl:1.2.840.113556.1.4.803:={UF_TRUSTED_FOR_DELEGATION}))")
        ctx.conn.search(
            ctx.base_dn, flt, search_scope=SUBTREE,
            attributes=["sAMAccountName", "userAccountControl",
                        "objectSid", "distinguishedName"],
            paged_size=200,
        )
        out: list[Finding] = []
        for e in ctx.conn.entries:
            uac = int(e["userAccountControl"].value or 0)
            sam = str(e["sAMAccountName"])
            sid = str(e["objectSid"]) if e["objectSid"] else None
            # DCs are always TRUSTED_FOR_DELEGATION; that's expected.
            if uac & UF_SERVER_TRUST_ACCOUNT:
                continue
            out.append(Finding(
                severity=Severity.HIGH,
                module=self.name,
                title=f"Unconstrained delegation: {sam}",
                description=(
                    "Account holds TGTs for any user that authenticates to it "
                    "(SPN coercion + user lured = full TGT theft)."
                ),
                target=e.entry_dn,
                evidence={"sAMAccountName": sam, "userAccountControl": hex(uac)},
                recipe=recipes.unconstrained_coerce(sam, ctx.auth.domain, ctx.dc,
                                                   "tun0"),
                edges=[Edge(src=ctx.me_node, dst=sid or e.entry_dn,
                            type="Unconstrained", dst_label=sam, cost=3)] if sid else [],
                domain_context=ctx.domain_context,
                references=[
                    "https://www.thehacker.recipes/ad/movement/kerberos/delegations/unconstrained",
                ],
            ))
        return out

    # ---- Constrained ----

    def _constrained(self, ctx: RunContext) -> list[Finding]:
        ctx.conn.search(
            ctx.base_dn,
            "(msDS-AllowedToDelegateTo=*)",
            search_scope=SUBTREE,
            attributes=["sAMAccountName", "userAccountControl",
                        "msDS-AllowedToDelegateTo", "objectSid"],
            paged_size=200,
        )
        out: list[Finding] = []
        for e in ctx.conn.entries:
            sam = str(e["sAMAccountName"])
            uac = int(e["userAccountControl"].value or 0)
            spns = list(e["msDS-AllowedToDelegateTo"]) if e["msDS-AllowedToDelegateTo"] else []
            sid = str(e["objectSid"]) if e["objectSid"] else None
            protocol_transition = bool(uac & UF_TRUSTED_TO_AUTH_FOR_DELEGATION)
            sev = Severity.HIGH if protocol_transition else Severity.MEDIUM
            out.append(Finding(
                severity=sev,
                module=self.name,
                title=f"Constrained delegation: {sam} -> {len(spns)} SPN(s)",
                description=(
                    "Account can delegate to specific services. With protocol "
                    "transition (TRUSTED_TO_AUTH_FOR_DELEGATION) you can use "
                    "S4U2Self+S4U2Proxy to impersonate any user."
                ),
                target=e.entry_dn,
                evidence={"sAMAccountName": sam, "spns": spns,
                          "protocolTransition": protocol_transition},
                recipe=recipes.constrained_s4u(sam, spns[0] if spns else "<spn>",
                                               "Administrator",
                                               ctx.auth.domain, ctx.dc,
                                               ctx.auth.nt_hash),
                edges=[Edge(src=ctx.me_node, dst=sid or e.entry_dn,
                            type="ConstrainedDelegation", dst_label=sam, cost=2)]
                      if sid and protocol_transition else [],
                domain_context=ctx.domain_context,
            ))
        return out

    # ---- RBCD inbound (already-configured) ----

    def _rbcd_inbound(self, ctx: RunContext) -> list[Finding]:
        ctx.conn.search(
            ctx.base_dn,
            "(msDS-AllowedToActOnBehalfOfOtherIdentity=*)",
            search_scope=SUBTREE,
            attributes=["sAMAccountName", "objectSid",
                        "msDS-AllowedToActOnBehalfOfOtherIdentity",
                        "distinguishedName"],
        )
        out: list[Finding] = []
        for e in ctx.conn.entries:
            sam = str(e["sAMAccountName"])
            sid = str(e["objectSid"]) if e["objectSid"] else None
            sd_raw = e["msDS-AllowedToActOnBehalfOfOtherIdentity"].raw_values
            allowed = self._parse_allowed_to_act(sd_raw)
            out.append(Finding(
                severity=Severity.HIGH,
                module=self.name,
                title=f"RBCD configured on {sam} ({len(allowed)} principal(s))",
                description=(
                    "Listed principals can request a TGS impersonating any user "
                    "for services on this target (S4U2Self+S4U2Proxy)."
                ),
                target=e.entry_dn,
                evidence={"sAMAccountName": sam, "allowedSids": allowed},
                edges=[Edge(src=allowed_sid, dst=sid or e.entry_dn,
                            type="RBCDInbound", dst_label=sam, cost=1)
                       for allowed_sid in allowed if sid],
                domain_context=ctx.domain_context,
            ))
        return out

    @staticmethod
    def _parse_allowed_to_act(raw_values) -> list[str]:
        try:
            from impacket.ldap.ldaptypes import SR_SECURITY_DESCRIPTOR
        except ImportError:
            return []
        out: list[str] = []
        for raw in raw_values or []:
            try:
                sd = SR_SECURITY_DESCRIPTOR(data=raw)
            except Exception:
                continue
            if not sd["Dacl"]:
                continue
            for ace in sd["Dacl"].aces:
                sid = format_sid(ace["Ace"]["Sid"].getData())
                out.append(sid)
        return out

    # ---- RBCD writable (you can ADD an entry) ----

    def _rbcd_writable(self, ctx: RunContext) -> list[Finding]:
        # Look for computers we can write msDS-AllowedToActOnBehalfOfOtherIdentity on.
        # That requires WriteProperty on the attribute or any of GenericAll/Write/WriteDACL.
        # For performance, only check a sample of computers + DCs.
        ctx.conn.search(
            ctx.base_dn, "(objectClass=computer)",
            search_scope=SUBTREE,
            attributes=["sAMAccountName", "objectSid", "distinguishedName"],
            paged_size=300,
        )
        out: list[Finding] = []
        username, password, nt_hash = ctx.auth.username, ctx.auth.password, ctx.auth.nt_hash
        principal_sids = ctx.principal_sids
        for entry in ctx.conn.entries[:200]:
            dn = entry.entry_dn
            sam = str(entry["sAMAccountName"])
            sid = str(entry["objectSid"]) if entry["objectSid"] else None
            sd = fetch_security_descriptor(ctx.conn, dn)
            if not sd:
                continue
            aces = find_dangerous_aces(sd, principal_sids, DANGEROUS_WRITE_RIGHTS)
            if not aces:
                continue
            # Pick a synthetic controlled-computer name for the recipe
            controlled = "ADEX-PWN$"
            out.append(Finding(
                severity=Severity.CRITICAL,
                module=self.name,
                title=f"RBCD attack possible against {sam}",
                description=(
                    "Current principal has dangerous write rights on the target "
                    "computer object — they can write "
                    "msDS-AllowedToActOnBehalfOfOtherIdentity to point at a "
                    "controlled computer account, then S4U their way to local "
                    "admin/SYSTEM on the target."
                ),
                target=dn,
                evidence={"target": sam,
                          "grantedAces": [{"sid": a["sid"], "mask": hex(a["mask"])} for a in aces]},
                recipe=recipes.rbcd_write(ctx.auth.domain, ctx.dc, sam, controlled,
                                          username or "", password, nt_hash),
                edges=[Edge(src=ctx.me_node, dst=sid or dn,
                            type="RBCDWritable", dst_label=sam, cost=2)] if sid else [],
                domain_context=ctx.domain_context,
                references=["https://www.thehacker.recipes/ad/movement/kerberos/delegations/rbcd"],
            ))
        return out
