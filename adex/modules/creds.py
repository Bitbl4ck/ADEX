"""Module: creds — Kerberoastable, AS-REP roastable, gMSA, LAPS, SYSVOL."""

from __future__ import annotations

from ldap3 import SUBTREE
from ldap3.protocol.formatters.formatters import format_sid

from adex import recipes
from adex.findings import Edge, Finding, Severity
from adex.modules.base import ModuleBase, RunContext

# userAccountControl bits
UF_DONT_REQUIRE_PREAUTH = 0x400000


class CredsModule(ModuleBase):
    name = "creds"
    description = "Kerberoastable SPNs, AS-REP roastable, SYSVOL creds, gMSA, LAPS"
    opsec_safe = True

    def run(self, ctx: RunContext) -> list[Finding]:
        out: list[Finding] = []
        out.extend(self._kerberoastable(ctx))
        out.extend(self._asrep_roastable(ctx))
        out.extend(self._gmsa(ctx))
        out.extend(self._laps(ctx))
        return out

    def _attacker(self, ctx: RunContext) -> tuple[str | None, str | None, str | None]:
        return ctx.auth.username, ctx.auth.password, ctx.auth.nt_hash

    # ---- Kerberoast ----

    def _kerberoastable(self, ctx: RunContext) -> list[Finding]:
        ctx.conn.search(
            ctx.base_dn,
            "(&(samAccountType=805306368)(servicePrincipalName=*)(!(sAMAccountName=krbtgt)))",
            search_scope=SUBTREE,
            attributes=["sAMAccountName", "servicePrincipalName", "objectSid",
                        "distinguishedName", "memberOf"],
            paged_size=200,
        )
        username, password, nt_hash = self._attacker(ctx)
        out: list[Finding] = []
        for e in ctx.conn.entries:
            sam = str(e["sAMAccountName"])
            spns = list(e["servicePrincipalName"]) if e["servicePrincipalName"] else []
            sid = str(e["objectSid"]) if e["objectSid"] else None
            severity = Severity.HIGH
            member_of = [str(m) for m in (e["memberOf"] or [])]
            if any("Domain Admins" in m or "Enterprise Admins" in m for m in member_of):
                severity = Severity.CRITICAL
            out.append(Finding(
                severity=severity,
                module=self.name,
                title=f"Kerberoastable user: {sam}",
                description=(
                    "User has a Service Principal Name set, so any authenticated "
                    "principal can request a TGS for them and crack the resulting "
                    "TGS-REP offline if the password is weak."
                ),
                target=e.entry_dn,
                evidence={"sAMAccountName": sam, "spns": spns,
                          "memberOf": member_of[:5]},
                recipe=recipes.kerberoast(ctx.auth.domain, ctx.dc, sam,
                                          username, password, nt_hash),
                edges=[Edge(
                    src=ctx.me_node, dst=sid or e.entry_dn,
                    type="Kerberoast", dst_label=sam, cost=2,
                    context={"spns": spns},
                )] if sid else [],
                domain_context=ctx.domain_context,
                references=["https://www.thehacker.recipes/ad/movement/kerberos/kerberoast"],
            ))
        return out

    # ---- AS-REP roast ----

    def _asrep_roastable(self, ctx: RunContext) -> list[Finding]:
        flt = (f"(&(samAccountType=805306368)"
               f"(userAccountControl:1.2.840.113556.1.4.803:={UF_DONT_REQUIRE_PREAUTH}))")
        ctx.conn.search(
            ctx.base_dn, flt, search_scope=SUBTREE,
            attributes=["sAMAccountName", "objectSid", "distinguishedName", "memberOf"],
            paged_size=200,
        )
        username, _password, _nt_hash = self._attacker(ctx)
        out: list[Finding] = []
        for e in ctx.conn.entries:
            sam = str(e["sAMAccountName"])
            sid = str(e["objectSid"]) if e["objectSid"] else None
            member_of = [str(m) for m in (e["memberOf"] or [])]
            severity = Severity.HIGH
            if any("Domain Admins" in m or "Enterprise Admins" in m for m in member_of):
                severity = Severity.CRITICAL
            out.append(Finding(
                severity=severity,
                module=self.name,
                title=f"AS-REP roastable user: {sam}",
                description=(
                    "User has Kerberos pre-authentication disabled "
                    "(UF_DONT_REQUIRE_PREAUTH). Any host can request the AS-REP "
                    "and crack it offline."
                ),
                target=e.entry_dn,
                evidence={"sAMAccountName": sam, "memberOf": member_of[:5]},
                recipe=recipes.asrep_roast(ctx.auth.domain, ctx.dc, sam, username),
                edges=[Edge(
                    src=ctx.me_node, dst=sid or e.entry_dn,
                    type="ASREPRoast", dst_label=sam, cost=2,
                )] if sid else [],
                domain_context=ctx.domain_context,
                references=["https://www.thehacker.recipes/ad/movement/kerberos/asreproast"],
            ))
        return out

    # ---- gMSA ----

    def _gmsa(self, ctx: RunContext) -> list[Finding]:
        ctx.conn.search(
            ctx.base_dn,
            "(objectClass=msDS-GroupManagedServiceAccount)",
            search_scope=SUBTREE,
            attributes=["sAMAccountName", "objectSid",
                        "msDS-GroupMSAMembership", "distinguishedName"],
        )
        out: list[Finding] = []
        principal_sids = ctx.principal_sids
        username, password, nt_hash = self._attacker(ctx)
        for e in ctx.conn.entries:
            sam = str(e["sAMAccountName"]).rstrip("$")
            sid = str(e["objectSid"]) if e["objectSid"] else None
            membership_raw = e["msDS-GroupMSAMembership"].raw_values or []
            readable = self._gmsa_readable(membership_raw, principal_sids)
            if readable:
                out.append(Finding(
                    severity=Severity.HIGH,
                    module=self.name,
                    title=f"gMSA password readable: {sam}",
                    description=(
                        "Current principal is in msDS-GroupMSAMembership for this "
                        "service account, so the NT hash can be retrieved from "
                        "msDS-ManagedPassword."
                    ),
                    target=e.entry_dn,
                    evidence={"sAMAccountName": sam},
                    recipe=recipes.gmsa_read(sam, ctx.auth.domain, ctx.dc,
                                             username, password, nt_hash),
                    edges=[Edge(src=ctx.me_node, dst=sid or e.entry_dn,
                                type="GMSAReadable", dst_label=sam, cost=1)] if sid else [],
                    domain_context=ctx.domain_context,
                ))
            else:
                out.append(Finding(
                    severity=Severity.INFO,
                    module=self.name,
                    title=f"gMSA present: {sam}",
                    target=e.entry_dn,
                    evidence={"sAMAccountName": sam,
                              "note": "current principal not in msDS-GroupMSAMembership"},
                    domain_context=ctx.domain_context,
                ))
        return out

    @staticmethod
    def _gmsa_readable(sd_bytes_list, principal_sids: set[str]) -> bool:
        """msDS-GroupMSAMembership is a security descriptor with SIDs allowed
        to read the password. Return True if any of our SIDs appear."""
        try:
            from impacket.ldap.ldaptypes import SR_SECURITY_DESCRIPTOR
        except ImportError:
            return False
        for raw in sd_bytes_list:
            try:
                sd = SR_SECURITY_DESCRIPTOR(data=raw)
            except Exception:
                continue
            if not sd["Dacl"]:
                continue
            for ace in sd["Dacl"].aces:
                sid = format_sid(ace["Ace"]["Sid"].getData())
                if sid in principal_sids:
                    return True
        return False

    # ---- LAPS ----

    def _laps(self, ctx: RunContext) -> list[Finding]:
        """Probe for readable LAPS passwords. Domains that haven't deployed
        Windows LAPS won't have `msLAPS-Password` in schema and the older
        `ms-Mcs-AdmPwd` attribute may also be absent. We try each separately
        and ignore the schema-missing error so one missing attribute doesn't
        kill the whole module."""
        from ldap3.core.exceptions import LDAPAttributeError

        SAMPLE = 10
        username, password, nt_hash = self._attacker(ctx)
        readable: list[tuple[str, str]] = []
        flt = "(&(objectClass=computer)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))"
        for attr in ("ms-Mcs-AdmPwd", "msLAPS-Password"):
            try:
                ctx.conn.search(
                    ctx.base_dn, flt,
                    search_scope=SUBTREE,
                    attributes=["sAMAccountName", attr],
                    paged_size=SAMPLE,
                )
            except LDAPAttributeError:
                ctx.log.debug("[creds] LAPS attribute %s not in schema — skipping", attr)
                continue
            except Exception as e:
                ctx.log.debug("[creds] LAPS probe %s failed: %s", attr, e)
                continue
            for e in ctx.conn.entries[:SAMPLE]:
                sam = str(e["sAMAccountName"])
                try:
                    if e[attr] and e[attr].value:
                        readable.append((sam, attr))
                except Exception:
                    continue
        out: list[Finding] = []
        if readable:
            for sam, attr in readable:
                out.append(Finding(
                    severity=Severity.HIGH,
                    module=self.name,
                    title=f"LAPS password readable on {sam}",
                    description=(
                        "Current principal can read LAPS-managed local admin "
                        "password — yields local admin (NT hash via DCSync, "
                        "lateral movement via psexec/wmiexec)."
                    ),
                    target=sam,
                    evidence={"attribute": attr},
                    recipe=recipes.laps_read(sam, ctx.auth.domain, ctx.dc,
                                             username, password, nt_hash),
                    domain_context=ctx.domain_context,
                ))
        return out
