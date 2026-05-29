"""Module: domain — functional level, MAQ, password policy, signing, trusts."""

from __future__ import annotations

from ldap3 import SUBTREE

from adex.findings import Finding, Severity
from adex.modules.base import ModuleBase, RunContext
from adex.utils import FUNC_LEVEL


class DomainModule(ModuleBase):
    name = "domain"
    description = "Domain info, functional level, trusts, password policy, LDAP/SMB signing"
    opsec_safe = True

    def run(self, ctx: RunContext) -> list[Finding]:
        findings: list[Finding] = []
        findings.extend(self._functional_level(ctx))
        findings.extend(self._machine_account_quota(ctx))
        findings.extend(self._password_policy(ctx))
        findings.extend(self._trusts(ctx))
        findings.extend(self._ldap_signing(ctx))
        findings.extend(self._smb_signing(ctx))
        return findings

    # ---- helpers ----

    def _read_domain_root(self, ctx: RunContext, attrs: list[str]) -> dict:
        ctx.conn.search(ctx.base_dn, "(objectClass=*)", search_scope="BASE", attributes=attrs)
        if not ctx.conn.entries:
            return {}
        e = ctx.conn.entries[0]
        return {a: e[a].value for a in attrs if a in e}

    def _functional_level(self, ctx: RunContext) -> list[Finding]:
        info = self._read_domain_root(ctx, ["msDS-Behavior-Version", "name"])
        raw = info.get("msDS-Behavior-Version")
        if raw is None:
            return []
        level = int(raw)
        label = FUNC_LEVEL.get(level, f"unknown ({level})")
        sev = Severity.INFO if level >= 7 else Severity.LOW
        return [Finding(
            severity=sev,
            module=self.name,
            title=f"Domain functional level: {label}",
            description=(
                "Functional level controls which features are available. "
                "Levels below Windows 2016 lack support for KeyCredentials "
                "(Shadow Credentials)."
            ),
            target=ctx.base_dn,
            evidence={"msDS-Behavior-Version": level, "label": label},
        )]

    def _machine_account_quota(self, ctx: RunContext) -> list[Finding]:
        info = self._read_domain_root(ctx, ["ms-DS-MachineAccountQuota"])
        maq = info.get("ms-DS-MachineAccountQuota")
        if maq is None:
            return []
        maq = int(maq)
        if maq <= 0:
            sev = Severity.INFO
            title = "MachineAccountQuota is 0 (good)"
        elif maq >= 10:
            sev = Severity.MEDIUM
            title = f"MachineAccountQuota is {maq} (default permits authenticated users to add computers)"
        else:
            sev = Severity.LOW
            title = f"MachineAccountQuota is {maq}"
        return [Finding(
            severity=sev,
            module=self.name,
            title=title,
            description=(
                "ms-DS-MachineAccountQuota controls how many computer accounts a "
                "non-admin user can add to the domain. >0 enables a number of "
                "abuse paths (RBCD, Shadow Credentials with attacker-controlled "
                "computer)."
            ),
            target=ctx.base_dn,
            evidence={"ms-DS-MachineAccountQuota": maq},
            references=[
                "https://www.thehacker.recipes/ad/movement/dacl/grant-rights/rbcd",
            ],
        )]

    def _password_policy(self, ctx: RunContext) -> list[Finding]:
        attrs = ["minPwdLength", "lockoutThreshold", "maxPwdAge", "pwdProperties",
                 "pwdHistoryLength"]
        info = self._read_domain_root(ctx, attrs)
        if not info:
            return []
        out: list[Finding] = []
        min_len = info.get("minPwdLength")
        if min_len is not None and int(min_len) < 8:
            out.append(Finding(
                severity=Severity.MEDIUM,
                module=self.name,
                title=f"Minimum password length is {min_len}",
                description="Password policies under 8 characters fall short of common baselines.",
                target=ctx.base_dn,
                evidence={"minPwdLength": int(min_len)},
            ))
        lt = info.get("lockoutThreshold")
        if lt is not None and int(lt) == 0:
            out.append(Finding(
                severity=Severity.MEDIUM,
                module=self.name,
                title="Account lockout disabled (lockoutThreshold = 0)",
                description="No lockout = unlimited password spraying / brute force on every account.",
                target=ctx.base_dn,
                evidence={"lockoutThreshold": 0},
            ))
        return out

    def _trusts(self, ctx: RunContext) -> list[Finding]:
        ctx.conn.search(
            f"CN=System,{ctx.base_dn}",
            "(objectClass=trustedDomain)",
            search_scope=SUBTREE,
            attributes=["trustPartner", "trustDirection", "trustAttributes", "trustType"],
        )
        out: list[Finding] = []
        for entry in ctx.conn.entries:
            attrs = int(entry["trustAttributes"].value or 0)
            direction = int(entry["trustDirection"].value or 0)
            partner = str(entry["trustPartner"].value or "")
            tquar = bool(attrs & 0x4)        # TRUST_ATTRIBUTE_QUARANTINED_DOMAIN
            forest = bool(attrs & 0x8)       # TRUST_ATTRIBUTE_FOREST_TRANSITIVE
            tcross = bool(attrs & 0x10)      # CROSS_ORGANIZATION
            sev = Severity.INFO
            note = "informational"
            if direction == 3 and not tquar:
                sev = Severity.LOW
                note = "bidirectional trust without SID-filter quarantine"
            out.append(Finding(
                severity=sev,
                module=self.name,
                title=f"Trust to {partner} ({note})",
                description="Trust relationships expand the attack surface across forests/domains.",
                target=ctx.base_dn,
                evidence={
                    "trustPartner": partner,
                    "trustDirection": direction,
                    "trustAttributes": hex(attrs),
                    "forest": forest,
                    "quarantined": tquar,
                    "crossOrganization": tcross,
                },
            ))
        return out

    def _ldap_signing(self, ctx: RunContext) -> list[Finding]:
        """Probe TCP 389 with NTLM bind (no signing). Success = enforcement off."""
        from ldap3 import NTLM, Connection, Server
        from ldap3.core.exceptions import LDAPException

        # Only meaningful for password/hash auth
        if ctx.auth.primary_method not in {"password", "hash"}:
            return []
        try:
            srv = Server(ctx.dc, port=389, use_ssl=False, connect_timeout=10)
            cred = ctx.auth.password if ctx.auth.primary_method == "password" else \
                   ":".join(ctx.auth.lm_nt())
            c = Connection(srv, user=f"{ctx.auth.domain}\\{ctx.auth.username}",
                           password=cred, authentication=NTLM)
            ok = c.bind()
            if ok and c.bound:
                f = Finding(
                    severity=Severity.HIGH,
                    module=self.name,
                    title="LDAP signing not enforced on port 389",
                    description=(
                        "Unsigned NTLM bind to LDAP succeeded; the DC accepts "
                        "unsigned NTLM relay. Combined with auth coercion this "
                        "allows ntlmrelayx -> ldap:// abuse paths."
                    ),
                    target=ctx.dc,
                    evidence={"port": 389, "binding": "NTLM (unsigned)"},
                    references=[
                        "https://github.com/zyn3rgy/LdapRelayScan",
                    ],
                )
                c.unbind()
                return [f]
        except LDAPException as e:
            msg = str(e).lower()
            if "stronger" in msg or "80090346" in msg or "8202" in msg:
                return [Finding(
                    severity=Severity.INFO,
                    module=self.name,
                    title="LDAP signing enforced on port 389 (good)",
                    target=ctx.dc,
                    evidence={"detail": str(e)[:200]},
                )]
        except Exception as e:
            ctx.log.debug("ldap signing probe failed: %s", e)
        return []

    def _smb_signing(self, ctx: RunContext) -> list[Finding]:
        try:
            from impacket.smbconnection import SMBConnection
        except ImportError:
            return []
        try:
            smb = SMBConnection(ctx.dc, ctx.dc, sess_port=445, timeout=10)
            required = smb.isSigningRequired()
            smb.close()
        except Exception as e:
            ctx.log.debug("smb signing probe failed: %s", e)
            return []
        if required:
            return [Finding(
                severity=Severity.INFO,
                module=self.name,
                title="SMB signing required (good)",
                target=ctx.dc,
                evidence={"signingRequired": True},
            )]
        return [Finding(
            severity=Severity.HIGH,
            module=self.name,
            title="SMB signing not required",
            description=(
                "DC does not require SMB signing — enables ntlmrelayx -> SMB "
                "relay attacks and various MITM scenarios."
            ),
            target=ctx.dc,
            evidence={"signingRequired": False},
            references=["https://www.thehacker.recipes/ad/movement/ntlm/relay"],
        )]
