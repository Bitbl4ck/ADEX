"""Module: adcs — ADCS misconfiguration scanner.

Phase 2 covers ESC1 and ESC8. ESC2-7 and ESC9-16 are explicitly INFO-logged
for transparency; Phase 3 expands coverage.

ESC1: template allows the enrollee to supply the subject (SAN) AND grants
client-auth EKU AND the enroll ACL grants the current principal. → Enroll a
cert as any user, including Domain Admins.

ESC8: the CA exposes an HTTP enrollment endpoint vulnerable to NTLM relay
from coerced machine accounts.
"""

from __future__ import annotations

import socket
import ssl
from urllib.request import Request, urlopen

from ldap3 import SUBTREE
from ldap3.protocol.formatters.formatters import format_sid
from ldap3.protocol.microsoft import security_descriptor_control

from adex import recipes
from adex.findings import Edge, Finding, Severity
from adex.modules.base import ModuleBase, RunContext

# mspki-certificate-name-flag bits
CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT = 0x00000001
CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT_ALT_NAME = 0x00010000

# mspki-enrollment-flag bits
CT_FLAG_PEND_ALL_REQUESTS = 0x00000002

# Authentication-suitable EKUs
AUTH_EKUS = {
    "1.3.6.1.5.5.7.3.2",            # Client Authentication
    "1.3.6.1.5.2.3.4",              # PKINIT Client Authentication
    "1.3.6.1.4.1.311.20.2.2",       # Smartcard Logon
    "2.5.29.37.0",                  # Any Purpose
}

# Microsoft "Certificate-Enrollment" extended-right GUID
CERT_ENROLLMENT_RIGHT = "0e10c968-78fb-11d2-90d4-00c04f79dc55"
CERT_AUTOENROLLMENT_RIGHT = "a05b8cc2-17bc-4802-a710-e7c15ab866a2"


class AdcsModule(ModuleBase):
    name = "adcs"
    description = "ADCS misconfigurations — ESC1, ESC8 (Phase 2)"
    opsec_safe = True

    def run(self, ctx: RunContext) -> list[Finding]:
        config_nc = self._configuration_nc(ctx)
        if not config_nc:
            ctx.log.warning("[adcs] no Configuration NC found")
            return []
        cas = self._enumerate_cas(ctx, config_nc)
        if not cas:
            ctx.log.info("[adcs] no Enterprise CAs found")
            return []
        out: list[Finding] = []
        out.extend(self._enumerate_templates(ctx, config_nc, cas))
        out.extend(self._esc8_probe(ctx, cas))
        # Transparent gap-noting for the unimplemented ESCs
        out.append(Finding(
            severity=Severity.INFO,
            module=self.name,
            title="ESC2-7, ESC9-16 not yet checked",
            description="Phase 2 covers ESC1 + ESC8. Other vectors will land in Phase 3.",
            domain_context=ctx.domain_context,
        ))
        return out

    # ---- helpers ----

    def _configuration_nc(self, ctx: RunContext) -> str | None:
        info = ctx.conn.server.info
        if info and info.other:
            cnc = info.other.get("configurationNamingContext")
            if isinstance(cnc, list) and cnc:
                return cnc[0]
            if isinstance(cnc, str):
                return cnc
        # Fallback: derive from base_dn
        return f"CN=Configuration,{ctx.base_dn}" if ctx.base_dn else None

    def _enumerate_cas(self, ctx: RunContext, config_nc: str) -> list[dict]:
        ctx.conn.search(
            f"CN=Enrollment Services,CN=Public Key Services,CN=Services,{config_nc}",
            "(objectClass=pKIEnrollmentService)",
            search_scope=SUBTREE,
            attributes=["cn", "dNSHostName", "certificateTemplates", "displayName"],
        )
        out = []
        for e in ctx.conn.entries:
            out.append({
                "cn": str(e["cn"]),
                "dns": str(e["dNSHostName"]) if e["dNSHostName"] else "",
                "templates": list(e["certificateTemplates"]) if e["certificateTemplates"] else [],
                "displayName": str(e["displayName"]) if e["displayName"] else "",
            })
        return out

    def _enumerate_templates(self, ctx: RunContext, config_nc: str,
                             cas: list[dict]) -> list[Finding]:
        published = set()
        for ca in cas:
            for t in ca["templates"]:
                published.add(str(t).lower())

        ctx.conn.search(
            f"CN=Certificate Templates,CN=Public Key Services,CN=Services,{config_nc}",
            "(objectClass=pKICertificateTemplate)",
            search_scope=SUBTREE,
            attributes=["cn", "displayName", "msPKI-Certificate-Name-Flag",
                        "msPKI-Enrollment-Flag", "pKIExtendedKeyUsage",
                        "nTSecurityDescriptor"],
            controls=security_descriptor_control(sdflags=0x04),
        )
        username, password, nt_hash = ctx.auth.username, ctx.auth.password, ctx.auth.nt_hash
        out: list[Finding] = []
        for e in ctx.conn.entries:
            cn = str(e["cn"])
            if cn.lower() not in published:
                continue  # not actually issued by any CA
            display = str(e["displayName"]) if e["displayName"] else cn
            name_flag = int(e["msPKI-Certificate-Name-Flag"].value or 0)
            enroll_flag = int(e["msPKI-Enrollment-Flag"].value or 0)
            ekus = list(e["pKIExtendedKeyUsage"]) if e["pKIExtendedKeyUsage"] else []
            ekus_set = set(map(str, ekus))

            esc1_supplies = bool(name_flag & CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT)
            esc1_auth_eku = bool(ekus_set & AUTH_EKUS) or not ekus
            ca_manager_approval = bool(enroll_flag & CT_FLAG_PEND_ALL_REQUESTS)
            sd_raw = e["nTSecurityDescriptor"].raw_values
            enroll_grants_principal = self._enroll_acl_grants(sd_raw, ctx.principal_sids)

            if (esc1_supplies and esc1_auth_eku
                    and not ca_manager_approval and enroll_grants_principal):
                ca_name = next((c["cn"] for c in cas if cn.lower() in [t.lower() for t in c["templates"]]), cas[0]["cn"])
                target_upn = f"administrator@{ctx.auth.domain}"
                out.append(Finding(
                    severity=Severity.CRITICAL,
                    module=self.name,
                    title=f"ESC1 vulnerable template: {display}",
                    description=(
                        "Template lets the enrollee supply the subject (SAN), "
                        "issues client-auth EKU, doesn't require manager approval, "
                        "and the enroll ACL allows the current principal. Enroll "
                        "a cert as any user (incl. Domain Admin) and PKINIT in."
                    ),
                    target=display,
                    evidence={
                        "template": display,
                        "ca": ca_name,
                        "msPKI-Certificate-Name-Flag": hex(name_flag),
                        "msPKI-Enrollment-Flag": hex(enroll_flag),
                        "ekus": list(ekus_set),
                    },
                    recipe=recipes.esc1(ca_name, display, target_upn,
                                        ctx.auth.domain, ctx.dc,
                                        username or "", password, nt_hash),
                    edges=[Edge(src=ctx.me_node, dst=f"ESC1:{display}",
                                type="ESC1", dst_label=f"ESC1 via {display}", cost=1,
                                context={"template": display, "ca": ca_name})],
                    domain_context=ctx.domain_context,
                    references=[
                        "https://posts.specterops.io/certified-pre-owned-d95910965cd2",
                    ],
                ))
        return out

    def _enroll_acl_grants(self, sd_raw, principal_sids: set[str]) -> bool:
        try:
            from impacket.ldap.ldaptypes import (
                ACCESS_ALLOWED_OBJECT_ACE,
                SR_SECURITY_DESCRIPTOR,
            )
        except ImportError:
            return False
        for raw in sd_raw or []:
            try:
                sd = SR_SECURITY_DESCRIPTOR(data=raw)
            except Exception:
                continue
            if not sd["Dacl"]:
                continue
            for ace in sd["Dacl"].aces:
                a = ace["Ace"]
                sid = format_sid(a["Sid"].getData())
                if sid not in principal_sids:
                    continue
                mask = a["Mask"]["Mask"]
                # Generic access bits or per-object enrollment right
                if mask & 0x000F01FF:  # GenericAll or All-Extended-Rights
                    return True
                if isinstance(ace, ACCESS_ALLOWED_OBJECT_ACE) or ace["AceType"] in (0x05, 0x07):
                    if mask & 0x00000100:  # CONTROL_ACCESS
                        obj = a.get("ObjectType")
                        if obj:
                            guid = obj.hex().lower() if isinstance(obj, bytes) else str(obj).lower()
                            wanted = {CERT_ENROLLMENT_RIGHT.replace("-", ""),
                                      CERT_AUTOENROLLMENT_RIGHT.replace("-", "")}
                            if guid.replace("-", "") in wanted:
                                return True
        return False

    # ---- ESC8 ----

    def _esc8_probe(self, ctx: RunContext, cas: list[dict]) -> list[Finding]:
        out: list[Finding] = []
        for ca in cas:
            host = ca.get("dns")
            if not host:
                continue
            for scheme, port in (("http", 80), ("https", 443)):
                if not self._tcp_open(host, port, timeout=3):
                    continue
                url = f"{scheme}://{host}/certsrv/"
                try:
                    req = Request(url, method="GET")
                    if scheme == "https":
                        ctx_ssl = ssl._create_unverified_context()
                        with urlopen(req, timeout=4, context=ctx_ssl) as resp:
                            self._maybe_emit_esc8(resp, host, scheme, ca, out, ctx)
                    else:
                        with urlopen(req, timeout=4) as resp:
                            self._maybe_emit_esc8(resp, host, scheme, ca, out, ctx)
                except Exception as e:
                    # 401 with WWW-Authenticate is normal — capture from headers
                    headers = getattr(e, "headers", None)
                    code = getattr(e, "code", None)
                    if headers and code == 401:
                        self._maybe_emit_esc8_headers(headers, host, scheme, ca, out, ctx)
                    continue
        return out

    def _maybe_emit_esc8(self, resp, host, scheme, ca, out, ctx):
        self._maybe_emit_esc8_headers(resp.headers, host, scheme, ca, out, ctx)

    def _maybe_emit_esc8_headers(self, headers, host, scheme, ca, out, ctx):
        auth = headers.get("WWW-Authenticate", "") if headers else ""
        if "NTLM" in auth or "Negotiate" in auth:
            url = f"{scheme}://{host}/certsrv/"
            out.append(Finding(
                severity=Severity.HIGH,
                module=self.name,
                title=f"ESC8: AD CS HTTP enrollment exposed at {url}",
                description=(
                    "CA's HTTP enrollment endpoint accepts NTLM/Negotiate auth "
                    "→ NTLM relay target. Coerce a machine account "
                    "(PetitPotam/PrinterBug) and relay to /certsrv/ to obtain a "
                    "client-auth cert as the coerced machine — own the DC."
                ),
                target=ca["cn"],
                evidence={"url": url, "wwwAuthenticate": auth},
                recipe=recipes.esc8_relay(f"{scheme}://{host}", host),
                edges=[Edge(src=ctx.me_node, dst=f"ESC8:{ca['cn']}",
                            type="ESC8", dst_label=f"ESC8 via {ca['cn']}", cost=2,
                            context={"ca": ca["cn"], "endpoint": url})],
                domain_context=ctx.domain_context,
                references=[
                    "https://github.com/SecureAuthCorp/impacket/pull/1265",
                    "https://posts.specterops.io/certified-pre-owned-d95910965cd2",
                ],
            ))

    @staticmethod
    def _tcp_open(host: str, port: int, timeout: float = 3) -> bool:
        try:
            with socket.create_connection((host, port), timeout=timeout):
                return True
        except OSError:
            return False
