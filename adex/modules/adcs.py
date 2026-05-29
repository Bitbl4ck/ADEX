"""Module: adcs — comprehensive AD CS misconfiguration scanner.

Covers, from LDAP only (with one or two RPC reachability probes):

  ESC1   Enrollee-supplies-subject + client-auth EKU + low-priv enroll
  ESC2   Any-Purpose / SubCA EKU on enrollable template
  ESC3   Enrollment-Agent template (Cert Request Agent EKU)
  ESC4   Vulnerable template ACL (you can rewrite the template object)
  ESC5   Vulnerable PKI infrastructure ACL (CA, NTAuthCertificates,
         Public Key Services container, Certificate Templates container)
  ESC6   EDITF_ATTRIBUTESUBJECTALTNAME2 — informational only;
         certipy/certutil RPC probe needed for ground truth, ADEX
         flags it for verification rather than guessing
  ESC7   Dangerous write rights on the CA Enrollment Service object
         (proxy for ManageCA / ManageCertificates in many configs)
  ESC8   HTTP enrollment endpoint advertises NTLM/Negotiate
  ESC9   CT_FLAG_NO_SECURITY_EXTENSION on enrollable template
  ESC11  ICPR (RPC) endpoint reachability — relay target
  ESC13  Issuance policy linked to a group (msDS-OIDToGroupLink)
  ESC15  EKUwu — schema-v1 template with ENROLLEE_SUPPLIES_SUBJECT
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

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

# msPKI-Certificate-Name-Flag bits
CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT = 0x00000001
CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT_ALT_NAME = 0x00010000

# msPKI-Enrollment-Flag bits
CT_FLAG_PEND_ALL_REQUESTS = 0x00000002       # CA Manager approval required
CT_FLAG_NO_SECURITY_EXTENSION = 0x00080000   # ESC9 root cause

# msPKI-Template-Schema-Version
SCHEMA_V1 = 1

# Authentication-suitable EKUs (any of these on a template makes it usable
# for client auth → PKINIT)
EKU_CLIENT_AUTH = "1.3.6.1.5.5.7.3.2"
EKU_PKINIT_CLIENT = "1.3.6.1.5.2.3.4"
EKU_SMARTCARD_LOGON = "1.3.6.1.4.1.311.20.2.2"
EKU_ANY_PURPOSE = "2.5.29.37.0"
EKU_CERT_REQUEST_AGENT = "1.3.6.1.4.1.311.20.2.1"  # Enrollment Agent

AUTH_EKUS = {EKU_CLIENT_AUTH, EKU_PKINIT_CLIENT, EKU_SMARTCARD_LOGON, EKU_ANY_PURPOSE}

# Microsoft extended-right GUIDs (object-specific ACEs)
CERT_ENROLLMENT_RIGHT = "0e10c968-78fb-11d2-90d4-00c04f79dc55"
CERT_AUTOENROLLMENT_RIGHT = "a05b8cc2-17bc-4802-a710-e7c15ab866a2"

# Standard write rights bitmap (subset of utils.DANGEROUS_WRITE_RIGHTS — kept
# local to keep this module self-explanatory).
GENERIC_ALL = 0x000F01FF
GENERIC_WRITE = 0x00020028
WRITE_DACL = 0x00040000
WRITE_OWNER = 0x00080000
DANGEROUS_WRITE = GENERIC_ALL | GENERIC_WRITE | WRITE_DACL | WRITE_OWNER


# ---------------------------------------------------------------------------
# Module
# ---------------------------------------------------------------------------

class AdcsModule(ModuleBase):
    name = "adcs"
    description = "ADCS misconfigurations — ESC1-9, 11, 13, 15"
    opsec_safe = True

    def run(self, ctx: RunContext) -> list[Finding]:
        config_nc = self._configuration_nc(ctx)
        if not config_nc:
            ctx.log.warning("[adcs] no Configuration NC found — skipping")
            return []

        cas = self._enumerate_cas(ctx, config_nc)
        if not cas:
            ctx.log.info("[adcs] no Enterprise CAs found in this domain")
            return []

        templates = self._enumerate_templates(ctx, config_nc)
        oid_groups = self._enumerate_oid_groups(ctx, config_nc)

        out: list[Finding] = []
        # Per-template checks (ESC1, 2, 3, 4, 9, 13, 15)
        for tpl in templates:
            ca_for_tpl = self._ca_publishing(tpl["cn"], cas)
            if not ca_for_tpl:
                continue
            out.extend(self._check_template(ctx, tpl, ca_for_tpl, oid_groups))

        # Per-CA checks (ESC6, ESC7, ESC8, ESC11)
        for ca in cas:
            out.extend(self._check_ca(ctx, ca, config_nc))

        # Container-level checks (ESC5)
        out.extend(self._check_pki_containers(ctx, config_nc))

        return out

    # ----- discovery helpers -----

    def _configuration_nc(self, ctx: RunContext) -> str | None:
        info = ctx.conn.server.info
        if info and info.other:
            cnc = info.other.get("configurationNamingContext")
            if isinstance(cnc, list) and cnc:
                return cnc[0]
            if isinstance(cnc, str):
                return cnc
        return f"CN=Configuration,{ctx.base_dn}" if ctx.base_dn else None

    def _enumerate_cas(self, ctx: RunContext, config_nc: str) -> list[dict]:
        ctx.conn.search(
            f"CN=Enrollment Services,CN=Public Key Services,CN=Services,{config_nc}",
            "(objectClass=pKIEnrollmentService)",
            search_scope=SUBTREE,
            attributes=["cn", "dNSHostName", "certificateTemplates",
                        "displayName", "distinguishedName",
                        "nTSecurityDescriptor"],
            controls=security_descriptor_control(sdflags=0x04),
        )
        out = []
        for e in ctx.conn.entries:
            sd_raw = e["nTSecurityDescriptor"].raw_values
            out.append({
                "cn": str(e["cn"]),
                "dn": e.entry_dn,
                "dns": str(e["dNSHostName"]) if e["dNSHostName"] else "",
                "templates": [str(t).lower() for t in
                              (e["certificateTemplates"] or [])],
                "displayName": str(e["displayName"]) if e["displayName"] else "",
                "sd_raw": sd_raw[0] if sd_raw else None,
            })
        return out

    def _enumerate_templates(self, ctx: RunContext, config_nc: str) -> list[dict]:
        ctx.conn.search(
            f"CN=Certificate Templates,CN=Public Key Services,CN=Services,{config_nc}",
            "(objectClass=pKICertificateTemplate)",
            search_scope=SUBTREE,
            attributes=["cn", "displayName",
                        "msPKI-Certificate-Name-Flag",
                        "msPKI-Enrollment-Flag",
                        "msPKI-Template-Schema-Version",
                        "msPKI-RA-Application-Policies",
                        "msPKI-Certificate-Policy",
                        "pKIExtendedKeyUsage",
                        "nTSecurityDescriptor",
                        "distinguishedName"],
            controls=security_descriptor_control(sdflags=0x04),
        )
        out = []
        for e in ctx.conn.entries:
            sd_raw = e["nTSecurityDescriptor"].raw_values
            ekus = [str(x) for x in (e["pKIExtendedKeyUsage"] or [])]
            policies = [str(x) for x in (e["msPKI-Certificate-Policy"] or [])]
            ra_policies = [str(x) for x in (e["msPKI-RA-Application-Policies"] or [])]
            out.append({
                "cn": str(e["cn"]),
                "dn": e.entry_dn,
                "displayName": str(e["displayName"]) if e["displayName"] else str(e["cn"]),
                "name_flag": int(e["msPKI-Certificate-Name-Flag"].value or 0),
                "enroll_flag": int(e["msPKI-Enrollment-Flag"].value or 0),
                "schema": int(e["msPKI-Template-Schema-Version"].value or 0),
                "ekus": set(ekus),
                "policies": policies,
                "ra_policies": ra_policies,
                "sd_raw": sd_raw[0] if sd_raw else None,
            })
        return out

    def _enumerate_oid_groups(self, ctx: RunContext, config_nc: str) -> dict[str, str]:
        """Return {oid: linked_group_dn} from CN=OID,...,CN=Public Key Services."""
        try:
            ctx.conn.search(
                f"CN=OID,CN=Public Key Services,CN=Services,{config_nc}",
                "(msDS-OIDToGroupLink=*)",
                search_scope=SUBTREE,
                attributes=["msPKI-Cert-Template-OID", "msDS-OIDToGroupLink",
                            "displayName"],
            )
        except Exception:
            return {}
        out: dict[str, str] = {}
        for e in ctx.conn.entries:
            oid = str(e["msPKI-Cert-Template-OID"]) if e["msPKI-Cert-Template-OID"] else None
            grp = str(e["msDS-OIDToGroupLink"]) if e["msDS-OIDToGroupLink"] else None
            if oid and grp:
                out[oid] = grp
        return out

    # ----- per-template checks -----

    @staticmethod
    def _ca_publishing(template_cn: str, cas: list[dict]) -> dict | None:
        for ca in cas:
            if template_cn.lower() in ca["templates"]:
                return ca
        return None

    @staticmethod
    def _eku_allows_auth(ekus: set[str]) -> bool:
        if not ekus:
            return True  # empty EKU = template usable for any purpose
        return bool(ekus & AUTH_EKUS)

    def _check_template(self, ctx: RunContext, tpl: dict, ca: dict,
                        oid_groups: dict[str, str]) -> list[Finding]:
        out: list[Finding] = []
        principal = ctx.principal_sids
        username = ctx.auth.username or ""
        password = ctx.auth.password
        nt_hash = ctx.auth.nt_hash
        domain = ctx.auth.domain
        dc = ctx.dc

        sd_raw = tpl["sd_raw"]
        if not sd_raw:
            return out

        target_upn = f"administrator@{domain}"
        manager_approval = bool(tpl["enroll_flag"] & CT_FLAG_PEND_ALL_REQUESTS)
        enroll_grants = self._enroll_acl_grants(sd_raw, principal)
        write_grants = self._template_write_grants(sd_raw, principal)

        # ---------- ESC4: dangerous write on the template object itself ----------
        if write_grants:
            attacker_sid = next(iter(principal), "")
            out.append(Finding(
                severity=Severity.CRITICAL,
                module=self.name,
                title=f"ESC4: vulnerable ACL on template '{tpl['displayName']}'",
                description=(
                    "Current principal can modify the template's configuration "
                    "(GenericAll / GenericWrite / WriteDACL / WriteOwner). "
                    "Make it ESC1-vulnerable, enrol, restore."
                ),
                target=tpl["dn"],
                evidence={
                    "template": tpl["displayName"],
                    "grantedAces": [{"sid": s, "mask": hex(m)} for (s, m) in write_grants],
                },
                recipe=recipes.esc4_template_acl(tpl["displayName"], attacker_sid,
                                                 domain, dc, username, password, nt_hash),
                edges=[Edge(src=ctx.me_node, dst=f"ESC4:{tpl['cn']}",
                            type="ESC4", dst_label=f"ESC4 via {tpl['displayName']}",
                            cost=2,
                            context={"template": tpl["displayName"]})],
                domain_context=ctx.domain_context,
                references=["https://posts.specterops.io/certified-pre-owned-d95910965cd2"],
            ))

        # The remaining template ESCs require enrollment access; if none, stop.
        if not enroll_grants:
            return out

        supplies_subject = bool(tpl["name_flag"] & CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT)

        # ---------- ESC1 ----------
        eku_for_auth = self._eku_allows_auth(tpl["ekus"])
        if (supplies_subject and eku_for_auth and not manager_approval
                and tpl["schema"] != SCHEMA_V1):
            out.append(Finding(
                severity=Severity.CRITICAL,
                module=self.name,
                title=f"ESC1: vulnerable template '{tpl['displayName']}'",
                description=(
                    "Enrollee supplies subject (SAN), template grants client-auth "
                    "EKU, no manager approval, current principal can enrol. "
                    "Mint a cert as any user — including Domain Admin."
                ),
                target=tpl["displayName"],
                evidence={
                    "template": tpl["displayName"],
                    "ca": ca["cn"],
                    "msPKI-Certificate-Name-Flag": hex(tpl["name_flag"]),
                    "msPKI-Enrollment-Flag": hex(tpl["enroll_flag"]),
                    "ekus": sorted(tpl["ekus"]),
                },
                recipe=recipes.esc1(ca["cn"], tpl["displayName"], target_upn,
                                    domain, dc, username, password, nt_hash),
                edges=[Edge(src=ctx.me_node, dst=f"ESC1:{tpl['cn']}",
                            type="ESC1", dst_label=f"ESC1 via {tpl['displayName']}",
                            cost=1, context={"template": tpl["displayName"], "ca": ca["cn"]})],
                domain_context=ctx.domain_context,
                references=["https://posts.specterops.io/certified-pre-owned-d95910965cd2"],
            ))

        # ---------- ESC2: Any-Purpose / SubCA ----------
        is_any_purpose = EKU_ANY_PURPOSE in tpl["ekus"]
        is_subca = not tpl["ekus"]  # empty EKU list = SubCA-equivalent
        if (is_any_purpose or is_subca) and not manager_approval:
            out.append(Finding(
                severity=Severity.CRITICAL,
                module=self.name,
                title=f"ESC2: Any-Purpose template '{tpl['displayName']}'",
                description=(
                    "Template issues a cert with Any-Purpose EKU (or no EKU at all "
                    "= SubCA), so the cert can be used to impersonate or to forge "
                    "subordinate certs."
                ),
                target=tpl["displayName"],
                evidence={"template": tpl["displayName"], "ca": ca["cn"],
                          "ekus": sorted(tpl["ekus"]) or ["(none / SubCA)"]},
                recipe=recipes.esc2_subca(ca["cn"], tpl["displayName"], domain, dc,
                                          username, password, nt_hash),
                edges=[Edge(src=ctx.me_node, dst=f"ESC2:{tpl['cn']}",
                            type="ESC2", dst_label=f"ESC2 via {tpl['displayName']}",
                            cost=2)],
                domain_context=ctx.domain_context,
            ))

        # ---------- ESC3: Enrollment Agent ----------
        if EKU_CERT_REQUEST_AGENT in tpl["ekus"] and not manager_approval:
            out.append(Finding(
                severity=Severity.HIGH,
                module=self.name,
                title=f"ESC3: Enrollment Agent template '{tpl['displayName']}'",
                description=(
                    "Template grants the Cert Request Agent EKU. Combine with a "
                    "second template that allows enrollment-on-behalf-of and you "
                    "can enrol any user's cert without their password."
                ),
                target=tpl["displayName"],
                evidence={"template": tpl["displayName"], "ca": ca["cn"]},
                recipe=recipes.esc3_enrollment_agent(ca["cn"], tpl["displayName"],
                                                     "User", target_upn, domain, dc,
                                                     username, password, nt_hash),
                edges=[Edge(src=ctx.me_node, dst=f"ESC3:{tpl['cn']}",
                            type="ESC3", dst_label=f"ESC3 via {tpl['displayName']}",
                            cost=2)],
                domain_context=ctx.domain_context,
            ))

        # ---------- ESC9: No Security Extension ----------
        if (tpl["enroll_flag"] & CT_FLAG_NO_SECURITY_EXTENSION
                and eku_for_auth and not manager_approval):
            out.append(Finding(
                severity=Severity.HIGH,
                module=self.name,
                title=f"ESC9: NO_SECURITY_EXTENSION on '{tpl['displayName']}'",
                description=(
                    "Template has CT_FLAG_NO_SECURITY_EXTENSION set. The cert "
                    "won't carry the szOID_NTDS_CA_SECURITY_EXT object, so the "
                    "DC's StrongCertificateBindingEnforcement falls back to "
                    "UPN-based mapping — supply a target UPN and PKINIT as them."
                ),
                target=tpl["displayName"],
                evidence={"template": tpl["displayName"], "ca": ca["cn"],
                          "msPKI-Enrollment-Flag": hex(tpl["enroll_flag"])},
                recipe=recipes.esc9_no_security_extension(ca["cn"], tpl["displayName"],
                                                          target_upn, domain, dc,
                                                          username, password, nt_hash),
                edges=[Edge(src=ctx.me_node, dst=f"ESC9:{tpl['cn']}",
                            type="ESC9", dst_label=f"ESC9 via {tpl['displayName']}",
                            cost=2)],
                domain_context=ctx.domain_context,
                references=["https://research.ifcr.dk/certipy-4-0-esc9-esc10-bloodhound-gui-new-authentication-and-request-methods-and-more-7237d88061f7"],
            ))

        # ---------- ESC15: EKUwu (schema v1 + supplies-subject) ----------
        if (tpl["schema"] == SCHEMA_V1 and supplies_subject
                and not manager_approval):
            out.append(Finding(
                severity=Severity.HIGH,
                module=self.name,
                title=f"ESC15 (EKUwu): schema-v1 template '{tpl['displayName']}'",
                description=(
                    "Schema-v1 template with ENROLLEE_SUPPLIES_SUBJECT lets the "
                    "enrollee supply the Application Policies extension at request "
                    "time, overriding the template's EKU restrictions."
                ),
                target=tpl["displayName"],
                evidence={"template": tpl["displayName"], "ca": ca["cn"],
                          "schema": tpl["schema"]},
                recipe=recipes.esc15_ekuwu(ca["cn"], tpl["displayName"], target_upn,
                                           domain, dc, username, password, nt_hash),
                edges=[Edge(src=ctx.me_node, dst=f"ESC15:{tpl['cn']}",
                            type="ESC15", dst_label=f"ESC15 via {tpl['displayName']}",
                            cost=2)],
                domain_context=ctx.domain_context,
                references=["https://trustedsec.com/blog/ekuwu-not-just-another-ad-cs-esc"],
            ))

        # ---------- ESC13: issuance-policy → group ----------
        for policy_oid in tpl["policies"]:
            if policy_oid in oid_groups:
                grp_dn = oid_groups[policy_oid]
                out.append(Finding(
                    severity=Severity.HIGH,
                    module=self.name,
                    title=f"ESC13: '{tpl['displayName']}' grants group via OID",
                    description=(
                        "Template carries an issuance policy OID that is linked "
                        "to an AD group via msDS-OIDToGroupLink. Anyone who "
                        "enrols inherits the linked group's membership in the "
                        "Kerberos PAC."
                    ),
                    target=tpl["displayName"],
                    evidence={"template": tpl["displayName"], "ca": ca["cn"],
                              "policyOID": policy_oid, "linkedGroup": grp_dn},
                    recipe=recipes.esc13_oid_group(ca["cn"], tpl["displayName"],
                                                   grp_dn, domain, dc, username,
                                                   password, nt_hash),
                    edges=[Edge(src=ctx.me_node, dst=grp_dn,
                                type="ESC13", dst_label=f"ESC13 via {tpl['displayName']}",
                                cost=2,
                                context={"template": tpl["displayName"],
                                         "policyOID": policy_oid})],
                    domain_context=ctx.domain_context,
                    references=["https://posts.specterops.io/adcs-esc13-abuse-technique-fda4272fbd53"],
                ))

        return out

    # ----- per-CA checks -----

    def _check_ca(self, ctx: RunContext, ca: dict, config_nc: str) -> list[Finding]:
        out: list[Finding] = []

        # ---------- ESC7: dangerous-write on the CA Enrollment Service object ----------
        if ca["sd_raw"]:
            ace_hits = self._template_write_grants(ca["sd_raw"], ctx.principal_sids)
            if ace_hits:
                out.append(Finding(
                    severity=Severity.HIGH,
                    module=self.name,
                    title=f"ESC7: dangerous write on CA '{ca['cn']}'",
                    description=(
                        "Current principal has Generic / Write rights on the CA's "
                        "Enrollment Service object — a strong proxy for "
                        "ManageCA / ManageCertificates (Officer role). With those "
                        "rights you can grant yourself extra privileges, approve "
                        "pending requests, and issue any template."
                    ),
                    target=ca["dn"],
                    evidence={
                        "ca": ca["cn"],
                        "grantedAces": [{"sid": s, "mask": hex(m)} for (s, m) in ace_hits],
                    },
                    recipe=recipes.esc7_manage_ca(ca["cn"], ctx.auth.domain, ctx.dc,
                                                  ctx.auth.username or "",
                                                  ctx.auth.password, ctx.auth.nt_hash),
                    edges=[Edge(src=ctx.me_node, dst=f"ESC7:{ca['cn']}",
                                type="ESC7", dst_label=f"ESC7 on {ca['cn']}",
                                cost=2)],
                    domain_context=ctx.domain_context,
                ))

        # ---------- ESC8: HTTP enrollment endpoint accepts NTLM ----------
        out.extend(self._esc8_probe(ctx, ca))

        # ---------- ESC11: ICPR (RPC) reachability ----------
        out.extend(self._esc11_probe(ctx, ca))

        # ---------- ESC6: informational (LDAP cannot confirm) ----------
        out.append(Finding(
            severity=Severity.INFO,
            module=self.name,
            title=f"ESC6: verify EDITF_ATTRIBUTESUBJECTALTNAME2 on '{ca['cn']}'",
            description=(
                "EDITF_ATTRIBUTESUBJECTALTNAME2 is stored in the CA's CertSrv "
                "registry, not LDAP. Cannot be confirmed without an RPC bind to "
                "the CA. Run `certipy find -enabled -dc-ip <dc> -u <user>@<dom>` "
                "to check this flag definitively."
            ),
            target=ca["cn"],
            evidence={"ca": ca["cn"], "verifyWith": "certipy find -enabled"},
            recipe=recipes.esc6_editflags(ca["cn"], ctx.auth.domain, ctx.dc,
                                          ctx.auth.username or "",
                                          ctx.auth.password, ctx.auth.nt_hash),
            domain_context=ctx.domain_context,
        ))

        return out

    def _esc8_probe(self, ctx: RunContext, ca: dict) -> list[Finding]:
        host = ca.get("dns")
        if not host:
            return []
        out: list[Finding] = []
        for scheme, port in (("http", 80), ("https", 443)):
            if not _tcp_open(host, port, timeout=3):
                continue
            url = f"{scheme}://{host}/certsrv/"
            auth_header = self._http_auth_header(url, scheme)
            if auth_header and ("NTLM" in auth_header or "Negotiate" in auth_header):
                out.append(Finding(
                    severity=Severity.HIGH,
                    module=self.name,
                    title=f"ESC8: AD CS HTTP enrollment exposed at {url}",
                    description=(
                        "CA's HTTP enrollment endpoint accepts NTLM/Negotiate auth "
                        "→ NTLM relay target. Coerce a machine account "
                        "(PetitPotam/PrinterBug) and relay to /certsrv/ to obtain "
                        "a client-auth cert as the coerced machine."
                    ),
                    target=ca["cn"],
                    evidence={"url": url, "wwwAuthenticate": auth_header},
                    recipe=recipes.esc8_relay(f"{scheme}://{host}", host),
                    edges=[Edge(src=ctx.me_node, dst=f"ESC8:{ca['cn']}",
                                type="ESC8", dst_label=f"ESC8 via {ca['cn']}",
                                cost=2,
                                context={"ca": ca["cn"], "endpoint": url})],
                    domain_context=ctx.domain_context,
                    references=[
                        "https://posts.specterops.io/certified-pre-owned-d95910965cd2",
                    ],
                ))
                break  # one relay path per CA is enough
        return out

    def _esc11_probe(self, ctx: RunContext, ca: dict) -> list[Finding]:
        host = ca.get("dns")
        if not host:
            return []
        if not _tcp_open(host, 135, timeout=3):
            return []
        return [Finding(
            severity=Severity.MEDIUM,
            module=self.name,
            title=f"ESC11: ICPR RPC reachable on '{ca['cn']}'",
            description=(
                "RPC endpoint mapper (TCP 135) is reachable on the CA host, so "
                "the ICertPassage interface (\\pipe\\cert) is potentially "
                "available. If the CA accepts NTLM authentication on this RPC "
                "interface, it can be relayed for ESC11 — same outcome as ESC8 "
                "but via RPC instead of HTTP."
            ),
            target=ca["cn"],
            evidence={"ca": ca["cn"], "host": host, "port": 135},
            recipe=recipes.esc11_icpr_relay(host, host),
            edges=[Edge(src=ctx.me_node, dst=f"ESC11:{ca['cn']}",
                        type="ESC11", dst_label=f"ESC11 via {ca['cn']}", cost=3)],
            domain_context=ctx.domain_context,
            references=["https://blog.compass-security.com/2022/11/relaying-to-ad-certificate-services-over-rpc/"],
        )]

    @staticmethod
    def _http_auth_header(url: str, scheme: str) -> str | None:
        try:
            req = Request(url, method="GET")
            ssl_ctx = ssl._create_unverified_context() if scheme == "https" else None
            kwargs = {"timeout": 4}
            if ssl_ctx:
                kwargs["context"] = ssl_ctx
            with urlopen(req, **kwargs) as resp:
                return resp.headers.get("WWW-Authenticate")
        except Exception as e:
            headers = getattr(e, "headers", None)
            if headers and getattr(e, "code", None) == 401:
                return headers.get("WWW-Authenticate")
        return None

    # ----- container-level checks (ESC5) -----

    def _check_pki_containers(self, ctx: RunContext, config_nc: str) -> list[Finding]:
        targets = [
            ("Public Key Services container",
             f"CN=Public Key Services,CN=Services,{config_nc}"),
            ("NTAuthCertificates",
             f"CN=NTAuthCertificates,CN=Public Key Services,CN=Services,{config_nc}"),
            ("Certificate Templates container",
             f"CN=Certificate Templates,CN=Public Key Services,CN=Services,{config_nc}"),
            ("Enrollment Services container",
             f"CN=Enrollment Services,CN=Public Key Services,CN=Services,{config_nc}"),
        ]
        out: list[Finding] = []
        for label, dn in targets:
            try:
                ctx.conn.search(
                    dn, "(objectClass=*)", search_scope="BASE",
                    attributes=["nTSecurityDescriptor"],
                    controls=security_descriptor_control(sdflags=0x04),
                )
            except Exception:
                continue
            if not ctx.conn.entries:
                continue
            sd_raw = ctx.conn.entries[0]["nTSecurityDescriptor"].raw_values
            if not sd_raw:
                continue
            hits = self._template_write_grants(sd_raw[0], ctx.principal_sids)
            if not hits:
                continue
            out.append(Finding(
                severity=Severity.CRITICAL,
                module=self.name,
                title=f"ESC5: dangerous write on PKI object '{label}'",
                description=(
                    "Current principal can modify a top-level PKI infrastructure "
                    "object. Depending on which one, this lets you publish a "
                    "rogue root, register a new template, or override CA-list "
                    "config — every cert-based auth in the forest becomes "
                    "untrustworthy."
                ),
                target=dn,
                evidence={
                    "object": label,
                    "grantedAces": [{"sid": s, "mask": hex(m)} for (s, m) in hits],
                },
                recipe=recipes.esc5_pki_object(dn, ctx.auth.domain, ctx.dc,
                                               ctx.auth.username or "",
                                               ctx.auth.password, ctx.auth.nt_hash),
                edges=[Edge(src=ctx.me_node, dst=f"ESC5:{label}",
                            type="ESC5", dst_label=f"ESC5 on {label}", cost=2)],
                domain_context=ctx.domain_context,
            ))
        return out

    # ----- ACL helpers -----

    @staticmethod
    def _enroll_acl_grants(sd_raw: bytes, principal_sids: set[str]) -> bool:
        """True if the principal has Enroll permission on this template."""
        try:
            from impacket.ldap.ldaptypes import (
                ACCESS_ALLOWED_OBJECT_ACE,
                SR_SECURITY_DESCRIPTOR,
            )
        except ImportError:
            return False
        try:
            sd = SR_SECURITY_DESCRIPTOR(data=sd_raw)
        except Exception:
            return False
        if not sd["Dacl"]:
            return False
        wanted_guids = {CERT_ENROLLMENT_RIGHT.replace("-", ""),
                        CERT_AUTOENROLLMENT_RIGHT.replace("-", "")}
        for ace in sd["Dacl"].aces:
            a = ace["Ace"]
            sid = format_sid(a["Sid"].getData())
            if sid not in principal_sids:
                continue
            mask = a["Mask"]["Mask"]
            if mask & GENERIC_ALL:
                return True
            if isinstance(ace, ACCESS_ALLOWED_OBJECT_ACE) or ace["AceType"] in (0x05, 0x07):
                if mask & 0x00000100:  # CONTROL_ACCESS
                    obj = a.get("ObjectType")
                    if obj:
                        guid = (obj.hex().lower() if isinstance(obj, bytes)
                                else str(obj).lower()).replace("-", "")
                        if guid in wanted_guids:
                            return True
        return False

    @staticmethod
    def _template_write_grants(sd_raw: bytes,
                               principal_sids: set[str]) -> list[tuple[str, int]]:
        """Return [(sid, mask)] for ACEs that grant the principal generic
        write rights on the template/CA/container object."""
        try:
            from impacket.ldap.ldaptypes import SR_SECURITY_DESCRIPTOR
        except ImportError:
            return []
        try:
            sd = SR_SECURITY_DESCRIPTOR(data=sd_raw)
        except Exception:
            return []
        if not sd["Dacl"]:
            return []
        out: list[tuple[str, int]] = []
        for ace in sd["Dacl"].aces:
            a = ace["Ace"]
            sid = format_sid(a["Sid"].getData())
            if sid not in principal_sids:
                continue
            mask = a["Mask"]["Mask"] & DANGEROUS_WRITE
            if mask:
                out.append((sid, mask))
        return out


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _tcp_open(host: str, port: int, timeout: float = 3) -> bool:
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False
