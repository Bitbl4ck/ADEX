"""Trust enumeration + multi-domain bind helper.

`enumerate_trusts` reads `(objectClass=trustedDomain)` from the bound DC
and returns parsed trust records. `traverse_trusts` calls a `runner`
callback for each reachable trusted domain (and the primary domain
itself), wiring up a fresh LDAP connection per domain.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass

from ldap3 import SUBTREE, Connection

from adex.auth import Auth
from adex.connection import BoundLDAP, connect_ldap, discover_dc
from adex.connection import ConnectionError as ADEXConnError

# trustAttributes bitmask
TRUST_ATTRIBUTE_NON_TRANSITIVE = 0x1
TRUST_ATTRIBUTE_QUARANTINED = 0x4
TRUST_ATTRIBUTE_FOREST_TRANSITIVE = 0x8
TRUST_ATTRIBUTE_CROSS_ORGANIZATION = 0x10


@dataclass
class TrustRecord:
    partner: str
    direction: int          # 1=inbound, 2=outbound, 3=bidirectional
    attributes: int
    trust_type: int

    @property
    def forest(self) -> bool:
        return bool(self.attributes & TRUST_ATTRIBUTE_FOREST_TRANSITIVE)

    @property
    def quarantined(self) -> bool:
        return bool(self.attributes & TRUST_ATTRIBUTE_QUARANTINED)

    @property
    def transitive(self) -> bool:
        return not bool(self.attributes & TRUST_ATTRIBUTE_NON_TRANSITIVE)


def enumerate_trusts(conn: Connection, base_dn: str) -> list[TrustRecord]:
    conn.search(
        f"CN=System,{base_dn}",
        "(objectClass=trustedDomain)",
        search_scope=SUBTREE,
        attributes=["trustPartner", "trustDirection",
                    "trustAttributes", "trustType"],
    )
    out = []
    for e in conn.entries:
        partner = str(e["trustPartner"]) if e["trustPartner"] else ""
        if not partner:
            continue
        out.append(TrustRecord(
            partner=partner,
            direction=int(e["trustDirection"].value or 0),
            attributes=int(e["trustAttributes"].value or 0),
            trust_type=int(e["trustType"].value or 0),
        ))
    return out


def traverse_trusts(primary: BoundLDAP, primary_auth: Auth,
                    trusts: list[TrustRecord], use_ldaps: bool,
                    timeout: int, dns_server: str | None,
                    runner: Callable[[BoundLDAP, Auth, str], None],
                    log) -> None:
    """For each outbound/bidirectional trust we can reach, discover its DC,
    bind with the same creds (best-effort), call runner(bound, auth, ctx_label).
    Failures are logged and skipped."""
    for trust in trusts:
        # Skip inbound-only — our creds aren't valid the other way (without
        # cross-realm Kerberos magic that's beyond Phase 2).
        if trust.direction == 1:
            log.info("[trusts] skipping inbound-only trust to %s", trust.partner)
            continue

        # Build a fresh Auth tied to the trusted domain
        traverse_auth = Auth(
            domain=trust.partner,
            username=primary_auth.username,
            password=primary_auth.password,
            nt_hash=primary_auth.nt_hash,
            use_kerberos=primary_auth.use_kerberos,
            pfx_path=primary_auth.pfx_path,
            pfx_password=primary_auth.pfx_password,
            pass_the_cert=primary_auth.pass_the_cert,
            aes_key=primary_auth.aes_key,
            kdc_host=primary_auth.kdc_host,
        )
        try:
            other_dc = discover_dc(trust.partner, dns_server)
            log.info("[trusts] traversing %s via DC %s", trust.partner, other_dc)
            bound = connect_ldap(traverse_auth, dc=other_dc, use_ldaps=use_ldaps,
                                 timeout=timeout, dns_server=dns_server)
        except (ADEXConnError, Exception) as e:
            log.warning("[trusts] could not reach trusted domain %s: %s", trust.partner, e)
            continue
        try:
            runner(bound, traverse_auth, trust.partner)
        finally:
            try:
                bound.conn.unbind()
            except Exception:
                pass
