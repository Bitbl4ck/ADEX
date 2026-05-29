"""Shared helpers: SIDs, ACL parsing, well-known constants."""

from __future__ import annotations

import logging
from collections.abc import Iterable

from impacket.ldap.ldaptypes import (
    ACCESS_ALLOWED_OBJECT_ACE,
    SR_SECURITY_DESCRIPTOR,
)
from ldap3 import SUBTREE, Connection
from ldap3.protocol.formatters.formatters import format_sid
from ldap3.protocol.microsoft import security_descriptor_control

log = logging.getLogger("adex")


# ---- Well-known SIDs ----
WELL_KNOWN = {
    "EVERYONE": "S-1-1-0",
    "AUTHENTICATED_USERS": "S-1-5-11",
    "USERS": "S-1-5-32-545",
    "PRE_W2K_COMPAT": "S-1-5-32-554",
}


# ---- Domain functional levels (msDS-Behavior-Version) ----
FUNC_LEVEL = {
    0: "Windows 2000",
    1: "Windows 2003 Interim",
    2: "Windows 2003",
    3: "Windows 2008",
    4: "Windows 2008 R2",
    5: "Windows 2012",
    6: "Windows 2012 R2",
    7: "Windows 2016",
    10: "Windows 2025",
}


# ---- Access masks (DS rights) ----
GENERIC_ALL = 0x000F01FF
GENERIC_WRITE = 0x00020028
GENERIC_READ = 0x00020094
WRITE_DACL = 0x00040000
WRITE_OWNER = 0x00080000
WRITE_PROPERTY = 0x00000020
SELF = 0x00000008
CONTROL_ACCESS = 0x00000100  # extended-right
CREATE_CHILD = 0x00000001

DANGEROUS_WRITE_RIGHTS = GENERIC_ALL | GENERIC_WRITE | WRITE_DACL | WRITE_OWNER


# ---- Extended-rights / attribute GUIDs ----
# DS-Replication-Get-Changes / -All / -In-Filtered-Set
DCSYNC_RIGHT_GUIDS = {
    "1131f6aa-9c07-11d1-f79f-00c04fc2dcd2": "DS-Replication-Get-Changes",
    "1131f6ad-9c07-11d1-f79f-00c04fc2dcd2": "DS-Replication-Get-Changes-All",
    "89e95b76-444d-4c62-991a-0facbeda640c": "DS-Replication-Get-Changes-In-Filtered-Set",
}

KEY_CREDENTIAL_LINK_GUID = "5b47d60f-6090-40b2-9f37-2a4de88f3063"
USER_FORCE_CHANGE_PASSWORD_GUID = "00299570-246d-11d0-a768-00aa006e0529"
WRITE_MEMBERS_GUID = "bf9679c0-0de6-11d0-a285-00aa003049e2"  # Self-Membership / member


def _norm_guid(g: str | bytes) -> str:
    if isinstance(g, bytes):
        g = g.hex()
    return g.replace("-", "").lower()


# ---- LDAP search helpers ----

def get_principal_sids(conn: Connection, base_dn: str, sam_account: str | None) -> set[str]:
    """Return the SID set for the bound principal: their own SID + tokenGroups
    (transitive group memberships) + a few well-knowns."""
    sids: set[str] = {WELL_KNOWN["EVERYONE"], WELL_KNOWN["AUTHENTICATED_USERS"], WELL_KNOWN["USERS"]}
    if not sam_account:
        return sids
    conn.search(
        base_dn,
        f"(sAMAccountName={sam_account})",
        search_scope=SUBTREE,
        attributes=["distinguishedName"],
    )
    if not conn.entries:
        log.debug("get_principal_sids: %s not found", sam_account)
        return sids
    user_dn = conn.entries[0].entry_dn
    conn.search(
        user_dn, "(objectClass=*)", search_scope="BASE",
        attributes=["objectSid", "tokenGroups"],
    )
    if not conn.entries:
        return sids
    e = conn.entries[0]
    if e["objectSid"].value:
        sids.add(str(e["objectSid"]))
    for raw in e["tokenGroups"].raw_values or []:
        sids.add(format_sid(raw))
    return sids


def fetch_security_descriptor(conn: Connection, dn: str) -> bytes | None:
    """Fetch nTSecurityDescriptor for a DN with DACL flag set."""
    conn.search(
        dn, "(objectClass=*)", search_scope="BASE",
        attributes=["nTSecurityDescriptor"],
        controls=security_descriptor_control(sdflags=0x04),
    )
    if not conn.entries:
        return None
    raw = conn.entries[0]["nTSecurityDescriptor"].raw_values
    return raw[0] if raw else None


# ---- ACE analysis ----

def ace_object_guid(ace) -> str | None:
    """Return the ObjectType GUID of an object-specific ACE, normalised."""
    if not isinstance(ace, ACCESS_ALLOWED_OBJECT_ACE):
        return None
    flags = ace["Flags"]
    obj = ace.get("ObjectType")
    if not flags or not obj:
        return None
    return _norm_guid(obj)


def iter_aces(sd_bytes: bytes):
    sd = SR_SECURITY_DESCRIPTOR(data=sd_bytes)
    if not sd["Dacl"]:
        return
    yield from sd["Dacl"].aces


def ace_grants_any(
    ace,
    principal_sids: set[str],
    rights_mask: int,
    object_guid: str | None = None,
) -> tuple[bool, int]:
    """Return (granted, mask) — granted is True if this ACE grants the principal
    any bit of `rights_mask`. If `object_guid` is given, the ACE must either be
    a non-object ACE or target that GUID."""
    a = ace["Ace"]
    sid = format_sid(a["Sid"].getData())
    if sid not in principal_sids:
        return False, 0
    mask = a["Mask"]["Mask"] & rights_mask
    if not mask:
        return False, 0
    if object_guid:
        guid = ace_object_guid(a)
        # If ACE is not object-specific (no GUID), it applies to all attributes/rights
        if guid and guid != _norm_guid(object_guid):
            return False, 0
    return True, mask


def find_dangerous_aces(
    sd_bytes: bytes,
    principal_sids: set[str],
    rights_mask: int = DANGEROUS_WRITE_RIGHTS,
    object_guid: str | None = None,
) -> list[dict]:
    """Return a list of {sid, mask, guid} for ACEs in `sd_bytes` that grant the
    principal any of `rights_mask` (optionally filtered to `object_guid`)."""
    out: list[dict] = []
    for ace in iter_aces(sd_bytes):
        granted, mask = ace_grants_any(ace, principal_sids, rights_mask, object_guid)
        if not granted:
            continue
        a = ace["Ace"]
        out.append({
            "sid": format_sid(a["Sid"].getData()),
            "mask": mask,
            "guid": ace_object_guid(a),
        })
    return out


def find_extended_rights(
    sd_bytes: bytes,
    principal_sids: set[str],
    right_guids: Iterable[str],
) -> list[dict]:
    """Find ACEs granting CONTROL_ACCESS for any of the specified extended-right GUIDs."""
    wanted = {_norm_guid(g): g for g in right_guids}
    out: list[dict] = []
    for ace in iter_aces(sd_bytes):
        a = ace["Ace"]
        sid = format_sid(a["Sid"].getData())
        # GenericAll on the object grants every extended right too
        full_mask = a["Mask"]["Mask"]
        if full_mask & GENERIC_ALL:
            for _normed, original in wanted.items():
                out.append({"sid": sid, "right": original, "via": "GenericAll"})
            continue
        if not (full_mask & CONTROL_ACCESS):
            continue
        guid = ace_object_guid(a)
        if guid and guid in wanted:
            out.append({"sid": sid, "right": wanted[guid], "via": "ControlAccess"})
    # Deduplicate (sid, right) pairs
    seen = set()
    deduped = []
    for entry in out:
        key = (entry["sid"], entry["right"])
        if key in seen:
            continue
        seen.add(key)
        deduped.append(entry)
    return deduped


# ---- DN helpers ----

def domain_from_dn(dn: str) -> str:
    parts = [p.split("=", 1)[1] for p in dn.split(",") if p.strip().upper().startswith("DC=")]
    return ".".join(parts)


def dn_for_domain(domain_fqdn: str) -> str:
    return ",".join(f"DC={p}" for p in domain_fqdn.split("."))
