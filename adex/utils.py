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
# Specific AD object rights (low byte + extended)
ADS_CREATE_CHILD     = 0x00000001
ADS_DELETE_CHILD     = 0x00000002
ADS_LIST_CONTENTS    = 0x00000004
ADS_SELF             = 0x00000008
ADS_READ_PROP        = 0x00000010
ADS_WRITE_PROP       = 0x00000020
ADS_DELETE_TREE      = 0x00000040
ADS_LIST_OBJECT      = 0x00000080
ADS_CONTROL_ACCESS   = 0x00000100   # extended-right (validated read or specific control)

# Standard rights
DELETE               = 0x00010000
READ_CONTROL         = 0x00020000
WRITE_DACL           = 0x00040000
WRITE_OWNER          = 0x00080000
SYNCHRONIZE          = 0x00100000

# Generic flag bits — these are templates that the kernel maps to specific
# rights when the SD is built; in committed ACLs they sometimes appear raw.
GENERIC_READ_BIT     = 0x80000000
GENERIC_WRITE_BIT    = 0x40000000
GENERIC_EXECUTE_BIT  = 0x20000000
GENERIC_ALL_BIT      = 0x10000000

# "Full Control" expressed as a fully-expanded specific bitmask. This is the
# value some tools commit directly into ACEs when the user picked "Full
# Control" in the GUI. NOTE: it includes read bits — testing for any overlap
# is wrong (every read-only ACE matches). Only treat as Full Control when
# the WHOLE bitmask is set together: (mask & GENERIC_ALL_BITPATTERN) == GENERIC_ALL_BITPATTERN.
GENERIC_ALL_BITPATTERN = 0x000F01FF

# Backwards-compat aliases used by older code paths.
GENERIC_ALL = GENERIC_ALL_BITPATTERN
WRITE_PROPERTY = ADS_WRITE_PROP
SELF = ADS_SELF
CONTROL_ACCESS = ADS_CONTROL_ACCESS
CREATE_CHILD = ADS_CREATE_CHILD

# Bits that grant a meaningful write / takeover capability on an AD object.
# Pure-read and CONTROL_ACCESS-only ACEs are intentionally excluded; CONTROL_ACCESS
# requires checking the ObjectType GUID separately.
DANGEROUS_WRITE_BITS = (
    ADS_CREATE_CHILD
    | ADS_DELETE_CHILD
    | ADS_DELETE_TREE
    | ADS_SELF
    | ADS_WRITE_PROP
    | DELETE
    | WRITE_DACL
    | WRITE_OWNER
)

# Kept for back-compat with code that imports this name. Semantically still a
# "set of dangerous bits" but callers should prefer is_dangerous_write_mask().
DANGEROUS_WRITE_RIGHTS = DANGEROUS_WRITE_BITS


def is_dangerous_write_mask(mask: int) -> int:
    """Return the *dangerous-write* bits set in `mask`, or 0 if none.

    Three ways an ACE counts as "dangerous":

    1. The full-control specific bitpattern is set together (Full Control
       was committed as a single ACE rather than a flag).
    2. The high generic GA / GW flag is set (rare in committed ACLs but
       possible).
    3. One of the specific write bits in DANGEROUS_WRITE_BITS is set.

    Critically: a mask with *only* read or list bits — including the very
    common 0x20094 "Authenticated Users read everything" ACE — returns 0.
    """
    if (mask & GENERIC_ALL_BITPATTERN) == GENERIC_ALL_BITPATTERN:
        return mask & GENERIC_ALL_BITPATTERN
    high = mask & (GENERIC_ALL_BIT | GENERIC_WRITE_BIT)
    if high:
        return high
    return mask & DANGEROUS_WRITE_BITS


def grants_full_control(mask: int) -> bool:
    """True if the mask grants Full Control (as a single bitpattern or via
    the high GENERIC_ALL flag)."""
    if (mask & GENERIC_ALL_BITPATTERN) == GENERIC_ALL_BITPATTERN:
        return True
    return bool(mask & GENERIC_ALL_BIT)


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
    """Return the SID set for the bound principal: their own SID plus
    `tokenGroups` (transitive group memberships).

    `tokenGroups` already includes the user's well-known group memberships
    (Authenticated Users, Everyone, Domain Users, Pre-W2K Compat, etc. as
    applicable), so we don't hand-add any well-knowns here. Hand-adding
    `Authenticated Users` blindly causes false positives on every ACE that
    grants `Authenticated Users` something — the most common ACE type in AD.
    """
    sids: set[str] = set()
    if not sam_account:
        # Schannel / cert binds: tokenGroups isn't reachable. Fall back to
        # 'Authenticated Users' only — at least we know we authenticated.
        return {WELL_KNOWN["AUTHENTICATED_USERS"], WELL_KNOWN["EVERYONE"]}
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
    # tokenGroups sometimes omits Everyone (S-1-1-0) on locked-down DCs.
    # Authenticated Users is reliably included; Everyone is conservative.
    sids.add(WELL_KNOWN["AUTHENTICATED_USERS"])
    sids.add(WELL_KNOWN["EVERYONE"])
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
    """Return the ObjectType GUID of an object-specific ACE, normalised.

    impacket Structure subclasses don't expose `.get()` — they raise KeyError
    if a conditional field (ObjectType is conditional on Flags & 0x01) wasn't
    parsed. We use [] + try/except instead.
    """
    if not isinstance(ace, ACCESS_ALLOWED_OBJECT_ACE):
        return None
    try:
        flags = ace["Flags"]
    except (KeyError, IndexError):
        return None
    if not (flags & 0x01):  # ACE_OBJECT_TYPE_PRESENT
        return None
    try:
        obj = ace["ObjectType"]
    except (KeyError, IndexError):
        return None
    if not obj:
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
    """Legacy: kept for back-compat. Prefer find_dangerous_aces directly."""
    a = ace["Ace"]
    sid = format_sid(a["Sid"].getData())
    if sid not in principal_sids:
        return False, 0
    full_mask = a["Mask"]["Mask"]
    write_bits = is_dangerous_write_mask(full_mask) & rights_mask
    if not write_bits:
        return False, 0
    if object_guid:
        guid = ace_object_guid(a)
        if guid and guid != _norm_guid(object_guid):
            return False, 0
    return True, write_bits


def find_dangerous_aces(
    sd_bytes: bytes,
    principal_sids: set[str],
    rights_mask: int | None = None,  # ignored; kept for back-compat
    object_guid: str | None = None,
) -> list[dict]:
    """Return ACEs that grant the principal a meaningful write capability.

    Read-only ACEs (the very common 'Authenticated Users can read DA' kind)
    are filtered out. CONTROL_ACCESS-only ACEs are filtered out unless their
    ObjectType matches `object_guid` — extended rights without a known GUID
    are not "dangerous writes".
    """
    out: list[dict] = []
    for ace in iter_aces(sd_bytes):
        a = ace["Ace"]
        sid = format_sid(a["Sid"].getData())
        if sid not in principal_sids:
            continue
        full_mask = a["Mask"]["Mask"]
        write_bits = is_dangerous_write_mask(full_mask)
        if not write_bits:
            continue
        if object_guid:
            guid = ace_object_guid(a)
            if guid and guid != _norm_guid(object_guid):
                continue
        out.append({
            "sid": sid,
            "mask": write_bits,
            "guid": ace_object_guid(a),
        })
    return out


def find_extended_rights(
    sd_bytes: bytes,
    principal_sids: set[str],
    right_guids: Iterable[str],
) -> list[dict]:
    """Find ACEs granting CONTROL_ACCESS for any of the specified extended-right
    GUIDs. Full Control on the object implicitly grants every extended right.

    Filters by `principal_sids` in BOTH branches — never lists ACEs whose SID
    isn't part of the bound principal's effective set.
    """
    wanted = {_norm_guid(g): g for g in right_guids}
    out: list[dict] = []
    for ace in iter_aces(sd_bytes):
        a = ace["Ace"]
        sid = format_sid(a["Sid"].getData())
        if sid not in principal_sids:
            continue
        full_mask = a["Mask"]["Mask"]
        # Full Control on the object grants every extended right too.
        if grants_full_control(full_mask):
            for _normed, original in wanted.items():
                out.append({"sid": sid, "right": original, "via": "GenericAll"})
            continue
        if not (full_mask & ADS_CONTROL_ACCESS):
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
