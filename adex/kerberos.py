"""Kerberos helpers — PKINIT and AES-key paths.

Phase 1 keeps these as thin wrappers; the LDAP bind path in
`adex.connection` raises if the user actually selects PKINIT or AES.
Phase 2 will fill these in (PKINIT via certipy-ad's auth library, AES
via impacket.krb5).
"""

from __future__ import annotations


class KerberosError(Exception):
    pass


def pkinit_to_ccache(pfx_path: str, pfx_password: str | None,
                    username: str, domain: str, dc: str) -> str:
    """Authenticate with the certificate and return path to the resulting
    ccache. Phase 2."""
    raise KerberosError(
        "PKINIT-to-ccache is implemented in Phase 2. "
        "For now run `certipy auth -pfx ... -dc-ip ...` and use `-k` with the "
        "resulting ccache."
    )


def aes_to_ccache(username: str, domain: str, aes_key: str, dc: str) -> str:
    """Use AES-128/256 long-term key to obtain a TGT, write a ccache, return
    its path. Phase 2."""
    raise KerberosError("AES-key Kerberos is implemented in Phase 2.")
