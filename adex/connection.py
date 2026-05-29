"""LDAP/LDAPS connection: password / hash / Kerberos / Schannel."""

from __future__ import annotations

import logging
import ssl
import tempfile
from dataclasses import dataclass

from ldap3 import (
    ALL,
    KERBEROS,
    NTLM,
    SASL,
    Connection,
    Server,
    Tls,
)
from ldap3.core.exceptions import LDAPException

from adex.auth import Auth, AuthError

log = logging.getLogger("adex.connection")


class ConnectionError(Exception):
    pass


@dataclass
class BoundLDAP:
    conn: Connection
    server: Server
    base_dn: str
    use_ldaps: bool


def discover_dc(domain: str, dns_server: str | None = None) -> str:
    """Resolve _ldap._tcp.dc._msdcs.<domain> via DNS SRV."""
    try:
        import dns.resolver
    except ImportError as e:
        raise ConnectionError(f"dnspython required for DC discovery: {e}") from e

    resolver = dns.resolver.Resolver()
    if dns_server:
        resolver.nameservers = [dns_server]
    qname = f"_ldap._tcp.dc._msdcs.{domain}"
    try:
        answers = resolver.resolve(qname, "SRV")
    except Exception as e:
        raise ConnectionError(f"DC SRV discovery failed for {qname}: {e}") from e
    answers = sorted(answers, key=lambda r: (r.priority, -r.weight))
    if not answers:
        raise ConnectionError(f"no SRV records for {qname}")
    return str(answers[0].target).rstrip(".")


def _server(dc: str, use_ldaps: bool, timeout: int = 30) -> Server:
    port = 636 if use_ldaps else 389
    tls = Tls(validate=ssl.CERT_NONE) if use_ldaps else None
    return Server(dc, port=port, use_ssl=use_ldaps, get_info=ALL, tls=tls,
                  connect_timeout=timeout)


def _server_schannel(dc: str, cert_pem: str, key_pem: str, timeout: int = 30) -> Server:
    tls = Tls(
        validate=ssl.CERT_NONE,
        local_certificate_file=cert_pem,
        local_private_key_file=key_pem,
        version=ssl.PROTOCOL_TLS_CLIENT,
    )
    return Server(dc, port=636, use_ssl=True, get_info=ALL, tls=tls,
                  connect_timeout=timeout)


def _ntlm_user(auth: Auth) -> str:
    return f"{auth.domain}\\{auth.username}"


def _bind_password(server: Server, auth: Auth) -> Connection:
    conn = Connection(server, user=_ntlm_user(auth), password=auth.password,
                      authentication=NTLM, raise_exceptions=True)
    conn.bind()
    return conn


def _bind_hash(server: Server, auth: Auth) -> Connection:
    lm, nt = auth.lm_nt()
    conn = Connection(server, user=_ntlm_user(auth), password=f"{lm}:{nt}",
                      authentication=NTLM, raise_exceptions=True)
    conn.bind()
    return conn


def _bind_kerberos(server: Server, auth: Auth) -> Connection:
    # ldap3 picks up KRB5CCNAME from the environment for SASL/GSSAPI
    conn = Connection(server, authentication=SASL, sasl_mechanism=KERBEROS,
                      raise_exceptions=True)
    conn.bind()
    return conn


def _extract_pfx(pfx_path: str, pfx_password: str | None) -> tuple[str, str]:
    """Return (cert_pem_path, key_pem_path) on disk for use by ldap3 TLS config."""
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.serialization import pkcs12

    with open(pfx_path, "rb") as fh:
        data = fh.read()
    pwd = pfx_password.encode() if pfx_password else None
    key, cert, _extras = pkcs12.load_key_and_certificates(data, pwd)
    if key is None or cert is None:
        raise AuthError(f"PFX {pfx_path} did not contain a key+cert pair")

    cert_pem = tempfile.NamedTemporaryFile(suffix=".pem", delete=False)
    key_pem = tempfile.NamedTemporaryFile(suffix=".key", delete=False)
    cert_pem.write(cert.public_bytes(serialization.Encoding.PEM))
    cert_pem.close()
    key_pem.write(
        key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
    )
    key_pem.close()
    return cert_pem.name, key_pem.name


def _bind_schannel(dc: str, auth: Auth, timeout: int) -> tuple[Connection, Server]:
    if not auth.pfx_path:
        raise AuthError("--pass-the-cert requires --pfx")
    cert_pem, key_pem = _extract_pfx(auth.pfx_path, auth.pfx_password)
    server = _server_schannel(dc, cert_pem, key_pem, timeout)
    conn = Connection(server, authentication=SASL, sasl_mechanism="EXTERNAL",
                      sasl_credentials=(), auto_bind=True, raise_exceptions=True)
    return conn, server


def connect_ldap(auth: Auth, dc: str | None = None, use_ldaps: bool = False,
                 timeout: int = 30, dns_server: str | None = None) -> BoundLDAP:
    auth.validate()

    if not dc:
        dc = discover_dc(auth.domain, dns_server)
        log.info("discovered DC: %s", dc)

    method = auth.primary_method

    if method == "pkinit":
        raise AuthError(
            "PKINIT is not yet wired in Phase 1. "
            "Use `certipy auth -pfx <file> -username <u> -domain <d> -dc-ip <dc>` "
            "to obtain a ccache, then re-run adex with `-k`. "
            "Or use `--pass-the-cert` for direct LDAPS Schannel."
        )
    if method == "aes":
        raise AuthError("AES-key Kerberos is not yet wired in Phase 1.")

    if method == "schannel":
        conn, server = _bind_schannel(dc, auth, timeout)
    else:
        server = _server(dc, use_ldaps=use_ldaps, timeout=timeout)
        try:
            if method == "password":
                conn = _bind_password(server, auth)
            elif method == "hash":
                conn = _bind_hash(server, auth)
            elif method == "kerberos":
                conn = _bind_kerberos(server, auth)
            else:
                raise AuthError(f"unknown auth method: {method}")
        except LDAPException as e:
            raise ConnectionError(f"LDAP bind failed: {e}") from e

    base_dn = _resolve_default_naming_context(server)
    return BoundLDAP(conn=conn, server=server, base_dn=base_dn,
                     use_ldaps=use_ldaps or method == "schannel")


def _resolve_default_naming_context(server: Server) -> str:
    """Pick the domain partition the DC belongs to.

    Pitfall: `server.info.naming_contexts[0]` is whichever NC the DC chose
    to list first, which on a child-domain DC (e.g. winterfell in GOAD)
    is often `CN=Configuration,...` — wrong for any module that searches
    relative to the domain root. The right field is `defaultNamingContext`
    from rootDSE; we fall back to filtering naming_contexts only if that's
    unavailable.
    """
    if not server.info:
        return ""
    other = server.info.other or {}
    for key in ("defaultNamingContext", "default_naming_context"):
        val = other.get(key)
        if val:
            return val[0] if isinstance(val, (list, tuple)) else str(val)
    if server.info.naming_contexts:
        for nc in server.info.naming_contexts:
            nc_str = str(nc)
            up = nc_str.upper()
            if (up.startswith("DC=") and "CN=CONFIGURATION" not in up
                    and "CN=SCHEMA" not in up
                    and not up.startswith("DC=DOMAINDNSZONES")
                    and not up.startswith("DC=FORESTDNSZONES")):
                return nc_str
        return str(server.info.naming_contexts[0])
    return ""
