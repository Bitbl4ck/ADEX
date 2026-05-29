"""Authentication parameters shared across commands."""

from __future__ import annotations

import os
from dataclasses import dataclass, field


class AuthError(Exception):
    pass


@dataclass
class Auth:
    domain: str = ""
    username: str | None = None
    password: str | None = None
    nt_hash: str | None = None  # accepts "LM:NT", ":NT", or bare NT
    use_kerberos: bool = False
    pfx_path: str | None = None
    pfx_password: str | None = None
    pass_the_cert: bool = False
    aes_key: str | None = None
    kdc_host: str | None = None
    ccache: str | None = field(default_factory=lambda: os.environ.get("KRB5CCNAME"))

    def methods(self) -> list[str]:
        m = []
        if self.password:
            m.append("password")
        if self.nt_hash:
            m.append("hash")
        if self.use_kerberos:
            m.append("kerberos")
        if self.pfx_path and self.pass_the_cert:
            m.append("schannel")
        elif self.pfx_path:
            m.append("pkinit")
        if self.aes_key:
            m.append("aes")
        return m

    def validate(self) -> None:
        if not self.domain:
            raise AuthError("--domain is required")
        m = self.methods()
        if len(m) == 0:
            raise AuthError(
                "no authentication method provided. Use one of: -p, -H, -k, --pfx, --aes-key"
            )
        if len(m) > 1:
            raise AuthError(f"conflicting auth methods: {', '.join(m)}")
        if m[0] != "schannel" and not self.username:
            raise AuthError("-u/--username is required for this auth method")
        if m[0] == "kerberos" and not self.ccache:
            raise AuthError("--kerberos requires KRB5CCNAME to point at a ccache file")

    @property
    def primary_method(self) -> str:
        return self.methods()[0]

    @classmethod
    def from_args(cls, args) -> Auth:
        return cls(
            domain=getattr(args, "domain", "") or "",
            username=getattr(args, "username", None),
            password=getattr(args, "password", None),
            nt_hash=getattr(args, "hashes", None),
            use_kerberos=bool(getattr(args, "kerberos", False)),
            pfx_path=getattr(args, "pfx", None),
            pfx_password=getattr(args, "pfx_pass", None),
            pass_the_cert=bool(getattr(args, "pass_the_cert", False)),
            aes_key=getattr(args, "aes_key", None),
            kdc_host=getattr(args, "kdcHost", None),
        )

    def lm_nt(self) -> tuple[str, str]:
        """Return (LM, NT) hash pair. Accepts 'LM:NT', ':NT', or bare NT."""
        if not self.nt_hash:
            return "", ""
        h = self.nt_hash
        if ":" in h:
            lm, nt = h.split(":", 1)
        else:
            lm, nt = "", h
        if not lm:
            lm = "aad3b435b51404eeaad3b435b51404ee"
        return lm, nt
