"""Top-level CLI: argparse subcommand dispatcher."""

from __future__ import annotations

import argparse
import logging
import sys

from adex.banner import print_banner
from adex.commands import asreproast, chain, enum, kerberoast, rbcd, report, shadow_creds
from adex.version import __version__


def build_common_parser() -> argparse.ArgumentParser:
    """Parent parser carrying auth + connection flags shared by every command."""
    p = argparse.ArgumentParser(add_help=False)
    g = p.add_argument_group("Required")
    g.add_argument("-d", "--domain", required=True, help="Target domain (e.g. corp.local)")

    a = p.add_argument_group("Authentication (one required)")
    a.add_argument("-u", "--username")
    a.add_argument("-p", "--password")
    a.add_argument("-H", "--hashes", help="LM:NT or just NT hash")
    a.add_argument("-k", "--kerberos", action="store_true",
                   help="Use Kerberos (KRB5CCNAME must be set)")
    a.add_argument("--pfx", help="PFX/P12 certificate file")
    a.add_argument("--pfx-pass", help="Password for PFX file")
    a.add_argument("--pass-the-cert", action="store_true",
                   help="Use PFX for LDAPS Schannel (Pass-the-Cert)")
    a.add_argument("--aes-key", help="AES-128/256 Kerberos key (Phase 2)")

    c = p.add_argument_group("Connection")
    c.add_argument("--dc", help="Domain controller (auto-discovered via DNS SRV if omitted)")
    c.add_argument("--dns", help="DNS server for DC SRV discovery")
    c.add_argument("--ldaps", action="store_true",
                   help="Use LDAPS (port 636) instead of LDAP (port 389)")
    c.add_argument("--kdcHost", help="KDC host for Kerberos (defaults to --dc)")
    c.add_argument("--timeout", type=int, default=30, help="Connection timeout (default: 30)")
    return p


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="adex",
        description="ADEX — Active Directory EXploitation: privilege escalation assessment tool.",
    )
    parser.add_argument("-V", "--version", action="version",
                        version=f"%(prog)s {__version__}")
    parser.add_argument("--log-level", default="INFO",
                        choices=["DEBUG", "INFO", "WARNING", "ERROR"])
    parser.add_argument("--no-banner", action="store_true",
                        help="Suppress the ADEX startup banner")

    sub = parser.add_subparsers(dest="command", required=True)
    common = build_common_parser()

    enum.add_parser(sub, common)
    kerberoast.add_parser(sub, common)
    asreproast.add_parser(sub, common)
    shadow_creds.add_parser(sub, common)
    rbcd.add_parser(sub, common)
    chain.add_parser(sub, common)
    report.add_parser(sub, common)
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    try:
        import argcomplete
        argcomplete.autocomplete(parser)
    except ImportError:
        pass

    args = parser.parse_args(argv)

    logging.basicConfig(
        level=getattr(logging, args.log_level),
        format="%(asctime)s %(levelname)-7s %(name)s: %(message)s",
        datefmt="%H:%M:%S",
    )

    if not args.no_banner:
        print_banner()

    handler = getattr(args, "handler", None)
    if handler is None:
        parser.error("no handler for command")
    return handler(args)


if __name__ == "__main__":
    sys.exit(main())
