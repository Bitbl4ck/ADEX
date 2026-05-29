"""Stub: Kerberoast (Phase 2)."""

from __future__ import annotations

import argparse

from adex.exit_codes import ExitCode


def add_parser(subparsers, common) -> None:
    p = subparsers.add_parser(
        "kerberoast",
        parents=[common],
        help="Request and dump Kerberoastable TGS hashes",
    )
    p.add_argument("-o", "--output", help="Write hashes to file")
    p.add_argument("--rc4-only", action="store_true",
                   help="Only roast accounts with RC4-HMAC etype")
    p.add_argument("--target-spn", help="Roast a specific SPN only")
    p.set_defaults(handler=handle)


def handle(args: argparse.Namespace) -> int:
    print("[stub] kerberoast is implemented in Phase 2.")
    return int(ExitCode.SUCCESS)
