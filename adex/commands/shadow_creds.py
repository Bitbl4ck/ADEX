"""Stub: Shadow Credentials (Phase 2).

Phase 2 will port `~/shadow_creds_check.py` logic into here, plus add/remove
of msDS-KeyCredentialLink entries via the certipy keycred helpers.
"""

from __future__ import annotations

import argparse

from adex.exit_codes import ExitCode


def add_parser(subparsers, common) -> None:
    p = subparsers.add_parser(
        "shadow-creds",
        parents=[common],
        help="Shadow credentials attack",
    )
    p.add_argument("--target", required=True, help="Target user/computer (sAMAccountName)")
    p.add_argument("--action", required=True, choices=["add", "list", "remove", "info"],
                   help="Action to perform")
    p.add_argument("--device-id", help="Device ID GUID for --action remove")
    p.add_argument("--out-pfx", help="Path to write the new PFX (action=add)")
    p.set_defaults(handler=handle)


def handle(args: argparse.Namespace) -> int:
    print("[stub] shadow-creds is implemented in Phase 2.")
    return int(ExitCode.SUCCESS)
