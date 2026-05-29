"""Stub: RBCD (Phase 2)."""

from __future__ import annotations

import argparse

from adex.exit_codes import ExitCode


def add_parser(subparsers, common) -> None:
    p = subparsers.add_parser(
        "rbcd",
        parents=[common],
        help="Resource-based constrained delegation abuse",
    )
    p.add_argument("--target", required=True, help="Target computer (sAMAccountName, e.g. WS01$)")
    p.add_argument("--action", required=True,
                   choices=["read", "write", "remove", "flush"])
    p.add_argument("--delegate-from", help="Computer or user permitted to delegate (action=write)")
    p.set_defaults(handler=handle)


def handle(args: argparse.Namespace) -> int:
    print("[stub] rbcd is implemented in Phase 2.")
    return int(ExitCode.SUCCESS)
