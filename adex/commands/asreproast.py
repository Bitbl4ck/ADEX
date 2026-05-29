"""Stub: AS-REP Roast (Phase 2)."""

from __future__ import annotations

import argparse

from adex.exit_codes import ExitCode


def add_parser(subparsers, common) -> None:
    p = subparsers.add_parser(
        "asreproast",
        parents=[common],
        help="Dump AS-REP roastable hashes",
    )
    p.add_argument("-o", "--output", help="Write hashes to file")
    p.add_argument("--user-list", help="Probe usernames from file (no auth)")
    p.set_defaults(handler=handle)


def handle(args: argparse.Namespace) -> int:
    print("[stub] asreproast is implemented in Phase 2.")
    return int(ExitCode.SUCCESS)
