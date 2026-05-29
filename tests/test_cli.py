import io
from contextlib import redirect_stderr, redirect_stdout

import pytest

from adex.cli import build_parser, main


def test_build_parser_smoke():
    p = build_parser()
    # The six subcommands declared in the README
    actions = [a for a in p._actions if hasattr(a, "choices") and a.choices]
    sub_choices = set()
    for a in actions:
        if isinstance(a.choices, dict):
            sub_choices.update(a.choices.keys())
    expected = {"enum", "kerberoast", "asreproast", "shadow-creds", "rbcd", "chain", "report"}
    assert expected.issubset(sub_choices), f"missing: {expected - sub_choices}"


def test_help_runs():
    p = build_parser()
    out = io.StringIO()
    with redirect_stdout(out):
        with pytest.raises(SystemExit) as ei:
            p.parse_args(["--help"])
    assert ei.value.code == 0
    assert "adex" in out.getvalue().lower()


def test_enum_list_modules(capsys):
    rc = main(["enum", "-d", "x", "-u", "u", "-p", "p", "-L"])
    captured = capsys.readouterr().out
    assert rc == 0
    # All 9 modules must appear in --list-modules output
    for name in ("domain", "creds", "rights", "delegation", "adcs",
                 "accounts", "gpo", "computer", "application"):
        assert name in captured


def test_module_registry_loads():
    from adex.modules import all_modules
    names = [m.name for m in all_modules()]
    assert sorted(names) == sorted([
        "domain", "creds", "rights", "delegation", "adcs",
        "accounts", "gpo", "computer", "application",
    ])
    impls = {m.name for m in all_modules() if m.implemented}
    assert impls == {"domain", "rights", "creds", "delegation", "adcs"}
