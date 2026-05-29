"""Regression tests for connection helpers — base_dn resolution in particular,
since picking the wrong NC silently breaks every module."""

from __future__ import annotations

from types import SimpleNamespace

from adex.connection import _resolve_default_naming_context


def _server_with(other: dict, naming: list[str] | None = None) -> SimpleNamespace:
    info = SimpleNamespace(other=other, naming_contexts=naming or [])
    return SimpleNamespace(info=info)


def test_prefers_default_naming_context():
    """When rootDSE returns defaultNamingContext, use it — even if
    naming_contexts[0] is something else."""
    s = _server_with(
        other={"defaultNamingContext": ["DC=north,DC=sevenkingdoms,DC=local"]},
        naming=["CN=Configuration,DC=sevenkingdoms,DC=local",
                "CN=Schema,CN=Configuration,DC=sevenkingdoms,DC=local",
                "DC=north,DC=sevenkingdoms,DC=local"],
    )
    assert _resolve_default_naming_context(s) == "DC=north,DC=sevenkingdoms,DC=local"


def test_falls_back_to_filtered_naming_contexts():
    """No defaultNamingContext key — pick a DC=-prefixed NC that isn't
    Configuration / Schema / DnsZones."""
    s = _server_with(
        other={},
        naming=["CN=Configuration,DC=corp,DC=local",
                "CN=Schema,CN=Configuration,DC=corp,DC=local",
                "DC=DomainDnsZones,DC=corp,DC=local",
                "DC=corp,DC=local"],
    )
    assert _resolve_default_naming_context(s) == "DC=corp,DC=local"


def test_handles_string_default_naming_context():
    """Some rootDSE responses give the value as a bare string, not a list."""
    s = _server_with(
        other={"defaultNamingContext": "DC=corp,DC=local"},
        naming=[],
    )
    assert _resolve_default_naming_context(s) == "DC=corp,DC=local"


def test_returns_empty_when_no_info():
    s = SimpleNamespace(info=None)
    assert _resolve_default_naming_context(s) == ""


def test_last_resort_first_naming_context():
    """If even the filtered list is empty (somehow), don't crash — return
    the first NC and let the module surface its own error."""
    s = _server_with(other={}, naming=["CN=Configuration,DC=corp,DC=local"])
    # No DC=-only NC available, fall back to first
    assert _resolve_default_naming_context(s) == "CN=Configuration,DC=corp,DC=local"
