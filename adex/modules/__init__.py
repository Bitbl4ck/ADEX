"""Module registry. Each submodule that defines a `ModuleBase` subclass
named with `name = "..."` is auto-registered."""

from __future__ import annotations

import importlib
import pkgutil
from collections.abc import Iterable

from adex.modules.base import ModuleBase

# Order in which modules appear in --list-modules and run by default.
_MODULE_ORDER = [
    "domain",
    "creds",
    "rights",
    "delegation",
    "adcs",
    "accounts",
    "gpo",
    "computer",
    "application",
]


def _discover() -> dict[str, type[ModuleBase]]:
    found: dict[str, type[ModuleBase]] = {}
    pkg = importlib.import_module(__name__)
    for info in pkgutil.iter_modules(pkg.__path__):
        if info.name in {"base", "__init__"}:
            continue
        m = importlib.import_module(f"{__name__}.{info.name}")
        for attr in dir(m):
            obj = getattr(m, attr)
            if (
                isinstance(obj, type)
                and issubclass(obj, ModuleBase)
                and obj is not ModuleBase
                and getattr(obj, "name", "")
            ):
                found[obj.name] = obj
    return found


def all_modules() -> list[type[ModuleBase]]:
    discovered = _discover()
    ordered = [discovered[n] for n in _MODULE_ORDER if n in discovered]
    extras = [discovered[n] for n in sorted(discovered) if n not in _MODULE_ORDER]
    return ordered + extras


def select(names: Iterable[str] | None, opsec_only: bool = False) -> list[type[ModuleBase]]:
    discovered = {m.name: m for m in all_modules()}
    if names:
        out: list[type[ModuleBase]] = []
        unknown = []
        for n in names:
            if n in discovered:
                out.append(discovered[n])
            else:
                unknown.append(n)
        if unknown:
            raise KeyError(f"unknown module(s): {', '.join(unknown)}")
    else:
        out = all_modules()
    if opsec_only:
        out = [m for m in out if m.opsec_safe]
    return out
