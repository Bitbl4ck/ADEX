"""Console banner shown at the start of any non-help ADEX run."""

from __future__ import annotations

from rich.console import Console

from adex.version import __version__

BANNER = r"""
  /$$$$$$  /$$$$$$$  /$$$$$$$$ /$$   /$$
 /$$__  $$| $$__  $$| $$_____/| $$  / $$
| $$  \ $$| $$  \ $$| $$      |  $$/ $$/
| $$$$$$$$| $$  | $$| $$$$$    \  $$$$/
| $$__  $$| $$  | $$| $$__/     >$$  $$
| $$  | $$| $$  | $$| $$       /$$/\  $$
| $$  | $$| $$$$$$$/| $$$$$$$$| $$  \ $$
|__/  |__/|_______/ |________/|__/  |__/
"""


def print_banner(console: Console | None = None, force: bool = False) -> None:
    """Print the ADEX banner. Skipped automatically when stdout is not a TTY
    (so that piping `adex … | tee` or `adex … | jq` doesn't pollute output).
    Pass `force=True` to print regardless."""
    console = console or Console()
    if not force and not console.is_terminal:
        return
    console.print(BANNER, style="bold red", highlight=False)
    console.print(
        f"  [bold red]Active Directory EXploitation[/bold red]  "
        f"[dim]v{__version__}  ·  by Bitbl4ck[/dim]\n"
    )
