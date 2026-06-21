"""Project metadata for ReconKit — single source of truth for branding."""

from __future__ import annotations

__version__ = "2.1.0"
__author__ = "Mohamed Sabkari"
__license__ = "MIT"
__url__ = "https://github.com/sabkari-mohamed/reconkit-"
TAGLINE = "Passive OSINT Reconnaissance Toolkit"

# Figlet-style wordmark (ANSI Shadow trimmed for terminal width).
LOGO = r"""
 ____                       _  ___ _
|  _ \ ___  ___ ___  _ __  | |/ (_) |_
| |_) / _ \/ __/ _ \| '_ \ | ' /| | __|
|  _ <  __/ (_| (_) | | | || . \| | |_
|_| \_\___|\___\___/|_| |_||_|\_\_|\__|
"""


def banner_text() -> str:
    """Return the rich-markup banner body shown at startup."""
    return (
        f"[bold green]{LOGO}[/bold green]\n"
        f"[bold]{TAGLINE}[/bold]  [dim]·[/dim]  [cyan]v{__version__}[/cyan]\n"
        f"[dim]by[/dim] [bold]{__author__}[/bold]\n\n"
        "[yellow]Passive sources only.[/yellow] [dim]Use on domains you own or "
        "are\nexplicitly authorized to assess (bug bounty in-scope).[/dim]"
    )


def version_string() -> str:
    """Return the one-line ``--version`` string."""
    return f"reconkit {__version__} — by {__author__}"


def meta_dict() -> dict:
    """Return the metadata block embedded in JSON/HTML reports."""
    return {
        "tool": "ReconKit",
        "version": __version__,
        "author": __author__,
        "license": __license__,
        "url": __url__,
    }
