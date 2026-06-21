"""External tool orchestration — integrate best-in-class GitHub recon tools.

ReconKit ships a complete pure-Python passive pipeline, but if the user has
the industry-standard tools installed it will automatically orchestrate them
for far broader coverage:

  * subfinder (ProjectDiscovery) — passive subdomain enum across ~30 sources
  * amass     (OWASP)            — passive subdomain enum (`-passive`)
  * gau       (lc/gau)           — known URLs from Wayback/OTX/CommonCrawl/urlscan

All three run in **passive** mode (no traffic to the target). Each tool is
auto-detected via ``shutil.which`` and skipped gracefully — with an install
hint — when missing. ReconKit therefore works with zero external tools and
gets stronger as you add them.
"""

from __future__ import annotations

import re
import shutil
import subprocess
from typing import Callable
from urllib.parse import urlparse

# domain chars only — defensive guard before building a subprocess argv
_SAFE_DOMAIN = re.compile(r"^[a-z0-9.-]+$", re.IGNORECASE)


class Tool:
    """Definition of one external command-line tool."""

    def __init__(self, name: str, argv: Callable[[str], list[str]],
                 kind: str, install: str) -> None:
        self.name = name
        self.argv = argv          # domain -> argument list
        self.kind = kind          # "subdomains" | "urls"
        self.install = install    # install hint


TOOLS: dict[str, Tool] = {
    "subfinder": Tool(
        "subfinder",
        lambda d: ["subfinder", "-d", d, "-all", "-silent"],
        "subdomains",
        "go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest",
    ),
    "amass": Tool(
        "amass",
        lambda d: ["amass", "enum", "-passive", "-d", d, "-timeout", "3"],
        "subdomains",
        "go install github.com/owasp-amass/amass/v4/...@master",
    ),
    "gau": Tool(
        "gau",
        lambda d: ["gau", d, "--subs", "--threads", "5"],
        "urls",
        "go install github.com/lc/gau/v2/cmd/gau@latest",
    ),
}


class ExternalTools:
    """Detect and orchestrate installed external recon tools (passive)."""

    def __init__(self, domain: str, timeout: int = 150, console=None) -> None:
        """Create the orchestrator.

        Args:
            domain: Target domain (must already be validated upstream).
            timeout: Per-tool subprocess timeout in seconds.
            console: Optional ``rich.console.Console`` for status output.
        """
        self.domain = domain.strip().lower().lstrip("*.")
        self.timeout = timeout
        self.console = console

    def _log(self, message: str, style: str = "cyan") -> None:
        if self.console is not None:
            self.console.print(message, style=style)

    def available(self) -> dict[str, str | None]:
        """Return ``{tool_name: path_or_None}`` for every known tool."""
        return {name: shutil.which(name) for name in TOOLS}

    def _in_scope(self, host: str) -> bool:
        host = host.strip().lower().rstrip(".")
        return host == self.domain or host.endswith("." + self.domain)

    def _run(self, tool: Tool) -> list[str]:
        """Run one tool and return its stdout lines (empty on any failure)."""
        if not _SAFE_DOMAIN.match(self.domain):
            return []
        path = shutil.which(tool.name)
        if path is None:
            self._log(f"[tools] {tool.name} not installed — "
                      f"skipping (install: {tool.install})", "yellow")
            return []
        argv = tool.argv(self.domain)
        argv[0] = path                     # use resolved absolute path
        try:
            proc = subprocess.run(
                argv,
                capture_output=True, text=True,
                timeout=self.timeout, check=False,
            )
        except subprocess.TimeoutExpired:
            self._log(f"[tools] {tool.name} timed out after "
                      f"{self.timeout}s", "yellow")
            return []
        except (OSError, ValueError) as exc:
            self._log(f"[tools] {tool.name} failed: {exc}", "yellow")
            return []
        return [ln.strip() for ln in proc.stdout.splitlines() if ln.strip()]

    def enrich(self) -> dict:
        """Run every available tool; return merged subdomains + URLs + status.

        Returns:
            ``{available, used, subdomains, urls, counts}``.
        """
        available = self.available()
        used: list[str] = []
        subdomains: set[str] = set()
        urls: set[str] = set()
        counts: dict[str, int] = {}

        for name, tool in TOOLS.items():
            if not available[name]:
                continue
            lines = self._run(tool)
            if tool.kind == "subdomains":
                hits = {ln.lower() for ln in lines if self._in_scope(ln)}
                subdomains |= hits
                counts[name] = len(hits)
            else:  # urls
                hits = set()
                for ln in lines:
                    urls.add(ln)
                    host = urlparse(ln).netloc.split(":")[0]
                    if self._in_scope(host):
                        subdomains.add(host.lower())
                    hits.add(ln)
                counts[name] = len(hits)
            if name in counts:
                used.append(name)
                self._log(f"[tools] {name}: {counts[name]} result(s)", "green")

        installed = [n for n, p in available.items() if p]
        if not installed:
            self._log("[tools] no external tools installed — using built-in "
                      "sources only (subfinder/amass/gau boost coverage)",
                      "yellow")

        return {
            "available": {n: bool(p) for n, p in available.items()},
            "used": used,
            "subdomains": sorted(subdomains),
            "urls": sorted(urls),
            "counts": counts,
        }


if __name__ == "__main__":  # pragma: no cover - manual test entry point
    import sys, json
    from rich.console import Console
    target = sys.argv[1] if len(sys.argv) > 1 else "example.com"
    out = ExternalTools(target, console=Console()).enrich()
    out["urls"] = out["urls"][:20]
    out["subdomains"] = out["subdomains"][:20]
    print(json.dumps(out, indent=2))
