"""Subdomain enumeration via Certificate Transparency logs.

Sources (all passive / public):
  * crt.sh        — https://crt.sh/?q=%25.<domain>&output=json
  * certspotter   — https://api.certspotter.com/v1/issuances

No traffic is sent to the target. We only read public CT log data and then
optionally perform standard DNS A-record lookups to mark which discovered
names currently resolve (live) versus are only historical.
"""

from __future__ import annotations

import time
from typing import Optional

import requests

try:
    import dns.resolver
    import dns.exception

    _HAVE_DNS = True
except ImportError:  # pragma: no cover - dnspython is a hard dependency
    _HAVE_DNS = False

USER_AGENT = "ReconKit/1.0 (+authorized-osint; contact: admin@localhost)"


class SubdomainEnumerator:
    """Enumerate subdomains for ``domain`` from Certificate Transparency logs."""

    def __init__(
        self,
        domain: str,
        timeout: int = 25,
        delay: float = 1.0,
        console=None,
    ) -> None:
        """Create an enumerator.

        Args:
            domain: Apex domain to enumerate (e.g. ``example.com``).
            timeout: Per-request HTTP timeout in seconds.
            delay: Polite delay (seconds) inserted between source requests.
            console: Optional ``rich.console.Console`` for status messages.
        """
        self.domain = domain.strip().lower().lstrip("*.")
        self.timeout = timeout
        self.delay = delay
        self.console = console
        self._session = requests.Session()
        self._session.headers.update({"User-Agent": USER_AGENT})

    # ------------------------------------------------------------------ #
    # logging helper
    # ------------------------------------------------------------------ #
    def _log(self, message: str, style: str = "cyan") -> None:
        if self.console is not None:
            self.console.print(message, style=style)

    def _clean(self, name: str) -> Optional[str]:
        """Normalise a CT ``name_value`` entry into a single hostname."""
        name = name.strip().lower().lstrip("*.")
        if not name or "@" in name:
            return None
        if name != self.domain and not name.endswith("." + self.domain):
            return None
        return name

    # ------------------------------------------------------------------ #
    # sources
    # ------------------------------------------------------------------ #
    def from_crtsh(self) -> set[str]:
        """Return the set of names found in crt.sh certificate data."""
        found: set[str] = set()
        url = f"https://crt.sh/?q=%25.{self.domain}&output=json"
        try:
            resp = self._session.get(url, timeout=self.timeout)
            resp.raise_for_status()
            data = resp.json()
        except requests.exceptions.JSONDecodeError:
            self._log("[crt.sh] empty / non-JSON response, skipping", "yellow")
            return found
        except requests.RequestException as exc:
            self._log(f"[crt.sh] request failed: {exc}", "yellow")
            return found

        for entry in data:
            for field in ("name_value", "common_name"):
                raw = entry.get(field, "")
                for line in str(raw).splitlines():
                    cleaned = self._clean(line)
                    if cleaned:
                        found.add(cleaned)
        self._log(f"[crt.sh] {len(found)} unique names", "green")
        return found

    def from_cert_transparency(self) -> set[str]:
        """Return names found via the certspotter CT API (broader coverage)."""
        found: set[str] = set()
        url = (
            "https://api.certspotter.com/v1/issuances"
            f"?domain={self.domain}&include_subdomains=true&expand=dns_names"
        )
        try:
            resp = self._session.get(url, timeout=self.timeout)
            if resp.status_code == 429:
                self._log("[certspotter] rate limited (429), skipping", "yellow")
                return found
            resp.raise_for_status()
            data = resp.json()
        except requests.exceptions.JSONDecodeError:
            self._log("[certspotter] non-JSON response, skipping", "yellow")
            return found
        except requests.RequestException as exc:
            self._log(f"[certspotter] request failed: {exc}", "yellow")
            return found

        for entry in data:
            for name in entry.get("dns_names", []):
                cleaned = self._clean(name)
                if cleaned:
                    found.add(cleaned)
        self._log(f"[certspotter] {len(found)} unique names", "green")
        return found

    # ------------------------------------------------------------------ #
    # resolution
    # ------------------------------------------------------------------ #
    @staticmethod
    def _resolve(host: str, timeout: float = 3.0) -> Optional[str]:
        """Return the first A-record IP for ``host`` or ``None``."""
        if not _HAVE_DNS:
            return None
        resolver = dns.resolver.Resolver()
        resolver.lifetime = timeout
        resolver.timeout = timeout
        try:
            answer = resolver.resolve(host, "A")
            return answer[0].to_text()
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer,
                dns.resolver.NoNameservers, dns.exception.Timeout,
                dns.exception.DNSException):
            return None

    def resolve_live(self, subdomains: set[str]) -> list[dict]:
        """Resolve each subdomain, marking live (resolving) vs historical."""
        results: list[dict] = []
        for host in sorted(subdomains):
            ip = self._resolve(host)
            results.append({"subdomain": host, "resolves": ip is not None, "ip": ip})
        live = sum(1 for r in results if r["resolves"])
        self._log(f"[resolve] {live}/{len(results)} resolve live", "green")
        return results

    # ------------------------------------------------------------------ #
    # public entry point
    # ------------------------------------------------------------------ #
    def enumerate(self, resolve: bool = True) -> list[dict]:
        """Run all CT sources, merge, dedupe, optionally resolve.

        Returns:
            List of ``{subdomain, resolves, ip}`` dicts, sorted by name.
        """
        names = self.from_crtsh()
        time.sleep(self.delay)
        names |= self.from_cert_transparency()

        if resolve:
            return self.resolve_live(names)
        return [
            {"subdomain": host, "resolves": None, "ip": None}
            for host in sorted(names)
        ]


if __name__ == "__main__":  # pragma: no cover - manual test entry point
    import sys
    from rich.console import Console

    target = sys.argv[1] if len(sys.argv) > 1 else "example.com"
    enum = SubdomainEnumerator(target, console=Console())
    for row in enum.enumerate():
        print(row)
