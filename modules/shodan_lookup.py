"""Shodan host lookup (passive — reads Shodan's existing scan data).

We resolve the domain (and any provided subdomain IPs) to addresses, then
ask Shodan what it already knows about those hosts. ReconKit performs no
active scanning itself. Skips with a warning when no API key is configured.
"""

from __future__ import annotations

import socket
from typing import Iterable, Optional

try:
    import shodan
    from shodan.exception import APIError

    _HAVE_SHODAN = True
except ImportError:  # pragma: no cover - shodan is a hard dependency
    _HAVE_SHODAN = False


class ShodanLookup:
    """Look up host intelligence on Shodan for a domain and its IPs."""

    def __init__(self, api_key: Optional[str], console=None) -> None:
        """Create the lookup helper.

        Args:
            api_key: Shodan API key, or ``None`` to skip the module.
            console: Optional ``rich.console.Console`` for status output.
        """
        self.api_key = api_key
        self.console = console
        self._api = shodan.Shodan(api_key) if (api_key and _HAVE_SHODAN) else None

    def _log(self, message: str, style: str = "cyan") -> None:
        if self.console is not None:
            self.console.print(message, style=style)

    @staticmethod
    def _resolve(host: str) -> Optional[str]:
        """Resolve ``host`` to an IPv4 address, or ``None``."""
        try:
            return socket.gethostbyname(host)
        except (socket.gaierror, OSError):
            return None

    def _collect_ips(self, domain: str, extra_ips: Iterable[str]) -> list[str]:
        """Build a deduped list of IPs from the domain plus extra IPs."""
        ips: set[str] = set()
        apex_ip = self._resolve(domain)
        if apex_ip:
            ips.add(apex_ip)
        for ip in extra_ips:
            if ip:
                ips.add(ip)
        return sorted(ips)

    def _host(self, ip: str) -> Optional[dict]:
        """Return a normalised Shodan host record for ``ip`` or ``None``."""
        try:
            host = self._api.host(ip)
        except APIError as exc:
            msg = str(exc)
            if "No information available" in msg:
                self._log(f"[shodan] {ip}: no data indexed", "yellow")
            elif "Invalid API key" in msg or "401" in msg:
                self._log("[shodan] invalid API key (401)", "yellow")
            elif "rate limit" in msg.lower() or "429" in msg:
                self._log("[shodan] rate limit hit (429)", "yellow")
            else:
                self._log(f"[shodan] {ip}: {msg}", "yellow")
            return None

        services = []
        for item in host.get("data", []):
            services.append({
                "port": item.get("port"),
                "transport": item.get("transport"),
                "product": item.get("product"),
                "version": item.get("version"),
                "banner": (item.get("data") or "").strip()[:300],
            })
        return {
            "ip": ip,
            "hostnames": host.get("hostnames", []),
            "org": host.get("org"),
            "isp": host.get("isp"),
            "country": host.get("country_name"),
            "os": host.get("os"),
            "last_update": host.get("last_update"),
            "ports": sorted(host.get("ports", [])),
            "vulns": sorted(host.get("vulns", [])),
            "services": services,
        }

    def resolve_and_lookup(
        self, domain: str, extra_ips: Optional[Iterable[str]] = None
    ) -> list[dict]:
        """Resolve the domain + extra IPs and return per-IP Shodan records.

        Args:
            domain: Apex domain to resolve.
            extra_ips: Already-resolved subdomain IPs to include (deduped).

        Returns:
            A list of per-IP Shodan host dicts (only those with data).
        """
        if not self.api_key:
            self._log("[shodan] Shodan key not set, skipping host lookup",
                      "yellow")
            return []
        if not _HAVE_SHODAN:
            self._log("[shodan] shodan library unavailable, skipping", "yellow")
            return []

        ips = self._collect_ips(domain, extra_ips or [])
        if not ips:
            self._log("[shodan] no IPs resolved, skipping", "yellow")
            return []

        results: list[dict] = []
        for ip in ips:
            record = self._host(ip)
            if record:
                self._log(
                    f"[shodan] {ip}: {len(record['ports'])} port(s), "
                    f"{len(record['vulns'])} vuln tag(s)",
                    "green",
                )
                results.append(record)
        return results


if __name__ == "__main__":  # pragma: no cover - manual test entry point
    import os
    import sys
    import json
    from rich.console import Console

    target = sys.argv[1] if len(sys.argv) > 1 else "example.com"
    key = os.environ.get("SHODAN_API_KEY")
    print(json.dumps(
        ShodanLookup(key, console=Console()).resolve_and_lookup(target),
        indent=2,
    ))
