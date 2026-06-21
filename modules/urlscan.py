"""urlscan.io passive lookup.

Reads urlscan.io's existing public scan index for a domain (no scan is
submitted by ReconKit). Surfaces previously observed URLs, IPs, servers, and
screenshot links. Works without an API key (rate-limited); an optional key
raises the limits.

Reference: https://urlscan.io/docs/api/
"""

from __future__ import annotations

from typing import Optional

import requests

USER_AGENT = "ReconKit/1.0 (+authorized-osint)"
SEARCH_URL = "https://urlscan.io/api/v1/search/"


class URLScanLookup:
    """Query urlscan.io's public scan history for ``domain``."""

    def __init__(self, domain: str, api_key: Optional[str] = None,
                 size: int = 100, timeout: int = 25, console=None) -> None:
        """Create the lookup helper.

        Args:
            domain: Domain to search.
            api_key: Optional urlscan.io API key (raises rate limits).
            size: Maximum number of results to request.
            timeout: HTTP timeout in seconds.
            console: Optional ``rich.console.Console`` for status output.
        """
        self.domain = domain.strip().lower().lstrip("*.")
        self.api_key = api_key
        self.size = size
        self.timeout = timeout
        self.console = console

    def _log(self, message: str, style: str = "cyan") -> None:
        if self.console is not None:
            self.console.print(message, style=style)

    def search(self) -> dict:
        """Return ``{results: [...], subdomains: [...], ips: [...]}``.

        Each result is ``{url, ip, server, country, time, scan_url}``.
        """
        headers = {"User-Agent": USER_AGENT}
        if self.api_key:
            headers["API-Key"] = self.api_key
        params = {"q": f"domain:{self.domain}", "size": str(self.size)}

        try:
            resp = requests.get(SEARCH_URL, params=params, headers=headers,
                                timeout=self.timeout)
        except requests.RequestException as exc:
            self._log(f"[urlscan] request failed: {exc}", "yellow")
            return {"results": [], "subdomains": [], "ips": []}

        if resp.status_code == 429:
            self._log("[urlscan] rate limit hit (429), skipping", "yellow")
            return {"results": [], "subdomains": [], "ips": []}
        if resp.status_code != 200:
            self._log(f"[urlscan] HTTP {resp.status_code}", "yellow")
            return {"results": [], "subdomains": [], "ips": []}

        try:
            data = resp.json()
        except ValueError:
            self._log("[urlscan] could not parse response", "yellow")
            return {"results": [], "subdomains": [], "ips": []}

        results: list[dict] = []
        subdomains: set[str] = set()
        ips: set[str] = set()
        for item in data.get("results", []):
            page = item.get("page", {})
            url = page.get("url")
            ip = page.get("ip")
            results.append({
                "url": url,
                "ip": ip,
                "server": page.get("server"),
                "country": page.get("country"),
                "time": (item.get("task", {}) or {}).get("time"),
                "scan_url": item.get("result"),
            })
            host = page.get("domain")
            if host and (host == self.domain or host.endswith("." + self.domain)):
                subdomains.add(host)
            if ip:
                ips.add(ip)

        self._log(
            f"[urlscan] {len(results)} scan(s), {len(subdomains)} host(s), "
            f"{len(ips)} IP(s)", "green" if results else "yellow")
        return {
            "results": results,
            "subdomains": sorted(subdomains),
            "ips": sorted(ips),
        }


if __name__ == "__main__":  # pragma: no cover - manual test entry point
    import sys, json
    from rich.console import Console
    target = sys.argv[1] if len(sys.argv) > 1 else "example.com"
    print(json.dumps(URLScanLookup(target, console=Console()).search(),
                     indent=2)[:2000])
