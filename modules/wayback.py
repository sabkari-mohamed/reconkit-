"""Historical URL discovery via the Internet Archive Wayback Machine.

Passive: reads archive.org's CDX index (no traffic to the target). Returns
historical URLs, derives extra subdomains, and flags potentially sensitive
endpoints (admin panels, API paths, config/backup files, auth, uploads).

Reference: https://github.com/internetarchive/wayback/tree/master/wayback-cdx-server
"""

from __future__ import annotations

from urllib.parse import urlparse

import requests

USER_AGENT = "ReconKit/1.0 (+authorized-osint)"
CDX_URL = "https://web.archive.org/cdx/search/cdx"

# Substrings that make an archived URL worth a closer look.
INTERESTING = (
    "admin", "login", "signin", "dashboard", "api", "graphql", "swagger",
    "upload", "backup", "config", "debug", "phpinfo", "internal", "staging",
    "dev", "test", "token", "apikey", "api_key", "secret", "password",
    ".sql", ".bak", ".env", ".json", ".xml", ".log", ".zip", ".tar", ".git",
)


class WaybackMachine:
    """Query the Wayback Machine CDX index for ``domain``."""

    def __init__(self, domain: str, limit: int = 1000, timeout: int = 40,
                 console=None) -> None:
        """Create the helper.

        Args:
            domain: Domain to query.
            limit: Maximum number of archived URLs to retrieve.
            timeout: HTTP timeout in seconds (archive.org can be slow).
            console: Optional ``rich.console.Console`` for status output.
        """
        self.domain = domain.strip().lower().lstrip("*.")
        self.limit = limit
        self.timeout = timeout
        self.console = console

    def _log(self, message: str, style: str = "cyan") -> None:
        if self.console is not None:
            self.console.print(message, style=style)

    def _is_in_scope(self, host: str) -> bool:
        return host == self.domain or host.endswith("." + self.domain)

    def fetch(self) -> dict:
        """Return ``{urls, interesting, subdomains, count}`` from the archive."""
        params = {
            "url": f"*.{self.domain}/*",
            "output": "json",
            "fl": "original,timestamp,statuscode,mimetype",
            "collapse": "urlkey",
            "limit": str(self.limit),
        }
        try:
            resp = requests.get(CDX_URL, params=params,
                                headers={"User-Agent": USER_AGENT},
                                timeout=self.timeout)
            resp.raise_for_status()
            rows = resp.json()
        except requests.exceptions.JSONDecodeError:
            self._log("[wayback] empty / non-JSON response", "yellow")
            return {"urls": [], "interesting": [], "subdomains": [], "count": 0}
        except requests.RequestException as exc:
            self._log(f"[wayback] request failed (archive.org slow?): {exc}",
                      "yellow")
            return {"urls": [], "interesting": [], "subdomains": [], "count": 0}

        urls: set[str] = set()
        subdomains: set[str] = set()
        interesting: list[dict] = []
        for row in rows[1:] if rows and rows[0] and rows[0][0] == "original" \
                else rows:
            if not row:
                continue
            url = row[0]
            urls.add(url)
            host = urlparse(url).netloc.split(":")[0].lower()
            if self._is_in_scope(host):
                subdomains.add(host)
            low = url.lower()
            hit = next((kw for kw in INTERESTING if kw in low), None)
            if hit:
                interesting.append({"url": url, "match": hit})

        self._log(
            f"[wayback] {len(urls)} archived URL(s), "
            f"{len(interesting)} interesting, {len(subdomains)} host(s)",
            "green" if urls else "yellow")
        return {
            "urls": sorted(urls),
            "interesting": interesting[:200],
            "subdomains": sorted(subdomains),
            "count": len(urls),
        }


if __name__ == "__main__":  # pragma: no cover - manual test entry point
    import sys, json
    from rich.console import Console
    target = sys.argv[1] if len(sys.argv) > 1 else "example.com"
    print(json.dumps(WaybackMachine(target, console=Console()).fetch(),
                     indent=2)[:2000])
