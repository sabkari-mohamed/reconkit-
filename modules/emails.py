"""Email harvesting via the Hunter.io Domain Search API.

Passive: queries Hunter.io's existing index, not the target. Skips with a
clear warning when no API key is configured.
"""

from __future__ import annotations

from typing import Optional

import requests

USER_AGENT = "ReconKit/1.0 (+authorized-osint)"
API_URL = "https://api.hunter.io/v2/domain-search"


class EmailHarvester:
    """Harvest public email addresses for ``domain`` from Hunter.io."""

    def __init__(
        self,
        domain: str,
        api_key: Optional[str],
        limit: int = 100,
        timeout: int = 20,
        console=None,
    ) -> None:
        """Create the harvester.

        Args:
            domain: Domain to search.
            api_key: Hunter.io API key, or ``None`` to skip the module.
            limit: Maximum number of emails to request.
            timeout: HTTP timeout in seconds.
            console: Optional ``rich.console.Console`` for status output.
        """
        self.domain = domain.strip().lower().lstrip("*.")
        self.api_key = api_key
        self.limit = limit
        self.timeout = timeout
        self.console = console

    def _log(self, message: str, style: str = "cyan") -> None:
        if self.console is not None:
            self.console.print(message, style=style)

    def harvest(self) -> list[dict]:
        """Return a list of ``{email, first_name, last_name, position,
        confidence}`` dicts. Returns an empty list (with a warning) when the
        key is missing or the request fails.
        """
        if not self.api_key:
            self._log("[emails] Hunter.io key not set, skipping email harvest",
                      "yellow")
            return []

        params = {"domain": self.domain, "api_key": self.api_key,
                  "limit": self.limit}
        try:
            resp = requests.get(
                API_URL,
                params=params,
                timeout=self.timeout,
                headers={"User-Agent": USER_AGENT},
            )
        except requests.RequestException as exc:
            self._log(f"[emails] request failed: {exc}", "yellow")
            return []

        if resp.status_code == 401:
            self._log("[emails] Hunter.io rejected the API key (401)", "yellow")
            return []
        if resp.status_code == 429:
            self._log("[emails] Hunter.io rate limit hit (429)", "yellow")
            return []
        if resp.status_code != 200:
            self._log(f"[emails] Hunter.io HTTP {resp.status_code}", "yellow")
            return []

        try:
            payload = resp.json().get("data", {})
        except ValueError:
            self._log("[emails] could not parse Hunter.io response", "yellow")
            return []

        results: list[dict] = []
        for item in payload.get("emails", []):
            results.append({
                "email": item.get("value"),
                "first_name": item.get("first_name"),
                "last_name": item.get("last_name"),
                "position": item.get("position"),
                "confidence": item.get("confidence"),
            })
        self._log(f"[emails] {len(results)} address(es) found", "green")
        return results


if __name__ == "__main__":  # pragma: no cover - manual test entry point
    import os
    import sys
    import json
    from rich.console import Console

    target = sys.argv[1] if len(sys.argv) > 1 else "example.com"
    key = os.environ.get("HUNTER_API_KEY")
    print(json.dumps(
        EmailHarvester(target, key, console=Console()).harvest(), indent=2))
