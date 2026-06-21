"""Threat-intelligence enrichment via AlienVault OTX (public, no key).

Passive: reads OTX's public indicator data for the domain — historical
passive-DNS records and the number of threat "pulses" the domain appears in
(a reputation signal). Handles OTX's frequent shared-IP rate limiting (429)
gracefully.

Reference: https://otx.alienvault.com/api
"""

from __future__ import annotations

import requests

USER_AGENT = "ReconKit/1.0 (+authorized-osint)"
BASE = "https://otx.alienvault.com/api/v1/indicators/domain"


class ThreatIntel:
    """Query AlienVault OTX for passive DNS and reputation signals."""

    def __init__(self, domain: str, timeout: int = 20, console=None) -> None:
        """Create the helper.

        Args:
            domain: Domain to query.
            timeout: HTTP timeout in seconds.
            console: Optional ``rich.console.Console`` for status output.
        """
        self.domain = domain.strip().lower().lstrip("*.")
        self.timeout = timeout
        self.console = console

    def _log(self, message: str, style: str = "cyan") -> None:
        if self.console is not None:
            self.console.print(message, style=style)

    def _get(self, section: str) -> dict | None:
        url = f"{BASE}/{self.domain}/{section}"
        try:
            resp = requests.get(url, headers={"User-Agent": USER_AGENT},
                                timeout=self.timeout)
        except requests.RequestException as exc:
            self._log(f"[threat] request failed: {exc}", "yellow")
            return None
        if resp.status_code == 429:
            self._log("[threat] OTX rate limit hit (429), skipping", "yellow")
            return None
        if resp.status_code != 200:
            self._log(f"[threat] OTX HTTP {resp.status_code}", "yellow")
            return None
        try:
            return resp.json()
        except ValueError:
            return None

    def analyze(self) -> dict:
        """Return ``{passive_dns, ips, subdomains, pulses, malicious}``."""
        result = {"passive_dns": [], "ips": [], "subdomains": [],
                  "pulses": 0, "malicious": False}

        general = self._get("general")
        if general:
            pulses = (general.get("pulse_info", {}) or {}).get("count", 0)
            result["pulses"] = pulses
            result["malicious"] = pulses > 0

        pdns = self._get("passive_dns")
        if pdns:
            ips: set[str] = set()
            subs: set[str] = set()
            records: list[dict] = []
            for row in pdns.get("passive_dns", [])[:500]:
                host = (row.get("hostname") or "").lower().rstrip(".")
                addr = row.get("address")
                records.append({
                    "hostname": host, "address": addr,
                    "record_type": row.get("record_type"),
                    "last": row.get("last"),
                })
                if addr and ":" not in str(addr):
                    ips.add(addr)
                if host and (host == self.domain
                             or host.endswith("." + self.domain)):
                    subs.add(host)
            result["passive_dns"] = records
            result["ips"] = sorted(ips)
            result["subdomains"] = sorted(subs)

        self._log(
            f"[threat] {result['pulses']} pulse(s), "
            f"{len(result['passive_dns'])} passive-DNS record(s)",
            "red" if result["malicious"] else "green")
        return result


if __name__ == "__main__":  # pragma: no cover - manual test entry point
    import sys, json
    from rich.console import Console
    target = sys.argv[1] if len(sys.argv) > 1 else "example.com"
    print(json.dumps(ThreatIntel(target, console=Console()).analyze(),
                     indent=2)[:2000])
