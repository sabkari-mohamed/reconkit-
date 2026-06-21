"""Aggregate per-module results into a single structured report object."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Iterable, Optional

from modules.risk import RiskScorer


class Aggregator:
    """Merge module outputs, derive notes + risk, and compute summary counts."""

    def __init__(self, target: str) -> None:
        """Create an aggregator for ``target``."""
        self.target = target.strip().lower().lstrip("*.")
        self._subs: dict[str, dict] = {}   # name -> {subdomain, resolves, ip}
        self._urls: set[str] = set()       # merged URLs from all sources
        self._interesting: list[dict] = []
        self._url_sources: dict[str, int] = {}
        self._urlscan_results: list[dict] = []
        self.data: dict = {
            "target": self.target,
            "scan_date": datetime.now(timezone.utc).strftime(
                "%Y-%m-%d %H:%M:%S UTC"),
            "whois": {},
            "dns": {},
            "subdomains": [],
            "emails": [],
            "shodan": [],
            "asn": {},
            "urls": {},
            "threat": {},
            "tools": {},
            "security_notes": [],
            "risk": {},
            "summary": {},
        }

    # ------------------------------------------------------------------ #
    # ingestion
    # ------------------------------------------------------------------ #
    def add_whois(self, whois_data: Optional[dict]) -> None:
        self.data["whois"] = whois_data or {}

    def add_dns(self, dns_data: Optional[dict]) -> None:
        self.data["dns"] = dns_data or {}

    def _merge_sub(self, row: dict) -> None:
        name = row.get("subdomain")
        if not name:
            return
        existing = self._subs.get(name)
        if existing is None:
            self._subs[name] = row
            return
        # prefer a row that resolves / carries an IP
        if row.get("resolves") and not existing.get("resolves"):
            self._subs[name] = row
        elif row.get("ip") and not existing.get("ip"):
            existing["ip"] = row["ip"]
            existing["resolves"] = True

    def add_subdomains(self, subdomains: Optional[list[dict]]) -> None:
        """Merge a list of ``{subdomain, resolves, ip}`` rows (idempotent)."""
        for row in subdomains or []:
            self._merge_sub(row)

    def merge_subdomain_names(self, names: Optional[Iterable[str]]) -> None:
        """Fold in bare hostnames discovered by secondary sources."""
        for name in names or []:
            self._merge_sub({"subdomain": name, "resolves": None, "ip": None})

    def add_emails(self, emails: Optional[list[dict]]) -> None:
        seen: set[str] = set()
        deduped: list[dict] = []
        for row in emails or []:
            addr = (row.get("email") or "").lower()
            if addr and addr not in seen:
                seen.add(addr)
                deduped.append(row)
        self.data["emails"] = sorted(deduped, key=lambda r: r["email"] or "")

    def add_shodan(self, shodan_data: Optional[list[dict]]) -> None:
        self.data["shodan"] = shodan_data or []

    def add_asn(self, asn_data: Optional[dict]) -> None:
        self.data["asn"] = asn_data or {}

    def add_threat(self, threat_data: Optional[dict]) -> None:
        self.data["threat"] = threat_data or {}
        if threat_data:
            self.merge_subdomain_names(threat_data.get("subdomains"))

    def add_urls(self, wayback: Optional[dict] = None,
                 urlscan: Optional[dict] = None) -> None:
        """Merge Wayback + urlscan URL findings into the URL accumulators."""
        wayback = wayback or {}
        urlscan = urlscan or {}
        self._urls.update(wayback.get("urls", []))
        for r in urlscan.get("results", []):
            if r.get("url"):
                self._urls.add(r["url"])
        self._interesting.extend(wayback.get("interesting", []))
        self._urlscan_results = urlscan.get("results", []) or self._urlscan_results
        self.merge_subdomain_names(wayback.get("subdomains"))
        self.merge_subdomain_names(urlscan.get("subdomains"))
        self._url_sources["wayback"] = wayback.get(
            "count", len(wayback.get("urls", [])))
        self._url_sources["urlscan"] = len(urlscan.get("results", []))

    def add_tools(self, tools_data: Optional[dict]) -> None:
        """Ingest external-tool (subfinder/amass/gau) orchestration results."""
        tools_data = tools_data or {}
        self.data["tools"] = {
            "available": tools_data.get("available", {}),
            "used": tools_data.get("used", []),
            "counts": tools_data.get("counts", {}),
        }
        self.merge_subdomain_names(tools_data.get("subdomains"))
        self._urls.update(tools_data.get("urls", []))
        if tools_data.get("urls"):
            self._url_sources["gau"] = len(tools_data["urls"])

    # ------------------------------------------------------------------ #
    # derivation
    # ------------------------------------------------------------------ #
    def _derive_security_notes(self) -> list[str]:
        notes: list[str] = []
        dns = self.data.get("dns", {})
        if dns:
            if dns.get("spf_missing"):
                notes.append("No SPF record found — domain spoofing risk.")
            if dns.get("dmarc_missing"):
                notes.append("No DMARC record found — weak email anti-spoofing.")

        whois_data = self.data.get("whois", {})
        if whois_data.get("expiring_soon"):
            days = whois_data.get("days_to_expiry")
            notes.append(
                f"Domain expires in {days} day(s) — renewal/takeover risk.")

        for host in self.data.get("shodan", []):
            if host.get("vulns"):
                notes.append(
                    f"Shodan reports {len(host['vulns'])} CVE tag(s) on "
                    f"{host['ip']}: {', '.join(host['vulns'][:5])}"
                    + (" ..." if len(host["vulns"]) > 5 else "")
                )

        interesting = (self.data.get("urls", {}) or {}).get("interesting", [])
        if interesting:
            notes.append(
                f"{len(interesting)} archived URL(s) match sensitive patterns "
                "(admin/api/config/backup) — review for exposure.")

        threat = self.data.get("threat", {})
        if threat.get("malicious"):
            notes.append(
                f"Domain appears in {threat.get('pulses')} OTX threat "
                "pulse(s) — reputation check advised.")
        return notes

    def _derive_summary(self) -> dict:
        subs = list(self._subs.values())
        open_ports = sum(len(h.get("ports", [])) for h in self.data["shodan"])
        urls = self.data.get("urls", {}) or {}
        return {
            "subdomains": len(subs),
            "live_hosts": sum(1 for s in subs if s.get("resolves")),
            "emails": len(self.data.get("emails", [])),
            "shodan_hosts": len(self.data.get("shodan", [])),
            "open_ports": open_ports,
            "asn_count": len((self.data.get("asn", {}) or {}).get("networks", [])),
            "archived_urls": urls.get("count", 0),
            "interesting_urls": len(urls.get("interesting", [])),
            "threat_pulses": (self.data.get("threat", {}) or {}).get("pulses", 0),
            "tools_used": len((self.data.get("tools", {}) or {}).get("used", [])),
            "security_notes": len(self.data.get("security_notes", [])),
        }

    def aggregate(self) -> dict:
        """Finalise subdomains, URLs, notes, summary, and risk; return data."""
        self.data["subdomains"] = sorted(
            self._subs.values(), key=lambda r: r["subdomain"])
        if self._urls or self._interesting:
            self.data["urls"] = {
                "all": sorted(self._urls),
                "interesting": self._interesting,
                "urlscan_results": self._urlscan_results,
                "count": len(self._urls),
                "sources": self._url_sources,
            }
        self.data["security_notes"] = self._derive_security_notes()
        self.data["summary"] = self._derive_summary()
        self.data["risk"] = RiskScorer(self.data).score()
        return self.data
