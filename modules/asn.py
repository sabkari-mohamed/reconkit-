"""ASN / netblock enrichment via the Team Cymru IP-to-ASN DNS service.

Fully passive: standard cached DNS TXT lookups against cymru.com — no traffic
to the target. Maps each resolved IP to its origin ASN, BGP prefix, country,
registry, and the autonomous-system (organisation) name.

Reference: https://www.team-cymru.com/ip-asn-mapping
"""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from typing import Iterable, Optional

import dns.resolver
import dns.exception


class ASNLookup:
    """Resolve IPs to ASN / netblock / organisation via Team Cymru DNS."""

    def __init__(self, timeout: float = 5.0, workers: int = 10,
                 console=None) -> None:
        """Create the ASN lookup helper.

        Args:
            timeout: Per-query DNS timeout in seconds.
            workers: Thread-pool size for concurrent lookups.
            console: Optional ``rich.console.Console`` for status output.
        """
        self.workers = workers
        self.console = console
        self._resolver = dns.resolver.Resolver()
        self._resolver.timeout = timeout
        self._resolver.lifetime = timeout

    def _log(self, message: str, style: str = "cyan") -> None:
        if self.console is not None:
            self.console.print(message, style=style)

    def _txt(self, name: str) -> Optional[str]:
        try:
            return self._resolver.resolve(name, "TXT")[0].to_text().strip('"')
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer,
                dns.resolver.NoNameservers, dns.exception.DNSException):
            return None

    def lookup_ip(self, ip: str) -> Optional[dict]:
        """Return ASN / prefix / org details for a single IPv4 address."""
        if ":" in ip:          # IPv6 not handled by this simple resolver path
            return None
        rev = ".".join(reversed(ip.split(".")))
        origin = self._txt(f"{rev}.origin.asn.cymru.com")
        if not origin:
            return None
        # "ASN | BGP Prefix | CC | Registry | Allocated"
        parts = [p.strip() for p in origin.split("|")]
        asn = parts[0].split()[0] if parts and parts[0] else None
        prefix = parts[1] if len(parts) > 1 else None
        country = parts[2] if len(parts) > 2 else None
        registry = parts[3] if len(parts) > 3 else None

        as_name = None
        if asn:
            asinfo = self._txt(f"AS{asn}.asn.cymru.com")
            if asinfo:
                # "ASN | CC | Registry | Allocated | AS Name"
                ap = [p.strip() for p in asinfo.split("|")]
                as_name = ap[-1] if ap else None
        return {
            "ip": ip,
            "asn": f"AS{asn}" if asn else None,
            "prefix": prefix,
            "country": country,
            "registry": registry,
            "as_name": as_name,
        }

    def lookup_ips(self, ips: Iterable[str]) -> dict:
        """Look up many IPs concurrently; return per-host + unique networks.

        Returns:
            ``{hosts: [...], networks: [{asn, as_name, prefix, country}...]}``
        """
        unique = sorted({ip for ip in ips if ip})
        if not unique:
            self._log("[asn] no IPs to enrich, skipping", "yellow")
            return {"hosts": [], "networks": []}

        hosts: list[dict] = []
        with ThreadPoolExecutor(max_workers=self.workers) as pool:
            for record in pool.map(self.lookup_ip, unique):
                if record:
                    hosts.append(record)

        networks: dict[str, dict] = {}
        for h in hosts:
            key = h.get("asn") or h.get("prefix") or h["ip"]
            if key not in networks:
                networks[key] = {
                    "asn": h.get("asn"), "as_name": h.get("as_name"),
                    "prefix": h.get("prefix"), "country": h.get("country"),
                }
        self._log(
            f"[asn] {len(hosts)} IP(s) across "
            f"{len(networks)} network(s)/ASN(s)", "green")
        return {"hosts": sorted(hosts, key=lambda h: h["ip"]),
                "networks": sorted(networks.values(),
                                   key=lambda n: n.get("asn") or "")}


if __name__ == "__main__":  # pragma: no cover - manual test entry point
    import sys, socket, json
    from rich.console import Console
    target = sys.argv[1] if len(sys.argv) > 1 else "example.com"
    ip = socket.gethostbyname(target)
    print(json.dumps(ASNLookup(console=Console()).lookup_ips([ip]), indent=2))
