"""DNS reconnaissance using dnspython.

Queries the standard record types and derives email-security posture
(SPF / DMARC presence) which feeds the report's security notes.
All lookups are ordinary public DNS queries.
"""

from __future__ import annotations

from typing import Optional

import dns.resolver
import dns.exception

RECORD_TYPES = ("A", "AAAA", "MX", "TXT", "NS", "CNAME", "SOA")


class DNSRecon:
    """Collect DNS records and email-security signals for ``domain``."""

    def __init__(self, domain: str, timeout: float = 5.0, console=None) -> None:
        """Create a DNS recon helper.

        Args:
            domain: Domain to query.
            timeout: Per-query timeout in seconds.
            console: Optional ``rich.console.Console`` for status output.
        """
        self.domain = domain.strip().lower().lstrip("*.")
        self.console = console
        self.resolver = dns.resolver.Resolver()
        self.resolver.timeout = timeout
        self.resolver.lifetime = timeout

    def _log(self, message: str, style: str = "cyan") -> None:
        if self.console is not None:
            self.console.print(message, style=style)

    def _query(self, name: str, rtype: str) -> list[str]:
        """Query one record type, returning text values (empty on any miss)."""
        try:
            answers = self.resolver.resolve(name, rtype)
            return [r.to_text().strip('"') if rtype == "TXT" else r.to_text()
                    for r in answers]
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer,
                dns.resolver.NoNameservers, dns.exception.Timeout,
                dns.exception.DNSException):
            return []

    def get_all_records(self) -> dict[str, list[str]]:
        """Return a dict keyed by record type with a list of values each."""
        records: dict[str, list[str]] = {}
        for rtype in RECORD_TYPES:
            values = self._query(self.domain, rtype)
            records[rtype] = values
            self._log(f"[dns] {rtype}: {len(values)} record(s)",
                      "green" if values else "yellow")
        return records

    # ------------------------------------------------------------------ #
    # email security posture
    # ------------------------------------------------------------------ #
    def get_spf(self, txt_records: list[str]) -> Optional[str]:
        """Return the SPF record string if present in ``txt_records``."""
        for txt in txt_records:
            if txt.lower().startswith("v=spf1"):
                return txt
        return None

    def get_dmarc(self) -> Optional[str]:
        """Return the DMARC record string from ``_dmarc.<domain>`` if present."""
        for txt in self._query(f"_dmarc.{self.domain}", "TXT"):
            if txt.lower().startswith("v=dmarc1"):
                return txt
        return None

    def analyze(self) -> dict:
        """Run a full DNS pass and return records plus email-security flags.

        Returns:
            ``{records: {...}, spf: str|None, dmarc: str|None,
               spf_missing: bool, dmarc_missing: bool}``
        """
        records = self.get_all_records()
        spf = self.get_spf(records.get("TXT", []))
        dmarc = self.get_dmarc()
        return {
            "records": records,
            "spf": spf,
            "dmarc": dmarc,
            "spf_missing": spf is None,
            "dmarc_missing": dmarc is None,
        }


if __name__ == "__main__":  # pragma: no cover - manual test entry point
    import sys
    import json
    from rich.console import Console

    target = sys.argv[1] if len(sys.argv) > 1 else "example.com"
    print(json.dumps(DNSRecon(target, console=Console()).analyze(), indent=2))
