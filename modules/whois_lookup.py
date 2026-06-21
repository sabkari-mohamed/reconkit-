"""WHOIS registration lookup using python-whois.

Returns a normalised dict and flags domains expiring within 30 days.
Handles privacy-redacted fields and the library's mixed return types
(single values vs lists) gracefully.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Optional


def _utcnow_naive() -> datetime:
    """Return current UTC time as a naive datetime (tz-free, no deprecation)."""
    return datetime.now(timezone.utc).replace(tzinfo=None)

import whois  # python-whois


def _first(value):
    """Collapse python-whois fields that may be a list into a single value."""
    if isinstance(value, (list, tuple)):
        return value[0] if value else None
    return value


def _as_date(value) -> Optional[datetime]:
    """Best-effort coercion of a whois date field to a naive ``datetime``."""
    value = _first(value)
    if isinstance(value, datetime):
        return value.replace(tzinfo=None)
    if isinstance(value, str):
        for fmt in ("%Y-%m-%dT%H:%M:%SZ", "%Y-%m-%d %H:%M:%S", "%Y-%m-%d"):
            try:
                return datetime.strptime(value.strip(), fmt)
            except ValueError:
                continue
    return None


def _iso(value) -> Optional[str]:
    dt = _as_date(value)
    return dt.isoformat() if dt else None


def _str_list(value) -> list[str]:
    """Normalise a field into a deduped, sorted list of strings."""
    if value is None:
        return []
    if isinstance(value, (list, tuple, set)):
        items = [str(v).strip() for v in value if v]
    else:
        items = [str(value).strip()]
    return sorted({i for i in items if i})


class WhoisLookup:
    """Fetch and normalise WHOIS registration data for ``domain``."""

    def __init__(self, domain: str, console=None) -> None:
        """Create a WHOIS lookup helper.

        Args:
            domain: Domain to query.
            console: Optional ``rich.console.Console`` for status output.
        """
        self.domain = domain.strip().lower().lstrip("*.")
        self.console = console

    def _log(self, message: str, style: str = "cyan") -> None:
        if self.console is not None:
            self.console.print(message, style=style)

    def lookup(self) -> dict:
        """Return a clean WHOIS dict, or ``{error: ...}`` on failure.

        Sets ``expiring_soon`` True when the domain expires within 30 days.
        """
        try:
            data = whois.whois(self.domain)
        except Exception as exc:  # python-whois raises broad exceptions
            self._log(f"[whois] lookup failed: {exc}", "yellow")
            return {"error": str(exc)}

        if not data or not data.get("domain_name"):
            self._log("[whois] no record found / fully redacted", "yellow")
            return {"error": "no WHOIS record returned"}

        expiry = _as_date(data.get("expiration_date"))
        expiring_soon = False
        days_to_expiry: Optional[int] = None
        if expiry:
            days_to_expiry = (expiry - _utcnow_naive()).days
            expiring_soon = 0 <= days_to_expiry <= 30

        result = {
            "domain_name": _first(data.get("domain_name")),
            "registrar": _first(data.get("registrar")),
            "creation_date": _iso(data.get("creation_date")),
            "expiration_date": _iso(data.get("expiration_date")),
            "updated_date": _iso(data.get("updated_date")),
            "name_servers": _str_list(data.get("name_servers")),
            "status": _str_list(data.get("status")),
            "registrant_org": _first(data.get("org"))
            or _first(data.get("registrant_organization")),
            "registrant_country": _first(data.get("country")),
            "emails": _str_list(data.get("emails")),
            "dnssec": _first(data.get("dnssec")),
            "days_to_expiry": days_to_expiry,
            "expiring_soon": expiring_soon,
        }
        self._log(
            f"[whois] registrar={result['registrar']} "
            f"expires={result['expiration_date']}",
            "green",
        )
        return result


if __name__ == "__main__":  # pragma: no cover - manual test entry point
    import sys
    import json
    from rich.console import Console

    target = sys.argv[1] if len(sys.argv) > 1 else "example.com"
    print(json.dumps(WhoisLookup(target, console=Console()).lookup(), indent=2))
