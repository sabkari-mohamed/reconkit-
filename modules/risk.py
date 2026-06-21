"""Attack-surface risk scoring.

Turns the raw aggregated findings into a single weighted exposure score, a
letter grade, an itemised factor breakdown, and a plain-English executive
summary — the kind of headline a stakeholder reads first.

Score is additive risk points (higher = worse), capped at 100.
"""

from __future__ import annotations


def _grade(score: int) -> str:
    """Map a risk score (0 best .. 100 worst) to a letter grade."""
    if score < 10:
        return "A"
    if score < 25:
        return "B"
    if score < 45:
        return "C"
    if score < 70:
        return "D"
    return "F"


class RiskScorer:
    """Compute an exposure score + grade + summary from aggregated data."""

    def __init__(self, data: dict) -> None:
        """Create a scorer bound to the aggregated ``data`` object."""
        self.data = data

    def _factors(self) -> list[dict]:
        f: list[dict] = []
        dns = self.data.get("dns", {})
        if dns:
            if dns.get("spf_missing"):
                f.append({"name": "No SPF record", "points": 10,
                          "detail": "Domain can be spoofed in email."})
            if dns.get("dmarc_missing"):
                f.append({"name": "No DMARC record", "points": 10,
                          "detail": "No policy against email spoofing."})

        whois_data = self.data.get("whois", {})
        if whois_data.get("expiring_soon"):
            f.append({"name": "Domain expiring soon", "points": 15,
                      "detail": f"{whois_data.get('days_to_expiry')} day(s) "
                                "to expiry — renewal/takeover risk."})

        shodan = self.data.get("shodan", [])
        vuln_count = sum(len(h.get("vulns", [])) for h in shodan)
        if vuln_count:
            f.append({"name": "Shodan CVE tags",
                      "points": min(vuln_count * 8, 40),
                      "detail": f"{vuln_count} CVE tag(s) across exposed hosts."})
        open_ports = self.data.get("summary", {}).get("open_ports", 0)
        if open_ports > 3:
            f.append({"name": "Exposed services",
                      "points": min((open_ports - 3) * 2, 20),
                      "detail": f"{open_ports} open port(s) visible on Shodan."})

        interesting = len((self.data.get("urls", {}) or {}).get("interesting", []))
        if interesting:
            f.append({"name": "Sensitive archived endpoints",
                      "points": min(interesting, 15),
                      "detail": f"{interesting} archived URL(s) match admin/"
                                "api/config/backup patterns."})

        threat = self.data.get("threat", {})
        if threat.get("malicious"):
            f.append({"name": "Threat-intel reputation", "points": 20,
                      "detail": f"Appears in {threat.get('pulses')} OTX "
                                "threat pulse(s)."})

        subs = self.data.get("summary", {}).get("subdomains", 0)
        if subs > 50:
            f.append({"name": "Large attack surface", "points": 10,
                      "detail": f"{subs} subdomains discovered."})
        elif subs > 20:
            f.append({"name": "Broad attack surface", "points": 5,
                      "detail": f"{subs} subdomains discovered."})
        return f

    def score(self) -> dict:
        """Return ``{score, grade, factors, summary}``."""
        factors = self._factors()
        total = min(sum(item["points"] for item in factors), 100)
        grade = _grade(total)

        if not factors:
            summary = ("No notable passive-exposure signals detected. "
                       "Maintain current email-security and patch hygiene.")
        else:
            top = ", ".join(item["name"].lower()
                            for item in sorted(
                                factors, key=lambda x: -x["points"])[:3])
            summary = (f"Exposure grade {grade} (score {total}/100). "
                       f"Primary drivers: {top}. Review the security notes and "
                       "factor breakdown below.")
        return {"score": total, "grade": grade,
                "factors": factors, "summary": summary}
