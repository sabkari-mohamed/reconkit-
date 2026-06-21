"""Offline unit tests for ReconKit (no live network calls).

Run from the project root:  python -m pytest -q
Network-touching code paths are exercised with mocked responses.
"""

from __future__ import annotations

import os
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest import mock

# make the package importable when run from project root
ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from modules.aggregator import Aggregator           # noqa: E402
from modules.asn import ASNLookup                   # noqa: E402
from modules.dns_recon import DNSRecon              # noqa: E402
from modules.emails import EmailHarvester           # noqa: E402
from modules.integrations import ExternalTools      # noqa: E402
from modules.reporter import Reporter               # noqa: E402
from modules.risk import RiskScorer                 # noqa: E402
from modules.subdomains import SubdomainEnumerator  # noqa: E402
from modules.threat_intel import ThreatIntel        # noqa: E402
from modules.urlscan import URLScanLookup           # noqa: E402
from modules.wayback import WaybackMachine          # noqa: E402
from modules.whois_lookup import WhoisLookup, _as_date, _str_list  # noqa: E402
import reconkit                                      # noqa: E402


# --------------------------------------------------------------------- #
# subdomains: name cleaning
# --------------------------------------------------------------------- #
def test_clean_accepts_subdomain_rejects_foreign():
    enum = SubdomainEnumerator("example.com")
    assert enum._clean("*.api.example.com") == "api.example.com"
    assert enum._clean("EXAMPLE.COM") == "example.com"
    assert enum._clean("evil.com") is None          # different apex
    assert enum._clean("user@example.com") is None  # email, not host
    assert enum._clean("   ") is None


def test_crtsh_parses_mocked_json():
    enum = SubdomainEnumerator("example.com")
    fake = mock.Mock(status_code=200)
    fake.json.return_value = [
        {"name_value": "a.example.com\n*.b.example.com"},
        {"name_value": "c.example.com", "common_name": "d.example.com"},
    ]
    fake.raise_for_status = mock.Mock()
    with mock.patch.object(enum._session, "get", return_value=fake):
        names = enum.from_crtsh()
    assert {"a.example.com", "b.example.com", "c.example.com"} <= names


# --------------------------------------------------------------------- #
# dns: spf / dmarc detection
# --------------------------------------------------------------------- #
def test_spf_detection():
    dns = DNSRecon("example.com")
    assert dns.get_spf(["v=spf1 include:_spf.google.com ~all"]) is not None
    assert dns.get_spf(["some other txt"]) is None


def test_dns_analyze_flags_missing(monkeypatch):
    dns = DNSRecon("example.com")
    monkeypatch.setattr(dns, "_query", lambda name, rtype: [])
    monkeypatch.setattr(dns, "get_dmarc", lambda: None)
    result = dns.analyze()
    assert result["spf_missing"] is True
    assert result["dmarc_missing"] is True


# --------------------------------------------------------------------- #
# whois: date coercion + expiry flag
# --------------------------------------------------------------------- #
def test_as_date_handles_list_and_string():
    assert _as_date(["2030-01-01", "2031-01-01"]).year == 2030
    assert _as_date("2025-06-15").month == 6
    assert _as_date(None) is None


def test_str_list_dedupes_and_sorts():
    assert _str_list(["B", "a", "a", None]) == ["B", "a"]
    assert _str_list("single") == ["single"]
    assert _str_list(None) == []


def test_whois_expiring_soon_flag():
    soon = datetime.now(timezone.utc).replace(tzinfo=None) + timedelta(days=10)
    fake = {"domain_name": "example.com", "registrar": "Test",
            "expiration_date": soon, "creation_date": None,
            "updated_date": None, "name_servers": [], "status": []}
    with mock.patch("modules.whois_lookup.whois.whois", return_value=fake):
        result = WhoisLookup("example.com").lookup()
    assert result["expiring_soon"] is True
    assert 0 <= result["days_to_expiry"] <= 30


# --------------------------------------------------------------------- #
# emails: graceful skip + parse
# --------------------------------------------------------------------- #
def test_emails_skip_without_key():
    assert EmailHarvester("example.com", None).harvest() == []


def test_emails_parse_mocked():
    harv = EmailHarvester("example.com", "fake-key")
    resp = mock.Mock(status_code=200)
    resp.json.return_value = {"data": {"emails": [
        {"value": "a@example.com", "first_name": "A", "last_name": "B",
         "position": "Eng", "confidence": 90}]}}
    with mock.patch("modules.emails.requests.get", return_value=resp):
        out = harv.harvest()
    assert out[0]["email"] == "a@example.com"
    assert out[0]["confidence"] == 90


def test_emails_handles_401():
    harv = EmailHarvester("example.com", "bad")
    resp = mock.Mock(status_code=401)
    with mock.patch("modules.emails.requests.get", return_value=resp):
        assert harv.harvest() == []


# --------------------------------------------------------------------- #
# aggregator: security notes + summary
# --------------------------------------------------------------------- #
def test_aggregator_derives_notes_and_summary():
    agg = Aggregator("example.com")
    agg.add_dns({"spf_missing": True, "dmarc_missing": True, "records": {}})
    agg.add_whois({"expiring_soon": True, "days_to_expiry": 5})
    agg.add_subdomains([
        {"subdomain": "a.example.com", "resolves": True, "ip": "1.2.3.4"},
        {"subdomain": "b.example.com", "resolves": False, "ip": None},
    ])
    agg.add_shodan([{"ip": "1.2.3.4", "ports": [80, 443],
                     "vulns": ["CVE-2021-1234"]}])
    data = agg.aggregate()
    notes = " ".join(data["security_notes"])
    assert "SPF" in notes and "DMARC" in notes
    assert "expires in 5" in notes
    assert "CVE-2021-1234" in notes
    assert data["summary"]["subdomains"] == 2
    assert data["summary"]["live_hosts"] == 1
    assert data["summary"]["open_ports"] == 2


def test_aggregator_dedupes_subdomains_and_emails():
    agg = Aggregator("example.com")
    agg.add_subdomains([
        {"subdomain": "a.example.com", "resolves": False, "ip": None},
        {"subdomain": "a.example.com", "resolves": True, "ip": "1.2.3.4"},
    ])
    agg.add_emails([{"email": "x@example.com"}, {"email": "X@example.com"}])
    data = agg.aggregate()
    assert len(data["subdomains"]) == 1
    assert data["subdomains"][0]["resolves"] is True  # live preferred
    assert len(data["emails"]) == 1


# --------------------------------------------------------------------- #
# reporter: json + html render
# --------------------------------------------------------------------- #
def _sample_data():
    agg = Aggregator("example.com")
    agg.add_whois({"registrar": "Test", "name_servers": ["ns1.x"],
                   "status": [], "expiring_soon": False})
    agg.add_dns({"records": {"A": ["1.2.3.4"], "TXT": []},
                 "spf": None, "dmarc": None,
                 "spf_missing": True, "dmarc_missing": True})
    agg.add_subdomains([{"subdomain": "a.example.com",
                         "resolves": True, "ip": "1.2.3.4"}])
    agg.add_emails([{"email": "a@example.com", "first_name": "A",
                     "last_name": "B", "position": "Eng", "confidence": 80}])
    agg.add_shodan([{"ip": "1.2.3.4", "org": "X", "country": "US",
                     "hostnames": [], "ports": [80], "vulns": [],
                     "services": [{"port": 80, "product": "nginx",
                                   "version": "1.0", "banner": ""}],
                     "last_update": "2025-01-01"}])
    return agg.aggregate()


def test_reporter_json_and_html(tmp_path):
    data = _sample_data()
    rep = Reporter(data)
    jpath = rep.export_json(str(tmp_path / "out.json"))
    hpath = rep.export_html(str(tmp_path / "out.html"))
    assert os.path.exists(jpath) and os.path.exists(hpath)
    html = Path(hpath).read_text(encoding="utf-8")
    assert "ReconKit OSINT Report" in html
    assert "example.com" in html
    assert "a.example.com" in html
    assert "missing" in html  # SPF/DMARC badge


def test_reporter_html_escapes_injection(tmp_path):
    """Autoescape must neutralise hostile strings from untrusted sources."""
    data = _sample_data()
    data["subdomains"].append(
        {"subdomain": "<script>alert(1)</script>", "resolves": False,
         "ip": None})
    rep = Reporter(data)
    hpath = rep.export_html(str(tmp_path / "x.html"))
    html = Path(hpath).read_text(encoding="utf-8")
    assert "<script>alert(1)</script>" not in html
    assert "&lt;script&gt;" in html


# --------------------------------------------------------------------- #
# CLI config: env var precedence + module parsing
# --------------------------------------------------------------------- #
def test_load_keys_env_overrides_file(tmp_path, monkeypatch):
    cfg = tmp_path / "config.ini"
    cfg.write_text("[hunter]\napi_key = file-key\n[shodan]\napi_key = \n")
    monkeypatch.setenv("HUNTER_API_KEY", "env-key")
    monkeypatch.delenv("SHODAN_API_KEY", raising=False)
    keys = reconkit.load_keys(str(cfg))
    assert keys["hunter"] == "env-key"   # env wins
    assert keys["shodan"] is None        # empty -> None


# --------------------------------------------------------------------- #
# asn: Team Cymru parsing
# --------------------------------------------------------------------- #
def test_asn_lookup_parses_cymru(monkeypatch):
    asn = ASNLookup()
    replies = {
        "4.3.2.1.origin.asn.cymru.com": "13335 | 1.2.3.0/24 | US | arin | 2014",
        "AS13335.asn.cymru.com": "13335 | US | arin | 2010 | CLOUDFLARENET, US",
    }
    monkeypatch.setattr(asn, "_txt", lambda name: replies.get(name))
    rec = asn.lookup_ip("1.2.3.4")
    assert rec["asn"] == "AS13335"
    assert rec["prefix"] == "1.2.3.0/24"
    assert "CLOUDFLARENET" in rec["as_name"]


def test_asn_lookup_ips_groups_networks(monkeypatch):
    asn = ASNLookup(workers=2)
    monkeypatch.setattr(asn, "lookup_ip", lambda ip: {
        "ip": ip, "asn": "AS1", "prefix": "1.0.0.0/8",
        "country": "US", "as_name": "ONE"})
    out = asn.lookup_ips(["1.1.1.1", "1.2.3.4"])
    assert len(out["hosts"]) == 2
    assert len(out["networks"]) == 1   # same ASN collapsed


# --------------------------------------------------------------------- #
# urlscan / wayback / threat: mocked parsing
# --------------------------------------------------------------------- #
def test_urlscan_parses_results():
    u = URLScanLookup("example.com")
    resp = mock.Mock(status_code=200)
    resp.json.return_value = {"results": [
        {"page": {"url": "https://a.example.com/", "ip": "1.2.3.4",
                  "server": "nginx", "domain": "a.example.com"},
         "task": {"time": "2025"}, "result": "https://urlscan.io/x"}]}
    with mock.patch("modules.urlscan.requests.get", return_value=resp):
        out = u.search()
    assert out["results"][0]["server"] == "nginx"
    assert "a.example.com" in out["subdomains"]
    assert "1.2.3.4" in out["ips"]


def test_wayback_flags_interesting():
    w = WaybackMachine("example.com")
    resp = mock.Mock()
    resp.raise_for_status = mock.Mock()
    resp.json.return_value = [
        ["original", "timestamp", "statuscode", "mimetype"],
        ["http://admin.example.com/login", "2020", "200", "text/html"],
        ["http://example.com/style.css", "2020", "200", "text/css"],
    ]
    with mock.patch("modules.wayback.requests.get", return_value=resp):
        out = w.fetch()
    assert out["count"] == 2
    matches = {i["match"] for i in out["interesting"]}
    assert "admin" in matches or "login" in matches
    assert "admin.example.com" in out["subdomains"]


def test_threat_intel_parses(monkeypatch):
    t = ThreatIntel("example.com")
    monkeypatch.setattr(t, "_get", lambda section: {
        "general": {"pulse_info": {"count": 3}},
        "passive_dns": {"passive_dns": [
            {"hostname": "x.example.com", "address": "9.9.9.9",
             "record_type": "A", "last": "2025"}]},
    }[section])
    out = t.analyze()
    assert out["pulses"] == 3 and out["malicious"] is True
    assert "9.9.9.9" in out["ips"]
    assert "x.example.com" in out["subdomains"]


# --------------------------------------------------------------------- #
# external tool orchestration (mocked subprocess)
# --------------------------------------------------------------------- #
def test_integrations_skip_when_absent(monkeypatch):
    monkeypatch.setattr("modules.integrations.shutil.which", lambda n: None)
    out = ExternalTools("example.com").enrich()
    assert out["used"] == [] and out["subdomains"] == []
    assert out["available"] == {"subfinder": False, "amass": False, "gau": False}


def test_integrations_parses_subfinder(monkeypatch):
    monkeypatch.setattr("modules.integrations.shutil.which",
                        lambda n: "/usr/bin/" + n if n == "subfinder" else None)
    monkeypatch.setattr("modules.integrations.subprocess.run",
                        lambda *a, **k: mock.Mock(
                            stdout="a.example.com\nb.example.com\nevil.com\n"))
    out = ExternalTools("example.com").enrich()
    assert "a.example.com" in out["subdomains"]
    assert "evil.com" not in out["subdomains"]      # out of scope dropped
    assert out["counts"]["subfinder"] == 2
    assert out["used"] == ["subfinder"]


def test_integrations_parses_gau_urls(monkeypatch):
    monkeypatch.setattr("modules.integrations.shutil.which",
                        lambda n: "/usr/bin/gau" if n == "gau" else None)
    monkeypatch.setattr("modules.integrations.subprocess.run",
                        lambda *a, **k: mock.Mock(
                            stdout="https://api.example.com/v1\nhttps://example.com/x\n"))
    out = ExternalTools("example.com").enrich()
    assert "https://api.example.com/v1" in out["urls"]
    assert "api.example.com" in out["subdomains"]    # host extracted from URL


def test_aggregator_add_tools(monkeypatch):
    agg = Aggregator("example.com")
    agg.add_tools({"available": {"subfinder": True, "amass": False, "gau": False},
                   "used": ["subfinder"], "subdomains": ["x.example.com"],
                   "urls": ["http://example.com/a"], "counts": {"subfinder": 1}})
    data = agg.aggregate()
    assert data["tools"]["used"] == ["subfinder"]
    assert any(s["subdomain"] == "x.example.com" for s in data["subdomains"])
    assert data["summary"]["tools_used"] == 1
    assert data["urls"]["count"] == 1


# --------------------------------------------------------------------- #
# risk scoring
# --------------------------------------------------------------------- #
def test_risk_scorer_grades_exposure():
    data = {
        "dns": {"spf_missing": True, "dmarc_missing": True},
        "whois": {"expiring_soon": True, "days_to_expiry": 5},
        "shodan": [{"vulns": ["CVE-1", "CVE-2"]}],
        "urls": {"interesting": [{"url": "x", "match": "admin"}]},
        "threat": {"malicious": True, "pulses": 4},
        "summary": {"open_ports": 10, "subdomains": 60},
    }
    out = RiskScorer(data).score()
    assert out["score"] > 0
    assert out["grade"] in {"A", "B", "C", "D", "F"}
    names = {f["name"] for f in out["factors"]}
    assert "No SPF record" in names and "Threat-intel reputation" in names


def test_risk_scorer_clean_domain():
    out = RiskScorer({"dns": {"spf_missing": False, "dmarc_missing": False},
                      "summary": {}}).score()
    assert out["score"] == 0 and out["grade"] == "A"
    assert out["factors"] == []


# --------------------------------------------------------------------- #
# aggregator: multi-source merge + new sections
# --------------------------------------------------------------------- #
def test_aggregator_merges_multisource_and_urls():
    agg = Aggregator("example.com")
    agg.add_subdomains([{"subdomain": "a.example.com",
                         "resolves": False, "ip": None}])
    agg.merge_subdomain_names(["a.example.com", "b.example.com"])
    agg.add_urls(
        wayback={"urls": ["http://example.com/x"], "count": 1,
                 "interesting": [{"url": "http://example.com/admin",
                                  "match": "admin"}],
                 "subdomains": ["c.example.com"]},
        urlscan={"results": [{"url": "http://example.com/y"}],
                 "subdomains": ["d.example.com"], "ips": ["1.1.1.1"]})
    agg.add_asn({"hosts": [], "networks": [{"asn": "AS1", "as_name": "X"}]})
    data = agg.aggregate()
    names = {s["subdomain"] for s in data["subdomains"]}
    assert {"a.example.com", "b.example.com",
            "c.example.com", "d.example.com"} <= names
    assert data["summary"]["archived_urls"] == 2
    assert data["summary"]["interesting_urls"] == 1
    assert data["summary"]["asn_count"] == 1
    assert any("sensitive patterns" in n for n in data["security_notes"])


def test_markdown_and_csv_export(tmp_path):
    data = _sample_data()
    rep = Reporter(data)
    md = rep.export_markdown(str(tmp_path / "r.md"))
    csvp = rep.export_csv(str(tmp_path / "s.csv"))
    md_text = Path(md).read_text(encoding="utf-8")
    assert "# ReconKit OSINT Report" in md_text
    assert "Exposure: Grade" in md_text
    csv_text = Path(csvp).read_text(encoding="utf-8")
    assert "subdomain,resolves,ip" in csv_text
    assert "a.example.com" in csv_text


def test_meta_branding():
    import meta
    assert meta.__author__ == "Mohamed Sabkari"
    assert meta.version_string().startswith("reconkit ")
    assert "Mohamed Sabkari" in meta.version_string()
    block = meta.meta_dict()
    assert block["tool"] == "ReconKit" and block["author"] == "Mohamed Sabkari"


def test_html_report_embeds_author(tmp_path):
    import meta
    data = _sample_data()
    data["meta"] = meta.meta_dict()
    hpath = Reporter(data).export_html(str(tmp_path / "branded.html"))
    html = Path(hpath).read_text(encoding="utf-8")
    assert "Mohamed Sabkari" in html
    assert f"ReconKit v{meta.__version__}" in html


def test_parse_modules_all_and_invalid():
    assert reconkit.parse_modules("all") == list(reconkit.VALID_MODULES)
    assert reconkit.parse_modules("dns,whois") == ["dns", "whois"]
    with mock.patch.object(reconkit.sys, "exit") as ex:
        reconkit.parse_modules("bogus")
        ex.assert_called_once_with(2)


# --------------------------------------------------------------------- #
# web dashboard (no network)
# --------------------------------------------------------------------- #
def test_web_domain_validation():
    from web.app import _valid_domain
    assert _valid_domain("example.com")
    assert _valid_domain("a.b.example.co.uk")
    assert not _valid_domain("not a domain")
    assert not _valid_domain("")
    assert not _valid_domain("http://example.com")


def test_web_health_and_index():
    from web.app import app
    client = app.test_client()
    h = client.get("/api/health")
    assert h.status_code == 200 and h.get_json()["status"] == "ok"
    page = client.get("/")
    assert page.status_code == 200
    assert b"ReconKit" in page.data and b"Mohamed Sabkari" in page.data


def test_web_scan_rejects_bad_domain():
    from web.app import app
    client = app.test_client()
    assert client.get("/api/scan?domain=bogus").status_code == 400
