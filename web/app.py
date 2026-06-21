"""ReconKit web dashboard — Flask backend with live (SSE) scan streaming.

Run:
    python web/app.py            # then open http://127.0.0.1:5000
    python web/app.py --port 8000 --host 0.0.0.0

The dashboard reuses the same passive OSINT modules as the CLI. Each module's
progress is streamed to the browser over Server-Sent Events so the user sees
the scan build up live, then the aggregated result + risk grade render.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

# Make the project modules importable when run as `python web/app.py`.
ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from flask import Flask, Response, jsonify, render_template, request  # noqa: E402

import meta  # noqa: E402
from reconkit import load_keys  # noqa: E402
from modules.aggregator import Aggregator  # noqa: E402
from modules.asn import ASNLookup  # noqa: E402
from modules.dns_recon import DNSRecon  # noqa: E402
from modules.emails import EmailHarvester  # noqa: E402
from modules.integrations import ExternalTools  # noqa: E402
from modules.shodan_lookup import ShodanLookup  # noqa: E402
from modules.subdomains import SubdomainEnumerator  # noqa: E402
from modules.threat_intel import ThreatIntel  # noqa: E402
from modules.urlscan import URLScanLookup  # noqa: E402
from modules.wayback import WaybackMachine  # noqa: E402
from modules.whois_lookup import WhoisLookup  # noqa: E402

VALID_MODULES = ("subdomains", "tools", "dns", "whois", "urlscan", "wayback",
                 "asn", "threat", "emails", "shodan")
DEFAULT_MODULES = ("subdomains", "dns", "whois", "asn", "urlscan", "threat")
DOMAIN_RE = re.compile(
    r"^(?=.{1,253}$)([a-z0-9](-?[a-z0-9])*\.)+[a-z]{2,}$", re.IGNORECASE)

app = Flask(__name__)


def _valid_domain(domain: str) -> bool:
    return bool(DOMAIN_RE.match(domain or ""))


def _sse(event: str, payload: dict) -> str:
    """Format a single Server-Sent Event frame."""
    return f"event: {event}\ndata: {json.dumps(payload, default=str)}\n\n"


def stream_scan(domain: str, modules: list[str], resolve: bool):
    """Generator yielding SSE frames as each module completes."""
    keys = load_keys(str(ROOT / "config" / "config.ini"))
    agg = Aggregator(domain)
    ips: set[str] = set()
    wayback_data: dict = {}
    urlscan_data: dict = {}

    ordered = [m for m in VALID_MODULES if m in modules]
    yield _sse("start", {"domain": domain, "modules": ordered})

    for name in ordered:
        yield _sse("module", {"name": name, "status": "running"})
        info: dict = {}
        try:
            if name == "whois":
                agg.add_whois(WhoisLookup(domain).lookup())
            elif name == "dns":
                d = DNSRecon(domain).analyze()
                agg.add_dns(d)
                info = {"spf": bool(d.get("spf")), "dmarc": bool(d.get("dmarc"))}
            elif name == "subdomains":
                subs = SubdomainEnumerator(domain).enumerate(resolve=resolve)
                agg.add_subdomains(subs)
                ips.update(s["ip"] for s in subs if s.get("ip"))
                info = {"found": len(subs)}
            elif name == "tools":
                tl = ExternalTools(domain).enrich()
                agg.add_tools(tl)
                info = {"used": len(tl.get("used", [])),
                        "installed": sum(1 for v in tl.get("available", {}).values() if v)}
            elif name == "urlscan":
                urlscan_data = URLScanLookup(domain, keys["urlscan"]).search()
                ips.update(urlscan_data.get("ips", []))
                info = {"results": len(urlscan_data.get("results", []))}
            elif name == "wayback":
                wayback_data = WaybackMachine(domain).fetch()
                info = {"urls": wayback_data.get("count", 0)}
            elif name == "threat":
                t = ThreatIntel(domain).analyze()
                agg.add_threat(t)
                ips.update(t.get("ips", []))
                info = {"pulses": t.get("pulses", 0)}
            elif name == "emails":
                emails = EmailHarvester(domain, keys["hunter"]).harvest()
                agg.add_emails(emails)
                info = {"found": len(emails), "key": bool(keys["hunter"])}
            elif name == "asn":
                if not ips:
                    import socket
                    try:
                        ips.add(socket.gethostbyname(domain))
                    except OSError:
                        pass
                a = ASNLookup().lookup_ips(ips)
                agg.add_asn(a)
                info = {"networks": len(a.get("networks", []))}
            elif name == "shodan":
                s = ShodanLookup(keys["shodan"]).resolve_and_lookup(
                    domain, sorted(ips))
                agg.add_shodan(s)
                info = {"hosts": len(s), "key": bool(keys["shodan"])}
            yield _sse("module", {"name": name, "status": "done", "info": info})
        except Exception as exc:  # never let one module break the stream
            yield _sse("module",
                       {"name": name, "status": "error", "error": str(exc)})

    # merge URL findings once both sources are in
    if "urlscan" in modules or "wayback" in modules:
        agg.add_urls(wayback=wayback_data, urlscan=urlscan_data)

    data = agg.aggregate()
    data["meta"] = meta.meta_dict()
    yield _sse("result", data)
    yield _sse("done", {"ok": True})


@app.route("/")
def index() -> str:
    """Serve the dashboard shell."""
    return render_template("index.html", meta=meta.meta_dict())


@app.route("/api/scan")
def api_scan() -> Response:
    """Stream a passive recon scan as Server-Sent Events."""
    domain = (request.args.get("domain") or "").strip().lower().lstrip("*.")
    if not _valid_domain(domain):
        return jsonify({"error": "invalid domain"}), 400

    requested = [m.strip().lower()
                 for m in (request.args.get("modules") or "").split(",")
                 if m.strip()]
    modules = [m for m in requested if m in VALID_MODULES] or list(DEFAULT_MODULES)
    resolve = request.args.get("resolve", "1") != "0"

    return Response(stream_scan(domain, modules, resolve),
                    mimetype="text/event-stream",
                    headers={"Cache-Control": "no-cache",
                             "X-Accel-Buffering": "no"})


@app.route("/api/health")
def health() -> Response:
    """Liveness probe + version."""
    return jsonify({"status": "ok", "version": meta.__version__})


def main() -> None:
    """CLI launcher for the dashboard."""
    parser = argparse.ArgumentParser(description="ReconKit web dashboard")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=5000)
    parser.add_argument("--debug", action="store_true")
    args = parser.parse_args()
    print(f"ReconKit dashboard v{meta.__version__} → "
          f"http://{args.host}:{args.port}")
    app.run(host=args.host, port=args.port, debug=args.debug, threaded=True)


if __name__ == "__main__":
    main()
