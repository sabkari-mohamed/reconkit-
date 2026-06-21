#!/usr/bin/env python3
"""ReconKit — Passive OSINT Reconnaissance Toolkit (CLI entry point).

For AUTHORIZED reconnaissance, bug bounty (in-scope targets only), and
educational use. All data sources are passive and public — no active
scanning or exploitation is performed against the target.
"""

from __future__ import annotations

import argparse
import configparser
import os
import sys
import time
from pathlib import Path

from rich.console import Console
from rich.panel import Panel

import meta

# Ensure Unicode (✓, ⚠, box-drawing) prints on legacy Windows consoles
# (cp1252) instead of raising UnicodeEncodeError.
for _stream in (sys.stdout, sys.stderr):
    try:
        _stream.reconfigure(encoding="utf-8", errors="replace")  # type: ignore[attr-defined]
    except (AttributeError, ValueError):
        pass

from modules.aggregator import Aggregator
from modules.asn import ASNLookup
from modules.dns_recon import DNSRecon
from modules.emails import EmailHarvester
from modules.integrations import ExternalTools
from modules.reporter import Reporter
from modules.shodan_lookup import ShodanLookup
from modules.subdomains import SubdomainEnumerator
from modules.threat_intel import ThreatIntel
from modules.urlscan import URLScanLookup
from modules.wayback import WaybackMachine
from modules.whois_lookup import WhoisLookup

VALID_MODULES = ("subdomains", "tools", "dns", "whois", "emails", "shodan",
                 "wayback", "asn", "urlscan", "threat")
console = Console()


# ---------------------------------------------------------------------- #
# configuration / API keys
# ---------------------------------------------------------------------- #
def load_keys(config_path: str) -> dict[str, str | None]:
    """Load API keys, with environment variables taking precedence.

    Args:
        config_path: Path to an ``ini`` file with ``[hunter]`` / ``[shodan]``
            sections each holding an ``api_key`` value.

    Returns:
        ``{"hunter": str|None, "shodan": str|None}``.
    """
    cfg = configparser.ConfigParser()
    if os.path.exists(config_path):
        try:
            cfg.read(config_path)
        except configparser.Error as exc:
            console.print(f"[yellow]Could not parse config: {exc}[/yellow]")

    def pick(env_name: str, section: str) -> str | None:
        env_val = os.environ.get(env_name)
        if env_val and env_val.strip():
            return env_val.strip()
        file_val = cfg.get(section, "api_key", fallback="").strip()
        return file_val or None

    return {
        "hunter": pick("HUNTER_API_KEY", "hunter"),
        "shodan": pick("SHODAN_API_KEY", "shodan"),
        "urlscan": pick("URLSCAN_API_KEY", "urlscan"),
    }


# ---------------------------------------------------------------------- #
# banner
# ---------------------------------------------------------------------- #
def print_banner() -> None:
    """Print the branded tool banner and the authorized-use notice."""
    console.print(
        Panel.fit(meta.banner_text(), border_style="green", padding=(0, 2))
    )


def parse_modules(value: str) -> list[str]:
    """Parse the ``--modules`` comma list into a validated module list."""
    if value.strip().lower() == "all":
        return list(VALID_MODULES)
    requested = [m.strip().lower() for m in value.split(",") if m.strip()]
    invalid = [m for m in requested if m not in VALID_MODULES]
    if invalid:
        console.print(
            f"[red]Unknown module(s): {', '.join(invalid)}. "
            f"Valid: {', '.join(VALID_MODULES)}, all[/red]"
        )
        sys.exit(2)
    return requested


# ---------------------------------------------------------------------- #
# main
# ---------------------------------------------------------------------- #
def build_parser() -> argparse.ArgumentParser:
    """Construct the argparse CLI parser."""
    parser = argparse.ArgumentParser(
        prog="reconkit",
        description="Passive OSINT reconnaissance aggregator for a domain.",
        epilog="Authorized / in-scope targets only.",
    )
    parser.add_argument(
        "--version", action="version", version=meta.version_string())
    parser.add_argument("domain", help="target domain, e.g. example.com")
    parser.add_argument(
        "--modules", default="all",
        help="comma list: subdomains,dns,whois,emails,shodan,all "
             "(default: all)",
    )
    parser.add_argument(
        "--output-dir", default="./output", help="output directory")
    parser.add_argument(
        "--report", default="all",
        help="terminal,json,html,markdown,csv,all (default: all)")
    parser.add_argument(
        "--config", default="config/config.ini",
        help="path to config.ini (default: config/config.ini)")
    parser.add_argument(
        "--check-tools", action="store_true",
        help="list detected external tools (subfinder/amass/gau) and exit")
    parser.add_argument(
        "--resolve", dest="resolve", action="store_true", default=True,
        help="resolve subdomains live (default on)")
    parser.add_argument(
        "--no-resolve", dest="resolve", action="store_false",
        help="skip live subdomain resolution")
    return parser


def _seed_apex_ip(domain: str, ips: set[str]) -> None:
    """Add the apex domain's resolved IP to ``ips`` (best effort)."""
    import socket
    try:
        ips.add(socket.gethostbyname(domain))
    except (socket.gaierror, OSError):
        pass


def run(args: argparse.Namespace) -> dict:
    """Execute the selected modules and return the aggregated data object."""
    domain = args.domain.strip().lower().lstrip("*.")
    modules = parse_modules(args.modules)
    keys = load_keys(args.config)

    agg = Aggregator(domain)
    ips: set[str] = set()          # IPs gathered for ASN / Shodan enrichment
    wayback_data: dict = {}
    urlscan_data: dict = {}

    if "whois" in modules:
        console.rule("[bold]WHOIS")
        agg.add_whois(WhoisLookup(domain, console=console).lookup())

    if "dns" in modules:
        console.rule("[bold]DNS")
        agg.add_dns(DNSRecon(domain, console=console).analyze())

    if "subdomains" in modules:
        console.rule("[bold]Subdomains")
        subs = SubdomainEnumerator(domain, console=console).enumerate(
            resolve=args.resolve)
        agg.add_subdomains(subs)
        ips.update(s["ip"] for s in subs if s.get("ip"))

    if "tools" in modules:
        console.rule("[bold]External Tools")
        agg.add_tools(ExternalTools(domain, console=console).enrich())

    if "urlscan" in modules:
        console.rule("[bold]urlscan.io")
        urlscan_data = URLScanLookup(
            domain, keys["urlscan"], console=console).search()
        ips.update(urlscan_data.get("ips", []))

    if "wayback" in modules:
        console.rule("[bold]Wayback Machine")
        wayback_data = WaybackMachine(domain, console=console).fetch()

    if "urlscan" in modules or "wayback" in modules:
        agg.add_urls(wayback=wayback_data, urlscan=urlscan_data)

    if "threat" in modules:
        console.rule("[bold]Threat Intel")
        threat = ThreatIntel(domain, console=console).analyze()
        agg.add_threat(threat)
        ips.update(threat.get("ips", []))

    if "emails" in modules:
        console.rule("[bold]Emails")
        agg.add_emails(
            EmailHarvester(domain, keys["hunter"], console=console).harvest())

    if "asn" in modules:
        console.rule("[bold]ASN / Netblocks")
        if not ips:
            _seed_apex_ip(domain, ips)
        agg.add_asn(ASNLookup(console=console).lookup_ips(ips))

    if "shodan" in modules:
        console.rule("[bold]Shodan")
        agg.add_shodan(
            ShodanLookup(keys["shodan"], console=console)
            .resolve_and_lookup(domain, sorted(ips)))

    return agg.aggregate()


def main(argv: list[str] | None = None) -> int:
    """CLI main: parse args, run modules, emit reports."""
    args = build_parser().parse_args(argv)
    print_banner()

    if args.check_tools:
        from modules.integrations import TOOLS
        status = ExternalTools(args.domain).available()
        console.print("[bold]External tool integrations[/bold]")
        for name, path in status.items():
            if path:
                console.print(f"  [green]✓[/green] {name}  [dim]{path}[/dim]")
            else:
                console.print(f"  [yellow]✗[/yellow] {name}  [dim]install: "
                              f"{TOOLS[name].install}[/dim]")
        return 0

    started = time.perf_counter()
    data = run(args)
    data["meta"] = meta.meta_dict()
    data["elapsed_seconds"] = round(time.perf_counter() - started, 2)

    reports = (["terminal", "json", "html", "markdown"]
               if args.report.strip().lower() == "all"
               else [r.strip().lower() for r in args.report.split(",")])

    reporter = Reporter(data, console=console)
    output_dir = Path(args.output_dir)
    safe = data["target"].replace("/", "_")

    if "terminal" in reports:
        reporter.print_terminal_summary()
    if "json" in reports:
        reporter.export_json(str(output_dir / f"{safe}_recon.json"))
    if "html" in reports:
        try:
            reporter.export_html(str(output_dir / f"{safe}_recon.html"))
        except Exception as exc:  # template/render safety
            console.print(f"[red]HTML report failed: {exc}[/red]")
    if "markdown" in reports or "md" in reports:
        reporter.export_markdown(str(output_dir / f"{safe}_recon.md"))
    if "csv" in reports:
        reporter.export_csv(str(output_dir / f"{safe}_subdomains.csv"))

    console.print(
        Panel.fit(
            f"[bold green]✓ Recon complete[/bold green] "
            f"[dim]in {data['elapsed_seconds']}s[/dim]\n"
            f"Reports: [cyan]{output_dir.resolve()}[/cyan]\n"
            f"[dim]ReconKit v{meta.__version__} · by {meta.__author__}[/dim]",
            border_style="green",
        )
    )
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        console.print("\n[yellow]Interrupted by user.[/yellow]")
        sys.exit(130)
