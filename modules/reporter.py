"""Reporting: rich terminal summary, JSON / HTML / Markdown / CSV exports."""

from __future__ import annotations

import csv
import json
import os
from pathlib import Path

from jinja2 import Environment, FileSystemLoader, select_autoescape
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

TEMPLATE_DIR = Path(__file__).resolve().parent.parent / "templates"

# Risk grade -> rich colour.
GRADE_STYLE = {"A": "bold green", "B": "green", "C": "yellow",
               "D": "orange3", "F": "bold red"}


class Reporter:
    """Render aggregated recon data to terminal, JSON, and HTML."""

    def __init__(self, data: dict, console: Console | None = None) -> None:
        """Create a reporter.

        Args:
            data: The aggregated data object from :class:`Aggregator`.
            console: Optional shared ``rich.console.Console``.
        """
        self.data = data
        self.console = console or Console()

    # ------------------------------------------------------------------ #
    # terminal
    # ------------------------------------------------------------------ #
    def print_terminal_summary(self) -> None:
        """Print a banner, summary table, and security notes to the terminal."""
        summary = self.data.get("summary", {})
        meta = self.data.get("meta", {})
        credit = (f"[dim]ReconKit v{meta.get('version', '')} · "
                  f"by {meta.get('author', '')}[/dim]\n") if meta else ""
        self.console.print(
            Panel.fit(
                f"[bold]ReconKit OSINT Report[/bold]\n"
                f"{credit}"
                f"target: [cyan]{self.data.get('target')}[/cyan]\n"
                f"scan:   {self.data.get('scan_date')}",
                border_style="green",
            )
        )

        # Risk headline.
        risk = self.data.get("risk", {})
        if risk:
            grade = risk.get("grade", "?")
            style = GRADE_STYLE.get(grade, "white")
            self.console.print(
                Panel.fit(
                    f"[{style}]Exposure grade {grade}[/{style}]  "
                    f"[dim]·[/dim]  score {risk.get('score', 0)}/100\n"
                    f"[dim]{risk.get('summary', '')}[/dim]",
                    title="Risk", border_style=style,
                )
            )

        table = Table(title="Summary", show_header=True,
                      header_style="bold magenta")
        table.add_column("Metric")
        table.add_column("Count", justify="right")
        table.add_row("Subdomains", str(summary.get("subdomains", 0)))
        table.add_row("Live hosts", str(summary.get("live_hosts", 0)))
        table.add_row("Emails", str(summary.get("emails", 0)))
        table.add_row("ASNs / networks", str(summary.get("asn_count", 0)))
        table.add_row("Archived URLs", str(summary.get("archived_urls", 0)))
        table.add_row("Sensitive URLs", str(summary.get("interesting_urls", 0)))
        table.add_row("Shodan hosts", str(summary.get("shodan_hosts", 0)))
        table.add_row("Open ports", str(summary.get("open_ports", 0)))
        table.add_row("Threat pulses", str(summary.get("threat_pulses", 0)))
        tools = self.data.get("tools", {})
        if tools.get("available"):
            avail = sum(1 for v in tools["available"].values() if v)
            table.add_row("External tools",
                          f"{len(tools.get('used', []))} used / "
                          f"{avail} installed")
        self.console.print(table)

        notes = self.data.get("security_notes", [])
        if notes:
            note_table = Table(title="Security Notes", show_header=False,
                               border_style="yellow")
            note_table.add_column("note")
            for note in notes:
                note_table.add_row(f"[yellow]⚠[/yellow]  {note}")
            self.console.print(note_table)
        else:
            self.console.print("[green]No security notes flagged.[/green]")

    # ------------------------------------------------------------------ #
    # JSON
    # ------------------------------------------------------------------ #
    def export_json(self, path: str) -> str:
        """Write the full data object as pretty JSON to ``path``."""
        os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(self.data, fh, indent=2, ensure_ascii=False, default=str)
        self.console.print(f"[green][✓][/green] JSON written: {path}")
        return path

    # ------------------------------------------------------------------ #
    # HTML
    # ------------------------------------------------------------------ #
    def export_html(self, path: str,
                    template_name: str = "report.html") -> str:
        """Render the HTML report via Jinja2 to ``path``."""
        os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
        env = Environment(
            loader=FileSystemLoader(str(TEMPLATE_DIR)),
            autoescape=select_autoescape(["html", "xml"]),
        )
        template = env.get_template(template_name)
        html = template.render(**self.data)
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(html)
        self.console.print(f"[green][✓][/green] HTML written: {path}")
        return path

    # ------------------------------------------------------------------ #
    # Markdown
    # ------------------------------------------------------------------ #
    def export_markdown(self, path: str) -> str:
        """Write a GitHub-flavoured Markdown report to ``path``."""
        d = self.data
        risk = d.get("risk", {})
        summary = d.get("summary", {})
        meta = d.get("meta", {})
        lines: list[str] = [
            f"# ReconKit OSINT Report — {d.get('target')}",
            "",
            f"_Scan: {d.get('scan_date')}_"
            + (f" · by {meta.get('author')}" if meta else ""),
            "",
            f"## Exposure: Grade {risk.get('grade', '?')} "
            f"({risk.get('score', 0)}/100)",
            "",
            f"> {risk.get('summary', '')}",
            "",
            "## Summary",
            "",
            "| Metric | Count |",
            "|---|---|",
        ]
        for label, key in (("Subdomains", "subdomains"),
                           ("Live hosts", "live_hosts"),
                           ("Emails", "emails"),
                           ("ASNs / networks", "asn_count"),
                           ("Archived URLs", "archived_urls"),
                           ("Sensitive URLs", "interesting_urls"),
                           ("Shodan hosts", "shodan_hosts"),
                           ("Open ports", "open_ports"),
                           ("Threat pulses", "threat_pulses")):
            lines.append(f"| {label} | {summary.get(key, 0)} |")

        notes = d.get("security_notes", [])
        lines += ["", "## Security Notes", ""]
        lines += [f"- ⚠ {n}" for n in notes] or ["- None flagged."]

        if risk.get("factors"):
            lines += ["", "## Risk Factors", "",
                      "| Factor | Points | Detail |", "|---|---|---|"]
            for f in risk["factors"]:
                lines.append(
                    f"| {f['name']} | {f['points']} | {f['detail']} |")

        subs = d.get("subdomains", [])
        if subs:
            lines += ["", f"## Subdomains ({len(subs)})", "",
                      "| Subdomain | Resolves | IP |", "|---|---|---|"]
            for s in subs:
                state = ("live" if s.get("resolves")
                         else "—" if s.get("resolves") is None else "historical")
                lines.append(
                    f"| {s['subdomain']} | {state} | {s.get('ip') or '—'} |")

        networks = (d.get("asn", {}) or {}).get("networks", [])
        if networks:
            lines += ["", "## Networks / ASN", "",
                      "| ASN | Organisation | Prefix | Country |",
                      "|---|---|---|---|"]
            for n in networks:
                lines.append(
                    f"| {n.get('asn') or '—'} | {n.get('as_name') or '—'} "
                    f"| {n.get('prefix') or '—'} | {n.get('country') or '—'} |")

        interesting = (d.get("urls", {}) or {}).get("interesting", [])
        if interesting:
            lines += ["", f"## Sensitive Archived URLs ({len(interesting)})", ""]
            lines += [f"- `{i['match']}` — {i['url']}"
                      for i in interesting[:50]]

        lines += ["", "---",
                  f"_Generated by ReconKit v{meta.get('version', '')} — "
                  "for authorized OSINT only._", ""]

        os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
        with open(path, "w", encoding="utf-8") as fh:
            fh.write("\n".join(lines))
        self.console.print(f"[green][✓][/green] Markdown written: {path}")
        return path

    # ------------------------------------------------------------------ #
    # CSV
    # ------------------------------------------------------------------ #
    def export_csv(self, path: str) -> str:
        """Write the subdomain inventory as CSV to ``path``."""
        os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
        with open(path, "w", encoding="utf-8", newline="") as fh:
            writer = csv.writer(fh)
            writer.writerow(["subdomain", "resolves", "ip"])
            for s in self.data.get("subdomains", []):
                writer.writerow([s.get("subdomain"), s.get("resolves"),
                                 s.get("ip") or ""])
        self.console.print(f"[green][✓][/green] CSV written: {path}")
        return path
