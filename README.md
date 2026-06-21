# ReconKit — Passive OSINT Reconnaissance Toolkit

[![CI](https://github.com/sabkari-mohamed/reconkit-/actions/workflows/ci.yml/badge.svg)](https://github.com/sabkari-mohamed/reconkit-/actions/workflows/ci.yml)
![Python](https://img.shields.io/badge/python-3.8%2B-blue)
![License](https://img.shields.io/badge/license-MIT-green)
![Status](https://img.shields.io/badge/recon-passive-orange)
![Version](https://img.shields.io/badge/version-2.1.0-blueviolet)

> Built by **Mohamed Sabkari**.

Aggregate open-source intelligence about a domain from public APIs and
registries, then produce a structured **JSON** export and a clean **HTML**
report.

> **Passive only.** ReconKit reads public data sources (Certificate
> Transparency logs, WHOIS, public DNS, Hunter.io's index, Shodan's existing
> scan data). It sends **no** active scan traffic to the target's own
> infrastructure beyond standard DNS/WHOIS resolution. Use it on domains you
> own or are **explicitly authorized** to assess (bug bounty in-scope).

---

## Data sources (all passive / public)

| Source | Module | What it gives | Key |
|--------|--------|---------------|-----|
| [crt.sh](https://crt.sh) | `subdomains` | Subdomains from CT certificate logs | — |
| [certspotter](https://sslmate.com/certspotter/) | `subdomains` | Additional CT log coverage | — |
| Public DNS | `dns` | A, AAAA, MX, TXT, NS, CNAME, SOA + SPF/DMARC | — |
| WHOIS registries | `whois` | Registrar, dates, name servers, status | — |
| [urlscan.io](https://urlscan.io) | `urlscan` | Observed URLs, IPs, servers from past scans | optional |
| [Wayback Machine](https://archive.org) | `wayback` | Historical URLs + sensitive-endpoint flags | — |
| [Team Cymru](https://www.team-cymru.com/ip-asn-mapping) | `asn` | IP → ASN, BGP prefix, org, country (via DNS) | — |
| [AlienVault OTX](https://otx.alienvault.com) | `threat` | Passive DNS + threat-pulse reputation | — |
| [Hunter.io](https://hunter.io) | `emails` | Public email addresses for the domain | required |
| [Shodan](https://shodan.io) | `shodan` | Open ports / services from existing scans | required |
| [subfinder](https://github.com/projectdiscovery/subfinder) · [amass](https://github.com/owasp-amass/amass) · [gau](https://github.com/lc/gau) | `tools` | Best-in-class passive enum, **auto-detected** | optional binaries |

## Features

- **Subdomain enumeration** from two Certificate Transparency sources, merged
  and deduplicated, with optional live DNS resolution (live vs historical).
- **DNS sweep** (A/AAAA/MX/TXT/NS/CNAME/SOA) with **SPF / DMARC** posture checks.
- **WHOIS** with an expiry-within-30-days flag.
- **urlscan.io + Wayback Machine** URL discovery — observed/historical URLs,
  extra subdomains, and automatic flagging of **sensitive endpoints**
  (admin / api / config / backup / `.env` / `.git` …).
- **ASN / netblock enrichment** (Team Cymru) — every resolved IP mapped to its
  origin ASN, BGP prefix, organisation, and country. Concurrent lookups.
- **Threat-intel reputation** via AlienVault OTX (passive DNS + threat pulses).
- **Email harvesting** (Hunter.io) and **Shodan** host intelligence
  (open ports, services, banners, CVE tags).
- **Exposure risk score** — every finding rolled into a weighted 0–100 score,
  an **A–F letter grade**, an itemised factor breakdown, and an executive
  summary. The headline a stakeholder reads first.
- **Tool orchestration** — auto-detects and integrates the industry-standard
  passive tools **subfinder · amass · gau** when installed (zero config), and
  falls back to the built-in Python sources when they're absent. ReconKit gets
  stronger as you add tools, but always works without them.
- **Five output formats**: rich terminal, JSON, self-contained HTML report
  (no external CSS), Markdown, and CSV.
- **Graceful degradation** — a failing or key-less module never kills the run.

---

## Installation

```bash
git clone https://github.com/sabkari-mohamed/reconkit-.git
cd reconkit-
pip install -r requirements.txt
cp config/config.example.ini config/config.ini   # then add your keys
```

### Install as a command (optional)

Install the package so the `reconkit` command is available system-wide:

```bash
pip install -e .          # editable / development install
reconkit example.com      # now runnable from anywhere
reconkit --version
```

### Optional power-ups (external tools)

ReconKit works fully on its own, but it will **automatically orchestrate** the
best passive recon tools if they are on your `PATH` — no configuration needed.
Install any subset to boost coverage:

```bash
# requires Go (https://go.dev/dl/)
go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install github.com/owasp-amass/amass/v4/...@master
go install github.com/lc/gau/v2/cmd/gau@latest

# verify ReconKit can see them
reconkit example.com --check-tools
```

Run them via the `tools` module (`reconkit example.com --modules tools`). All
run in **passive** mode (`subfinder -all`, `amass -passive`, `gau`).

### API keys (optional but recommended)

ReconKit runs without any keys — the `emails` and `shodan` modules simply skip
with a warning. To enable them:

- **Hunter.io** — free tier at <https://hunter.io/api-keys>
- **Shodan** — free key at <https://account.shodan.io/>

Add them to `config/config.ini`:

```ini
[hunter]
api_key = your_hunter_key

[shodan]
api_key = your_shodan_key
```

Or via environment variables (these take precedence over the file):

```bash
export HUNTER_API_KEY=your_hunter_key
export SHODAN_API_KEY=your_shodan_key
```

---

## Usage

```bash
# Everything (default): all modules, all report formats
python reconkit.py example.com

# Only subdomain + DNS recon
python reconkit.py example.com --modules subdomains,dns

# Attack-surface + URL discovery, no API keys needed
python reconkit.py example.com --modules subdomains,urlscan,wayback,asn,threat

# HTML report only / Markdown for a GitHub issue / CSV inventory
python reconkit.py example.com --report html
python reconkit.py example.com --report markdown
python reconkit.py example.com --report csv

# Skip live subdomain resolution (faster, CT data only)
python reconkit.py example.com --no-resolve

# Custom output directory and config path
python reconkit.py example.com --output-dir ./reports --config /path/config.ini
```

### CLI reference

| Flag | Default | Description |
|------|---------|-------------|
| `domain` | — | target domain (positional, required) |
| `--modules` | `all` | `subdomains,tools,dns,whois,urlscan,wayback,asn,threat,emails,shodan,all` |
| `--output-dir` | `./output` | where reports are written |
| `--report` | `all` | `terminal,json,html,markdown,csv,all` |
| `--check-tools` | — | list detected external tools (subfinder/amass/gau) and exit |
| `--version` | — | print version + author and exit |
| `--config` | `config/config.ini` | path to the ini config |
| `--resolve` / `--no-resolve` | on | live-resolve discovered subdomains |

Each module is also runnable standalone for testing, e.g.:

```bash
python -m modules.dns_recon example.com
python -m modules.subdomains example.com
```

Outputs are written to `output/<domain>_recon.json` and
`output/<domain>_recon.html`.

---

## Web dashboard

A professional **dark-mode web dashboard** ships alongside the CLI. It runs the
same passive modules and streams progress **live** to the browser (Server-Sent
Events), then renders an exposure grade, stat cards, a risk-factor chart, and
sortable detail tables — with one-click JSON / Markdown download.

```bash
pip install -r requirements.txt      # includes Flask
python web/app.py                    # → http://127.0.0.1:5000
# or, after `pip install -e .`
reconkit-web --host 0.0.0.0 --port 8000
```

Then open the URL, type a domain, pick modules, and hit **Run Recon**.

Highlights:
- Live per-module progress (SSE) — watch each source resolve in real time.
- Animated risk-score ring + A–F grade, colour-coded.
- Stat cards, risk-factor bar chart, security notes, and per-section tables
  (subdomains, DNS, WHOIS, ASN, sensitive URLs, threat intel, emails, Shodan).
- Fully responsive, keyboard-accessible, `prefers-reduced-motion` aware,
  SVG icons (no emoji), WCAG-AA contrast.
- Server-side domain validation; no traffic to the target beyond DNS/WHOIS.

---

## Sample output

```
╭─ ReconKit OSINT Report ─╮
│ target: example.com     │
╰─────────────────────────╯
        Summary
┏━━━━━━━━━━━━━━┳━━━━━━━┓
┃ Metric       ┃ Count ┃
┡━━━━━━━━━━━━━━╇━━━━━━━┩
│ Subdomains   │   12  │
│ Live hosts   │    9  │
│ ...          │  ...  │
```

> _Screenshot placeholder — add `screenshots/report.png` of the HTML report._

---

## Ethics & legal

ReconKit is for **authorized** reconnaissance only: domains you own, or targets
explicitly **in scope** for a bug-bounty program or engagement. All data
sources are passive and public; nevertheless, you are responsible for
complying with each source's terms of service and with the law in your
jurisdiction. Do not use ReconKit against systems you are not permitted to
assess.

## Author

**Mohamed Sabkari** — security / OSINT tooling.

- GitHub: <https://github.com/sabkari-mohamed>
- LinkedIn / portfolio: _add your link here_

If ReconKit is useful to you, a ⭐ on the repo is appreciated.

## License

Released under the [MIT License](LICENSE) © 2026 Mohamed Sabkari.
