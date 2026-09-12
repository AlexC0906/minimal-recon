# Minimal Recon

[![CI](https://github.com/AlexC0906/minimal-recon/actions/workflows/ci.yml/badge.svg)](https://github.com/AlexC0906/minimal-recon/actions/workflows/ci.yml)

Minimal Recon is a modular, read-only OSINT command-line utility written in Python.
It is designed as a portfolio project with small services that can be extended without
coupling the CLI to network or file-system logic.

## Features

- `lookup`: basic IP/domain resolution and reverse DNS
- `dns`: common DNS record enumeration (`A`, `AAAA`, `MX`, `NS`, `TXT`, `CNAME`)
- `footprint`: low-volume username checks against an explicit public-site registry
- `email`: email format validation and public MX record analysis
- `metadata`: local filesystem metadata plus image dimensions and readable EXIF fields
- `web`: passive inspection of public web security headers
- `subdomains`: passive discovery from Certificate Transparency logs
- `report`: consolidated JSON or HTML audit report
- `whois`: public RDAP registration, registrar, dates and nameservers
- `geoip`: approximate IP location and network ownership information
- `archive`: public website history from the Wayback Machine
- `verify`: explicit proof-of-control verification for supplied profile URLs
- `reputation`: optional read-only VirusTotal IP/domain reputation lookup
- `tls`: read-only TLS version and certificate inspection
- `web`: passive security headers and WAF fingerprint detection

## Setup

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -e ".[dev]"
```

## Local Testing

Run the automated tests:

```powershell
python -m pytest
```

Test commands without external requests:

```powershell
python -m minimal_recon.cli --help
python -m minimal_recon.cli lookup 192.0.2.10 --json
python -m minimal_recon.cli metadata pyproject.toml --json
```

For network-backed commands, use only authorized targets:

```powershell
python -m minimal_recon.cli lookup example.com --json
python -m minimal_recon.cli dns example.com --json
python -m minimal_recon.cli footprint octocat --delay 0.5 --json
python -m minimal_recon.cli web https://example.com --json
python -m minimal_recon.cli subdomains example.com --json
python -m minimal_recon.cli whois example.com --json
python -m minimal_recon.cli geoip 1.1.1.1 --json
python -m minimal_recon.cli archive example.com --json
python -m minimal_recon.cli tls example.com --json
python -m minimal_recon.cli report example.com --username alex576_ --output audit.json --html audit.html
```

## Usage

```powershell
recon --help
recon lookup example.com
recon lookup example.com --json
recon dns example.com
recon footprint octocat
recon footprint octocat --delay 0.5 --json
python -m minimal_recon.cli email analyst@example.com --json
python -m minimal_recon.cli web https://example.com --json
recon metadata .\sample.jpg
```

Every command supports `--json` for scripting and pipeline integration.
For `dns --json`, the response includes the raw records and a derived `summary`
with nameservers, mail servers and conservative provider hints.
Footprint checks use an explicit public-site registry containing GitHub, Instagram,
Reddit, X, TikTok, YouTube, Twitch, Pinterest, Medium and Dev.to. Results include
the source URL, final URL, HTTP status, UTC timestamp, page title and meta description,
plus an explicit match basis. They support
`--delay` to space out requests and do not bypass authentication or access controls.
A `200` response is not enough to prove that a profile exists. Results are classified
as `FOUND`, `NOT FOUND` or `UNKNOWN`; platform challenges and generic pages are kept
as `UNKNOWN`.
Metadata inspection is local-only and does not upload files anywhere.
Email analysis does not verify mailbox existence or query breach databases; it only
checks the address format and public MX records. It also flags missing MX records,
role-based addresses and a small built-in list of disposable email domains. These
are heuristics, not proof that a mailbox exists or is compromised.
Web checks make one normal HTTP request and report selected response headers; they do
not scan ports, crawl pages or attempt to bypass access controls.
Subdomain discovery uses public Certificate Transparency records and does not scan
the discovered hosts.
Reports combine the passive checks into portable JSON and HTML files with timestamps
and source URLs.
WHOIS data comes from RDAP and may omit private or registry-restricted fields.
IP geolocation is approximate and usually identifies the network, CDN or hosting
provider rather than a precise physical location.
Archive history uses the public Wayback CDX index and returns snapshot links; it does
not download archived pages.
TLS checks connect only to the requested host and port, report the negotiated protocol,
cipher and certificate dates, and do not scan other ports.
WAF detection is passive and heuristic: it uses response headers and public response
markers, so `not_detected` does not prove that a site has no WAF.
Ownership verification is opt-in: generate a token, publish it temporarily on each
profile you control, then pass those exact URLs to `verify`. It does not discover or
link accounts automatically.

External reputation checks use a user-provided VirusTotal API key and never upload
files. Set it locally before running:

```powershell
$env:VT_API_KEY = "your-api-key"
recon reputation example.com --json
recon reputation 1.1.1.1 --json
```

```powershell
recon verify-token
recon verify --token minimal-recon-verify-... --url https://github.com/your-user --url https://www.instagram.com/your-user --json
```

## Roadmap

1. Stabilize the core services with validation, timeouts and mock-based tests.
2. Add richer DNS analysis, including nameserver and mail-provider summaries.
3. Add configurable public username and email checks with rate limiting.
4. Add export formats and a small plugin interface for new OSINT collectors.
5. Add CI checks for tests, type checking and packaging.

Only use this tool against systems, domains, files and identities you are authorized
to investigate. The first version intentionally avoids brute force, stealth and
access-control bypass techniques.

## Why Typer?

Typer is a good fit here because it provides modern type-hint-based command definitions,
help generation and shell-friendly errors while keeping each CLI command thin. It is
less verbose than `argparse`, and the project can add nested command groups later
without losing a clean service layer.
