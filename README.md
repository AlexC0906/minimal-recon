# Minimal Recon

Minimal Recon is a modular, read-only OSINT command-line utility written in Python.
It is designed as a portfolio project with small services that can be extended without
coupling the CLI to network or file-system logic.

## Features

- `lookup`: basic IP/domain resolution and reverse DNS
- `dns`: common DNS record enumeration (`A`, `AAAA`, `MX`, `NS`, `TXT`, `CNAME`)
- `footprint`: low-volume username checks against an explicit public-site registry
- `metadata`: local file metadata extraction

## Setup

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -e ".[dev]"
```

## Usage

```powershell
recon --help
recon lookup example.com
recon lookup example.com --json
recon dns example.com
recon footprint octocat
recon footprint octocat --delay 0.5 --json
recon metadata .\sample.jpg
```

Every command supports `--json` for scripting and pipeline integration.
For `dns --json`, the response includes the raw records and a derived `summary`
with nameservers, mail servers and conservative provider hints.
Footprint checks use an explicit public-site registry and support `--delay` to
space out requests; they do not bypass authentication or access controls.

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
