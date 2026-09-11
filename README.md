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
recon dns example.com
recon footprint octocat
recon metadata .\sample.jpg
```

Only use this tool against systems, domains, files and identities you are authorized
to investigate. The first version intentionally avoids brute force, stealth and
access-control bypass techniques.

## Why Typer?

Typer is a good fit here because it provides modern type-hint-based command definitions,
help generation and shell-friendly errors while keeping each CLI command thin. It is
less verbose than `argparse`, and the project can add nested command groups later
without losing a clean service layer.
