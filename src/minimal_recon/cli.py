"""Command-line interface for Minimal Recon."""

from dataclasses import asdict, is_dataclass
import json
from pathlib import Path
from typing import Any

import typer

from minimal_recon.services.dns import enumerate_dns
from minimal_recon.services.footprint import check_username
from minimal_recon.services.lookup import lookup_target
from minimal_recon.services.metadata import extract_metadata

app = typer.Typer(help="Read-only OSINT reconnaissance utilities.")


def emit(data: Any, as_json: bool) -> None:
    """Print a result in human-readable or automation-friendly form."""
    if as_json:
        payload = asdict(data) if is_dataclass(data) else data
        typer.echo(json.dumps(payload, indent=2, sort_keys=True))
        return
    if isinstance(data, dict):
        for key, values in data.items():
            for value in values if isinstance(values, list) else [values]:
                typer.echo(f"{key}: {value}")


def handle_error(error: Exception) -> None:
    typer.echo(f"Error: {error}", err=True)
    raise typer.Exit(code=1)


@app.command()
def lookup(target: str, as_json: bool = typer.Option(False, "--json")) -> None:
    """Resolve an IP address or domain to basic network information."""
    try:
        result = lookup_target(target)
    except (OSError, ValueError) as error:
        handle_error(error)
    if as_json:
        emit(result, as_json=True)
        return
    typer.echo(f"Target: {result.target}")
    typer.echo(f"Type: {result.target_type}")
    for address in result.addresses:
        typer.echo(f"Address: {address}")
    if result.reverse_name:
        typer.echo(f"Reverse DNS: {result.reverse_name}")


@app.command("dns")
def dns_enumeration(domain: str, as_json: bool = typer.Option(False, "--json")) -> None:
    """Query common DNS records for a domain."""
    try:
        records = enumerate_dns(domain)
    except (OSError, ValueError) as error:
        handle_error(error)
    if as_json:
        emit(records, as_json=True)
        return
    for record_type, values in records.items():
        for value in values:
            typer.echo(f"{record_type}: {value}")


@app.command()
def footprint(username: str, as_json: bool = typer.Option(False, "--json")) -> None:
    """Check a username against a small, explicit public-site registry."""
    results = check_username(username)
    if as_json:
        emit([asdict(result) for result in results], as_json=True)
        return
    for result in results:
        status = "found" if result.found else "not found"
        typer.echo(f"{result.site}: {status} ({result.url})")


@app.command()
def metadata(path: Path, as_json: bool = typer.Option(False, "--json")) -> None:
    """Extract filesystem and basic image metadata from a local file."""
    try:
        result = extract_metadata(path)
    except OSError as error:
        handle_error(error)
    if as_json:
        emit(result, as_json=True)
        return
    for key, value in result.items():
        typer.echo(f"{key}: {value}")


if __name__ == "__main__":
    app()
