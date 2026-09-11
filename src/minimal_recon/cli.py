"""Command-line interface for Minimal Recon."""

from pathlib import Path

import typer

from minimal_recon.services.dns import enumerate_dns
from minimal_recon.services.footprint import check_username
from minimal_recon.services.lookup import lookup_target
from minimal_recon.services.metadata import extract_metadata

app = typer.Typer(help="Read-only OSINT reconnaissance utilities.")


@app.command()
def lookup(target: str) -> None:
    """Resolve an IP address or domain to basic network information."""
    result = lookup_target(target)
    typer.echo(f"Target: {result.target}")
    typer.echo(f"Type: {result.target_type}")
    for address in result.addresses:
        typer.echo(f"Address: {address}")
    if result.reverse_name:
        typer.echo(f"Reverse DNS: {result.reverse_name}")


@app.command("dns")
def dns_enumeration(domain: str) -> None:
    """Query common DNS records for a domain."""
    records = enumerate_dns(domain)
    for record_type, values in records.items():
        for value in values:
            typer.echo(f"{record_type}: {value}")


@app.command()
def footprint(username: str) -> None:
    """Check a username against a small, explicit public-site registry."""
    for result in check_username(username):
        status = "found" if result.found else "not found"
        typer.echo(f"{result.site}: {status} ({result.url})")


@app.command()
def metadata(path: Path) -> None:
    """Extract filesystem and basic image metadata from a local file."""
    for key, value in extract_metadata(path).items():
        typer.echo(f"{key}: {value}")


if __name__ == "__main__":
    app()
