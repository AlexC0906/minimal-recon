"""Command-line interface for Minimal Recon."""

from dataclasses import asdict, is_dataclass
import json
from pathlib import Path
from typing import Any

import typer

from minimal_recon.services.dns import enumerate_dns, summarize_dns
from minimal_recon.services.email import analyze_email
from minimal_recon.services.footprint import check_username
from minimal_recon.services.lookup import lookup_target
from minimal_recon.services.metadata import extract_metadata
from minimal_recon.services.web import check_web
from minimal_recon.services.subdomains import enumerate_subdomains
from minimal_recon.services.report import build_report, write_report
from minimal_recon.services.whois import lookup_whois
from minimal_recon.services.geoip import geolocate_ip

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
        emit({"domain": domain, "records": records, "summary": summarize_dns(records)}, as_json=True)
        return
    for record_type, values in records.items():
        for value in values:
            typer.echo(f"{record_type}: {value}")


@app.command("whois")
def whois_lookup(domain: str, as_json: bool = typer.Option(False, "--json")) -> None:
    """Query public domain registration data through RDAP."""
    try:
        result = lookup_whois(domain)
    except (OSError, ValueError) as error:
        handle_error(error)
    if as_json:
        emit(result, as_json=True)
        return
    typer.echo(f"Domain: {result.domain}")
    typer.echo(f"Registrar: {result.registrar or 'unknown'}")
    typer.echo(f"Registered: {result.registration_date or 'unknown'}")
    typer.echo(f"Expires: {result.expiration_date or 'unknown'}")
    typer.echo(f"Last changed: {result.last_changed or 'unknown'}")
    typer.echo(f"Nameservers: {', '.join(result.nameservers) or 'unknown'}")
    typer.echo(f"Source: {result.source}")


@app.command("geoip")
def geoip_lookup(ip: str, as_json: bool = typer.Option(False, "--json")) -> None:
    """Query approximate public geolocation and hosting data for an IP."""
    try:
        result = geolocate_ip(ip)
    except (OSError, ValueError) as error:
        handle_error(error)
    if as_json:
        emit(result, as_json=True)
        return
    typer.echo(f"IP: {result.ip}")
    typer.echo(f"Location: {result.city or 'unknown'}, {result.region or 'unknown'}, {result.country or 'unknown'}")
    typer.echo(f"Coordinates: {result.latitude}, {result.longitude}")
    typer.echo(f"ISP: {result.isp or 'unknown'}")
    typer.echo(f"Organization: {result.organization or 'unknown'}")
    typer.echo(f"ASN: {result.asn or 'unknown'}")
    typer.echo(f"Source: {result.source}")


@app.command()
def footprint(
    username: str,
    as_json: bool = typer.Option(False, "--json"),
    delay: float = typer.Option(0.2, "--delay", min=0, help="Seconds between site requests."),
) -> None:
    """Check a username against a small, explicit public-site registry."""
    try:
        results = check_username(username, delay_seconds=delay)
    except ValueError as error:
        handle_error(error)
    if as_json:
        emit([asdict(result) for result in results], as_json=True)
        return
    for result in results:
        status = {
            "found": "FOUND",
            "not_found": "NOT FOUND",
            "unknown": "UNKNOWN",
        }[result.state]
        typer.echo(f"{result.site}: {status} {result.url}")


@app.command("email")
def email_analysis(address: str, as_json: bool = typer.Option(False, "--json")) -> None:
    """Validate an email and inspect its public MX records."""
    try:
        result = analyze_email(address)
    except ValueError as error:
        handle_error(error)
    if as_json:
        emit(result, as_json=True)
        return
    typer.echo(f"Email: {result.email}")
    typer.echo(f"Domain: {result.domain}")
    typer.echo(f"Valid format: {result.valid}")
    typer.echo(f"MX available: {result.mx_available}")
    typer.echo(f"Role address: {result.is_role_address}")
    typer.echo(f"Disposable domain: {result.is_disposable_domain}")
    typer.echo(f"Risk flags: {', '.join(result.risk_flags) or 'none'}")
    for record in result.mx_records:
        typer.echo(f"MX: {record}")


@app.command("web")
def web_check(url: str, as_json: bool = typer.Option(False, "--json")) -> None:
    """Passively inspect public web security headers."""
    try:
        result = check_web(url)
    except (OSError, ValueError) as error:
        handle_error(error)
    if as_json:
        emit(result, as_json=True)
        return
    typer.echo(f"URL: {result.url}")
    typer.echo(f"Final URL: {result.final_url}")
    typer.echo(f"Status: {result.status_code}")
    for name, value in result.security_headers.items():
        typer.echo(f"{name}: {value}")
    typer.echo(f"Missing headers: {', '.join(result.missing_security_headers) or 'none'}")


@app.command("subdomains")
def subdomain_enumeration(domain: str, as_json: bool = typer.Option(False, "--json")) -> None:
    """Discover public in-scope subdomains from certificate logs."""
    try:
        result = enumerate_subdomains(domain)
    except (OSError, ValueError) as error:
        handle_error(error)
    if as_json:
        emit(result, as_json=True)
        return
    typer.echo(f"Domain: {result.domain}")
    typer.echo(f"Source: {result.source}")
    for subdomain in result.subdomains:
        typer.echo(subdomain)


@app.command("report")
def report_command(
    domain: str,
    username: str = typer.Option("", "--username"),
    email: str = typer.Option("", "--email"),
    output: Path = typer.Option(None, "--output", help="Write a JSON report to this path."),
    html_output: Path = typer.Option(None, "--html", help="Write an HTML report to this path."),
) -> None:
    """Build a consolidated passive OSINT report."""
    try:
        result = build_report(domain, username or None, email or None)
        write_report(result, output, html_output)
    except (OSError, ValueError) as error:
        handle_error(error)
    if not output and not html_output:
        typer.echo(json.dumps(result, indent=2, sort_keys=True))
    else:
        if output:
            typer.echo(f"JSON report: {output}")
        if html_output:
            typer.echo(f"HTML report: {html_output}")


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
