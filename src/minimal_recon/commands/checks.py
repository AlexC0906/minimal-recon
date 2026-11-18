"""Single-target checks: domains, IP addresses, web pages, email, files and ownership."""

from dataclasses import asdict
from pathlib import Path
import ssl

import httpx
import typer

from minimal_recon.commands.common import emit, handle_error
from minimal_recon.services.antispoofing import analyze_anti_spoofing
from minimal_recon.services.archive import enumerate_archive
from minimal_recon.services.dns import enumerate_dns, summarize_dns
from minimal_recon.services.email import analyze_email
from minimal_recon.services.geoip import geolocate_ip
from minimal_recon.services.links import extract_links
from minimal_recon.services.lookup import lookup_target
from minimal_recon.services.metadata import extract_metadata
from minimal_recon.services.public_files import discover_public_files
from minimal_recon.services.shodan import lookup_host
from minimal_recon.services.subdomains import enumerate_subdomains
from minimal_recon.services.threatintel import check_reputation
from minimal_recon.services.tls import inspect_tls
from minimal_recon.services.verification import create_token, verify_urls
from minimal_recon.services.web import check_web
from minimal_recon.services.whois import lookup_whois

app = typer.Typer()


@app.command()
def lookup(target: str, as_json: bool = typer.Option(False, "--json")) -> None:
    """Resolve an IP address or domain to basic network information."""
    try:
        result = lookup_target(target)
    except (httpx.HTTPError, OSError, ValueError) as error:
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
    except (httpx.HTTPError, OSError, ValueError) as error:
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
    except (httpx.HTTPError, OSError, ValueError) as error:
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
    except (httpx.HTTPError, OSError, ValueError) as error:
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


@app.command("archive")
def archive_history(domain: str, as_json: bool = typer.Option(False, "--json")) -> None:
    """List public Wayback Machine snapshots for a domain."""
    try:
        result = enumerate_archive(domain)
    except (httpx.HTTPError, OSError, ValueError) as error:
        handle_error(error)
    if as_json:
        emit(result, as_json=True)
        return
    typer.echo(f"Domain: {result.domain}")
    typer.echo(f"Source: {result.source}")
    for snapshot in result.snapshots:
        typer.echo(f"{snapshot.timestamp} {snapshot.original_url} {snapshot.archive_url}")


@app.command("verify-token")
def verification_token() -> None:
    """Generate a token for explicit public profile ownership verification."""
    typer.echo(create_token())


@app.command("verify")
def verify_profiles(
    token: str = typer.Option(..., "--token"),
    urls: list[str] = typer.Option(..., "--url"),
    as_json: bool = typer.Option(False, "--json"),
) -> None:
    """Verify an exact token on explicitly supplied public profile URLs."""
    try:
        results = verify_urls(urls, token)
    except (httpx.HTTPError, OSError, ValueError) as error:
        handle_error(error)
    if as_json:
        emit([asdict(result) for result in results], as_json=True)
        return
    for result in results:
        status = "VERIFIED" if result.verified else "NOT VERIFIED"
        typer.echo(f"{status} {result.url} - {result.evidence}")


@app.command("reputation")
def reputation_check(target: str, as_json: bool = typer.Option(False, "--json")) -> None:
    """Read external VirusTotal reputation data for an IP or domain."""
    try:
        result = check_reputation(target)
    except (httpx.HTTPError, OSError, ValueError) as error:
        handle_error(error)
    if as_json:
        emit(result, as_json=True)
        return
    typer.echo(f"Target: {result.target}")
    typer.echo(f"Type: {result.target_type}")
    typer.echo(f"Malicious: {result.malicious}")
    typer.echo(f"Suspicious: {result.suspicious}")
    typer.echo(f"Harmless: {result.harmless}")
    typer.echo(f"Undetected: {result.undetected}")
    typer.echo(f"Reputation: {result.reputation}")
    typer.echo(f"Source: {result.source}")


@app.command("tls")
def tls_check(
    hostname: str,
    port: int = typer.Option(443, "--port", min=1, max=65535),
    as_json: bool = typer.Option(False, "--json"),
) -> None:
    """Inspect one public TLS endpoint and certificate."""
    try:
        result = inspect_tls(hostname, port)
    except (OSError, ValueError, ssl.SSLError) as error:
        handle_error(error)
    if as_json:
        emit(result, as_json=True)
        return
    typer.echo(f"Host: {result.hostname}:{result.port}")
    typer.echo(f"TLS: {result.tls_version}")
    typer.echo(f"Cipher: {result.cipher}")
    typer.echo(f"Subject: {result.subject}")
    typer.echo(f"Issuer: {result.issuer}")
    typer.echo(f"Expires: {result.not_after or 'unknown'}")
    typer.echo(f"Days until expiry: {result.days_until_expiry}")
    if result.verified:
        typer.echo("Certificate valid: yes")
    else:
        typer.echo(f"Certificate valid: NO ({result.verification_error})")


@app.command("shodan")
def shodan_lookup(ip: str, as_json: bool = typer.Option(False, "--json")) -> None:
    """Read Shodan's indexed host data for one IP address."""
    try:
        result = lookup_host(ip)
    except (httpx.HTTPError, OSError, ValueError) as error:
        handle_error(error)
    if as_json:
        emit(result, as_json=True)
        return
    typer.echo(f"IP: {result.ip}")
    typer.echo(f"Organization: {result.organization or 'unknown'}")
    typer.echo(f"ISP: {result.isp or 'unknown'}")
    typer.echo(f"ASN: {result.asn or 'unknown'}")
    typer.echo(f"Location: {result.city or 'unknown'}, {result.country or 'unknown'}")
    typer.echo(f"Hostnames: {', '.join(result.hostnames) or 'none'}")
    typer.echo(f"Indexed ports: {', '.join(map(str, result.ports)) or 'none'}")
    typer.echo(f"Domains: {', '.join(result.domains) or 'none'}")
    typer.echo(f"Last update: {result.last_update or 'unknown'}")


@app.command("links")
def links_command(
    url: str,
    max_links: int = typer.Option(500, "--max-links", min=1, max=5000),
    as_json: bool = typer.Option(False, "--json"),
) -> None:
    """Extract links from one public page without following them."""
    try:
        result = extract_links(url, max_links=max_links)
    except (httpx.HTTPError, OSError, ValueError) as error:
        handle_error(error)
    if as_json:
        emit(result, as_json=True)
        return
    typer.echo(f"Source: {result.source_url}")
    typer.echo(f"Final URL: {result.final_url}")
    typer.echo(f"Links found: {result.links_found}")
    typer.echo("Internal links:")
    for link in result.internal_links:
        typer.echo(f"  {link}")
    typer.echo("External links:")
    for link in result.external_links:
        typer.echo(f"  {link}")


@app.command("anti-spoofing")
def anti_spoofing_check(
    domain: str,
    selectors: str = typer.Option("", "--selectors", help="Comma-separated DKIM selectors to check."),
    as_json: bool = typer.Option(False, "--json"),
) -> None:
    """Check public SPF, DMARC and selected DKIM policies."""
    try:
        result = analyze_anti_spoofing(domain, [item for item in selectors.split(",") if item.strip()])
    except (httpx.HTTPError, OSError, ValueError) as error:
        handle_error(error)
    if as_json:
        emit(result, as_json=True)
        return
    typer.echo(f"Domain: {result.domain}")
    typer.echo(f"SPF: {result.spf_status}")
    typer.echo(f"DMARC: {result.dmarc_status} (p={result.dmarc_policy or 'unknown'})")
    typer.echo(f"DKIM: {result.dkim_status}")
    for finding in result.findings:
        typer.echo(f"Finding: {finding}")


@app.command("public-files")
def public_files_check(url: str, as_json: bool = typer.Option(False, "--json")) -> None:
    """Check standard public web documents without brute-force discovery."""
    try:
        results = discover_public_files(url)
    except (httpx.HTTPError, OSError, ValueError) as error:
        handle_error(error)
    if as_json:
        emit([asdict(result) for result in results], as_json=True)
        return
    for result in results:
        status = "FOUND" if result.found else "NOT FOUND"
        typer.echo(f"{status} {result.url} ({result.status_code or 'request error'})")


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
    except (httpx.HTTPError, OSError, ValueError) as error:
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
    typer.echo(f"WAF: {result.waf_vendor or 'not detected'}")
    typer.echo(f"WAF signals: {', '.join(result.waf_signals) or 'none'}")
    typer.echo(f"WAF confidence: {result.waf_confidence}")
    typer.echo("Technologies:")
    for technology, signals in result.technologies.items():
        typer.echo(f"  {technology}: {', '.join(signals)}")


@app.command("subdomains")
def subdomain_enumeration(domain: str, as_json: bool = typer.Option(False, "--json")) -> None:
    """Discover public in-scope subdomains from certificate logs."""
    try:
        result = enumerate_subdomains(domain)
    except (httpx.HTTPError, OSError, ValueError) as error:
        handle_error(error)
    if as_json:
        emit(result, as_json=True)
        return
    typer.echo(f"Domain: {result.domain}")
    typer.echo(f"Source: {result.source}")
    for subdomain in result.subdomains:
        typer.echo(subdomain)


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
