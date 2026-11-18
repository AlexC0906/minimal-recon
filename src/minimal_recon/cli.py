"""Command-line interface for Minimal Recon."""

from dataclasses import asdict, is_dataclass
import json
from pathlib import Path
import ssl
from typing import Any, List, NoReturn, Optional

import httpx
import typer

from minimal_recon import __version__
from minimal_recon.services.antispoofing import analyze_anti_spoofing
from minimal_recon.services.archive import enumerate_archive
from minimal_recon.services.diff import diff_reports, load_report
from minimal_recon.services.dns import enumerate_dns, summarize_dns
from minimal_recon.services.email import analyze_email
from minimal_recon.services.footprint import (
    SITES,
    FootprintResult,
    check_username,
    load_registry,
    mastodon_rule,
    run_self_test,
    search_links,
)
from minimal_recon.services.geoip import geolocate_ip
from minimal_recon.services.http import configure
from minimal_recon.services.links import extract_links
from minimal_recon.services.lookup import lookup_target
from minimal_recon.services.metadata import extract_metadata
from minimal_recon.services.public_files import discover_public_files
from minimal_recon.services.report import build_report, write_report
from minimal_recon.services.shodan import lookup_host
from minimal_recon.services.subdomains import enumerate_subdomains
from minimal_recon.services.threatintel import check_reputation
from minimal_recon.services.tls import inspect_tls
from minimal_recon.services.verification import create_token, verify_urls
from minimal_recon.services.web import check_web
from minimal_recon.services.whois import lookup_whois

app = typer.Typer(help="Read-only OSINT reconnaissance utilities.")


def version_callback(value: bool) -> None:
    if value:
        typer.echo(f"Minimal Recon {__version__}")
        raise typer.Exit()


@app.callback()
def main(
    version: bool = typer.Option(
        False,
        "--version",
        callback=version_callback,
        is_eager=True,
        help="Show the installed version and exit.",
    ),
    timeout: Optional[float] = typer.Option(
        None,
        "--timeout",
        min=0.1,
        help="Seconds to wait on each HTTP, DNS and TLS operation instead of the per-command defaults.",
    ),
) -> None:
    """Read-only OSINT reconnaissance utilities."""
    configure(timeout)


def emit(data: Any, as_json: bool) -> None:
    """Print a result in human-readable or automation-friendly form."""
    if as_json:
        payload = asdict(data) if is_dataclass(data) and not isinstance(data, type) else data
        typer.echo(json.dumps(payload, indent=2, sort_keys=True))
        return
    if isinstance(data, dict):
        for key, values in data.items():
            for value in values if isinstance(values, list) else [values]:
                typer.echo(f"{key}: {value}")


def handle_error(error: Exception) -> NoReturn:
    if isinstance(error, httpx.TimeoutException):
        message = "network timeout"
    elif isinstance(error, httpx.HTTPStatusError):
        message = f"remote service returned HTTP {error.response.status_code}"
    elif isinstance(error, httpx.RequestError):
        message = "network connection failed"
    else:
        message = str(error)
    typer.echo(f"Error: {message}", err=True)
    raise typer.Exit(code=1)


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


FOOTPRINT_LABELS = {
    "found": "FOUND",
    "not_found": "NOT FOUND",
    "unknown": "UNKNOWN",
    "rate_limited": "RATE LIMITED",
    "not_applicable": "N/A",
}

PROFILE_LABELS = {
    "display_name": "Name",
    "bio": "Bio",
    "location": "Location",
    "website": "Website",
    "created_at": "Joined",
    "declared_accounts": "Self-declared accounts (not verified)",
    "stats": "Public stats",
}


@app.command()
def footprint(
    usernames: Optional[List[str]] = typer.Argument(
        None, help="One or more usernames to check. Not needed with --self-test."
    ),
    as_json: bool = typer.Option(False, "--json"),
    delay: float = typer.Option(0.2, "--delay", min=0, help="Seconds between requests to the same host."),
    sites_file: Optional[Path] = typer.Option(
        None, "--sites", help="JSON site registry to use instead of the bundled one."
    ),
    only: List[str] = typer.Option([], "--site", help="Check only this site (repeatable)."),
    self_test: bool = typer.Option(
        False, "--self-test", help="Check every rule against its known present and absent usernames."
    ),
    details: bool = typer.Option(
        False,
        "--details",
        help="Also show self-published profile fields and public stats from site APIs.",
    ),
    mastodon_servers: List[str] = typer.Option(
        [], "--mastodon", help="Also check this Mastodon server, e.g. fosstodon.org (repeatable)."
    ),
    audit_token: Optional[str] = typer.Option(
        None,
        "--audit-token",
        help="Self-audit your own accounts: a token from `recon verify-token` that you placed in your profiles.",
    ),
    found_only: bool = typer.Option(
        False, "--found-only", help="Show only sites where the username was found (all sites are still checked)."
    ),
) -> None:
    """Check one or more usernames against an explicit registry of public sites."""
    try:
        registry = load_registry(sites_file) if sites_file else dict(SITES)
        if only:
            unknown_sites = sorted(set(only) - set(registry))
            if unknown_sites:
                raise ValueError(f"unknown site(s): {', '.join(unknown_sites)}")
            registry = {name: rule for name, rule in registry.items() if name in only}
        if mastodon_servers:
            base = registry.get("mastodon", SITES["mastodon"])
            for server in mastodon_servers:
                rule = mastodon_rule(server, base)
                registry[rule.name] = rule
        if self_test:
            report = run_self_test(registry)
        elif not usernames:
            raise ValueError("a username is required unless --self-test is used")
        else:
            runs = [
                (
                    username,
                    check_username(
                        username, sites=registry, delay_seconds=delay, details=details, audit_token=audit_token
                    ),
                )
                for username in dict.fromkeys(usernames)
            ]
    except (OSError, ValueError) as error:
        handle_error(error)

    if self_test:
        if as_json:
            emit(report, as_json=True)
            return
        for entry in report:
            outcome = f"present={entry['present']}, absent={entry['absent']}"
            typer.echo(f"{entry['site']}: {entry['status'].upper()} ({outcome})")
        broken = sum(1 for entry in report if entry["status"] == "broken")
        typer.echo(f"{len(report) - broken} of {len(report)} rules not broken.")
        return

    if as_json:
        if found_only:
            runs = [(username, [result for result in results if result.found]) for username, results in runs]
        if len(runs) == 1:
            emit([asdict(result) for result in runs[0][1]], as_json=True)
        else:
            payload = [
                {"username": username, "results": [asdict(result) for result in results]} for username, results in runs
            ]
            emit(payload, as_json=True)
        return
    for position, (username, results) in enumerate(runs):
        if len(runs) > 1:
            typer.echo(("\n" if position else "") + f"=== {username}")
        _print_footprint(results, audit=audit_token is not None, found_only=found_only)


def _print_footprint(results: List[FootprintResult], audit: bool, found_only: bool = False) -> None:
    for result in results:
        if found_only and not result.found:
            continue
        status = FOOTPRINT_LABELS.get(result.state, result.state.upper())
        confidence = f" [{result.confidence}]" if result.confidence else ""
        origin = f" (declared on {result.discovered_from})" if result.discovered_from else ""
        typer.echo(f"{result.site}: {status} {result.url}{confidence}{origin}")
        if audit and result.found:
            typer.echo(f"  Audit token: {'found - verified as yours' if result.owner_verified else 'not found'}")
        if result.found and result.page_title:
            typer.echo(f"  Title: {result.page_title}")
        if result.found and result.meta_description:
            typer.echo(f"  Description: {result.meta_description}")
        for name, value in result.profile.items():
            if isinstance(value, dict):
                value = ", ".join(f"{label}: {item}" for label, item in value.items())
            typer.echo(f"  {PROFILE_LABELS.get(name, name)}: {value}")
        if result.profile_note:
            typer.echo(f"  Details: {result.profile_note}")
    found = sum(1 for result in results if result.found)
    undecided = sum(1 for result in results if result.state in ("unknown", "rate_limited"))
    typer.echo(f"Found on {found} of {len(results)} sites; {undecided} could not be determined.")
    if audit:
        verified = sum(1 for result in results if result.owner_verified)
        typer.echo(f"Verified as yours: {verified} profile(s).")


@app.command("ui")
def ui_command(
    port: int = typer.Option(8765, "--port", min=0, max=65535, help="Local port; 0 picks a free one."),
    no_browser: bool = typer.Option(False, "--no-browser", help="Do not open the browser automatically."),
) -> None:
    """Open the local web interface (served on 127.0.0.1 only)."""
    from minimal_recon.ui.server import serve

    try:
        serve(port, open_browser=not no_browser, announce=typer.echo)
    except OSError as error:
        handle_error(OSError(f"could not start the interface on port {port}: {error.strerror or error}"))


@app.command("search-links")
def search_links_command(username: str, as_json: bool = typer.Option(False, "--json")) -> None:
    """Print web-search and Wayback links for manual review. Sends no requests."""
    try:
        links = search_links(username)
    except ValueError as error:
        handle_error(error)
    if as_json:
        emit(links, as_json=True)
        return
    typer.echo(f"Username: {links['username']}")
    typer.echo("Exact-match web searches:")
    for engine, url in links["search_engines"].items():
        typer.echo(f"  {engine}: {url}")
    typer.echo("Wayback Machine history of each possible profile:")
    for site, url in links["archived_profiles"].items():
        typer.echo(f"  {site}: {url}")


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


@app.command("report")
def report_command(
    domain: str,
    username: str = typer.Option("", "--username"),
    email: str = typer.Option("", "--email"),
    output: Path = typer.Option(None, "--output", help="Write a JSON report to this path."),
    html_output: Path = typer.Option(None, "--html", help="Write an HTML report to this path."),
    details: bool = typer.Option(
        False, "--details", help="Include self-published profile fields in the username footprint."
    ),
) -> None:
    """Build a consolidated passive OSINT report."""
    try:
        result = build_report(domain, username or None, email or None, footprint_details=details)
        write_report(result, output, html_output)
    except (httpx.HTTPError, OSError, ValueError) as error:
        handle_error(error)
    if not output and not html_output:
        typer.echo(json.dumps(result, indent=2, sort_keys=True))
    else:
        if output:
            typer.echo(f"JSON report: {output}")
        if html_output:
            typer.echo(f"HTML report: {html_output}")


@app.command("diff")
def diff_command(
    old: Path = typer.Argument(..., help="Earlier JSON report."),
    new: Path = typer.Argument(..., help="Later JSON report."),
    as_json: bool = typer.Option(False, "--json"),
) -> None:
    """Compare two saved JSON reports without making any network request."""
    try:
        old_report = load_report(old)
        new_report = load_report(new)
    except (OSError, ValueError) as error:
        handle_error(error)
    changes = diff_reports(old_report, new_report)
    if as_json:
        emit(
            {
                "target": new_report.get("target"),
                "old_generated_at": old_report.get("generated_at"),
                "new_generated_at": new_report.get("generated_at"),
                "changes": [asdict(change) for change in changes],
            },
            as_json=True,
        )
        return
    typer.echo(f"Target: {new_report.get('target')}")
    typer.echo(f"Compared: {old_report.get('generated_at', 'unknown')} -> {new_report.get('generated_at', 'unknown')}")
    if not changes:
        typer.echo("No changes.")
        return
    for change in changes:
        if change.change == "added":
            typer.echo(f"+ {change.path}: {_compact(change.new)}")
        elif change.change == "removed":
            typer.echo(f"- {change.path}: {_compact(change.old)}")
        else:
            typer.echo(f"~ {change.path}: {_compact(change.old)} -> {_compact(change.new)}")
    typer.echo(f"{len(changes)} change(s).")


def _compact(value: Any) -> str:
    """Render one diff value on a single line."""
    return value if isinstance(value, str) else json.dumps(value, sort_keys=True, default=str)


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
