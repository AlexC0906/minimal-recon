"""Username footprint and manual search links."""

from dataclasses import asdict
from pathlib import Path
from typing import List, Optional

import typer

from minimal_recon.commands.common import emit, handle_error
from minimal_recon.commands.reports import print_saved, save_footprint
from minimal_recon.services.footprint import (
    SITES,
    FootprintResult,
    check_username,
    load_registry,
    mastodon_rule,
    run_self_test,
    search_links,
)

app = typer.Typer()


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
    save: bool = typer.Option(False, "--save", help="Save to local history and show changes since the last run."),
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
            saved = {
                username: save_footprint(username, [asdict(result) for result in results])
                for username, results in runs
                if save
            }
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
        if username in saved:
            print_saved(saved[username])


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
