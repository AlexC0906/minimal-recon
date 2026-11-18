"""Consolidated reports, saved history, periodic monitoring and report comparison."""

from dataclasses import asdict
from datetime import datetime
import json
from pathlib import Path
import re
import time
from typing import List, Optional

import httpx
import typer

from minimal_recon.commands.common import compact, emit, handle_error, short
from minimal_recon.services import history
from minimal_recon.services.diff import diff_reports, load_report
from minimal_recon.services.report import build_report, write_report

app = typer.Typer()


def save_footprint(username: str, results: List[dict]) -> dict:
    entry = history.save(
        "footprint", username, {"username": username, "results": results}, history.summarize_footprint(results)
    )
    return comparison_with_previous(entry)


def comparison_with_previous(entry: history.HistoryEntry) -> dict:
    earlier = history.previous(entry)
    info: dict = {"id": entry.id, "previous": earlier, "comparison": None}
    if earlier is not None:
        info["comparison"] = history.compare(earlier.id, entry.id)
    return info


def print_saved(info: dict) -> None:
    typer.echo(f"Saved to history as {info['id']}.")
    comparison, earlier = info["comparison"], info["previous"]
    if comparison is None:
        typer.echo("First saved run for this target; later runs will show what changed.")
        return
    changes = comparison["changes"]
    typer.echo(f"Changes since {earlier.created_at}: {len(changes) or 'none'}")
    print_changes(changes)
    for alert in comparison.get("alerts", []):
        typer.echo(f"! {alert}")


def print_changes(changes: List[dict], limit: int = 50) -> None:
    for change in changes[:limit]:
        if change["change"] == "added":
            typer.echo(f"  + {change['path']}: {short(change['new'])}")
        elif change["change"] == "removed":
            typer.echo(f"  - {change['path']}: {short(change['old'])}")
        else:
            typer.echo(f"  ~ {change['path']}: {short(change['old'])} -> {short(change['new'])}")
    if len(changes) > limit:
        typer.echo(f"  ... and {len(changes) - limit} more (see `recon history diff`)")


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
    save: bool = typer.Option(False, "--save", help="Save the report to local history and show changes."),
) -> None:
    """Build a consolidated passive OSINT report."""
    try:
        result = build_report(domain, username or None, email or None, footprint_details=details)
        write_report(result, output, html_output)
        saved = save_report(result) if save else None
    except (httpx.HTTPError, OSError, ValueError) as error:
        handle_error(error)
    if not output and not html_output and not save:
        typer.echo(json.dumps(result, indent=2, sort_keys=True))
    else:
        if output:
            typer.echo(f"JSON report: {output}")
        if html_output:
            typer.echo(f"HTML report: {html_output}")
    if saved is not None:
        print_saved(saved)


def save_report(report: dict) -> dict:
    entry = history.save("report", str(report["target"]), report, history.summarize_report(report))
    return comparison_with_previous(entry)


def parse_interval(text: str) -> int:
    """Turn ``30m``, ``6h`` or ``1d`` into seconds (at least 5 minutes)."""
    match = re.fullmatch(r"\s*(\d+)\s*([mhd])\s*", text.lower())
    if not match:
        raise ValueError("interval must look like 30m, 6h or 1d")
    seconds = int(match.group(1)) * {"m": 60, "h": 3600, "d": 86400}[match.group(2)]
    if seconds < 300:
        raise ValueError("interval must be at least 5 minutes")
    return seconds


@app.command("watch")
def watch_command(
    domain: str,
    username: str = typer.Option("", "--username", help="Also track this username's footprint in the report."),
    details: bool = typer.Option(False, "--details", help="Include profile details for the username."),
    interval: str = typer.Option("6h", "--interval", help="Time between runs, e.g. 30m, 6h or 1d."),
    once: bool = typer.Option(False, "--once", help="Run a single time, e.g. from Windows Task Scheduler or cron."),
) -> None:
    """Re-run the domain report periodically and print what changed since the last run."""
    try:
        seconds = parse_interval(interval)
    except ValueError as error:
        handle_error(error)
    while True:
        stamp = datetime.now().strftime("%Y-%m-%d %H:%M")
        typer.echo(f"[{stamp}] Checking {domain}...")
        try:
            report = build_report(domain, username or None, footprint_details=details)
            print_saved(save_report(report))
        except (httpx.HTTPError, OSError, ValueError) as error:
            if once:
                handle_error(error)
            typer.echo(f"Error: {error}", err=True)
        if once:
            return
        typer.echo(f"Next check in {interval}. Press Ctrl+C to stop.")
        try:
            time.sleep(seconds)
        except KeyboardInterrupt:
            typer.echo("Stopped.")
            return


history_app = typer.Typer(help="Saved footprint runs and reports (stored only on this computer).")
app.add_typer(history_app, name="history")


@history_app.command("list")
def history_list(
    kind: str = typer.Option("", "--kind", help="footprint or report"),
    target: str = typer.Option("", "--target", help="Only targets containing this text."),
    as_json: bool = typer.Option(False, "--json"),
) -> None:
    """List saved runs, newest first."""
    if kind and kind not in history.KINDS:
        handle_error(ValueError("--kind must be footprint or report"))
    entries = history.list_entries(kind or None, target or None)
    if as_json:
        emit([asdict(entry) for entry in entries], as_json=True)
        return
    typer.echo(f"Folder: {history.history_dir()}")
    if not entries:
        typer.echo("No saved runs yet. Use --save on footprint or report, or `recon watch`.")
    for entry in entries:
        typer.echo(f"{entry.id}  {entry.kind:9}  {entry.target}  {short(entry.summary)}")


@history_app.command("show")
def history_show(entry_id: str) -> None:
    """Print one saved run as JSON."""
    try:
        stored = history.load(entry_id)
    except ValueError as error:
        handle_error(error)
    emit({"entry": asdict(stored["entry"]), "data": stored["data"]}, as_json=True)


@history_app.command("diff")
def history_diff(
    new_id: str = typer.Argument(..., help="Saved run to inspect."),
    old_id: Optional[str] = typer.Argument(None, help="Earlier run; defaults to the previous run of the same target."),
    as_json: bool = typer.Option(False, "--json"),
) -> None:
    """Show what changed between two saved runs."""
    try:
        if old_id is None:
            earlier = history.previous(history.load(new_id)["entry"])
            if earlier is None:
                raise ValueError("there is no earlier run of this target to compare with")
            old_id = earlier.id
        comparison = history.compare(old_id, new_id)
    except ValueError as error:
        handle_error(error)
    if as_json:
        emit(comparison, as_json=True)
        return
    old, new = comparison["old"], comparison["new"]
    typer.echo(f"{old['created_at']} -> {new['created_at']} ({new['target']})")
    typer.echo(f"{len(comparison['changes'])} change(s).")
    print_changes(comparison["changes"], limit=len(comparison["changes"]))
    for alert in comparison["alerts"]:
        typer.echo(f"! {alert}")


@history_app.command("delete")
def history_delete(entry_id: str) -> None:
    """Delete one saved run."""
    try:
        deleted = history.delete(entry_id)
    except ValueError as error:
        handle_error(error)
    typer.echo("Deleted." if deleted else "No such entry.")


@history_app.command("clear")
def history_clear(yes: bool = typer.Option(False, "--yes", help="Confirm deleting every saved run.")) -> None:
    """Delete every saved run."""
    if not yes:
        handle_error(ValueError("this deletes all saved runs; repeat with --yes to confirm"))
    typer.echo(f"Deleted {history.clear()} saved run(s).")


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
            typer.echo(f"+ {change.path}: {compact(change.new)}")
        elif change.change == "removed":
            typer.echo(f"- {change.path}: {compact(change.old)}")
        else:
            typer.echo(f"~ {change.path}: {compact(change.old)} -> {compact(change.new)}")
    typer.echo(f"{len(changes)} change(s).")
