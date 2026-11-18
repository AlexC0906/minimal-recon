import json

import httpx
import pytest
from typer.testing import CliRunner

from minimal_recon import __version__, cli
from minimal_recon.commands import checks, reports
from minimal_recon.commands import footprint as footprint_commands
from minimal_recon.services.email import EmailResult
from minimal_recon.services.footprint import FootprintResult
from minimal_recon.services.lookup import LookupResult

runner = CliRunner()


def test_lookup_json_output(monkeypatch):
    monkeypatch.setattr(
        checks,
        "lookup_target",
        lambda target: LookupResult(target, "domain", ("192.0.2.10",)),
    )

    result = runner.invoke(cli.app, ["lookup", "example.test", "--json"])

    assert result.exit_code == 0
    assert json.loads(result.stdout)["addresses"] == ["192.0.2.10"]


def test_version_option_shows_tool_version():
    result = runner.invoke(cli.app, ["--version"])

    assert result.exit_code == 0
    assert result.stdout.strip() == f"Minimal Recon {__version__}"


def test_dns_json_output(monkeypatch):
    monkeypatch.setattr(checks, "enumerate_dns", lambda domain: {"A": ["192.0.2.10"]})

    result = runner.invoke(cli.app, ["dns", "example.test", "--json"])

    payload = json.loads(result.stdout)
    assert result.exit_code == 0
    assert payload["records"] == {"A": ["192.0.2.10"]}
    assert payload["summary"]["mail_servers"] == []


def test_email_json_output(monkeypatch):
    monkeypatch.setattr(
        checks,
        "analyze_email",
        lambda address: EmailResult(
            address,
            "analyst",
            "example.test",
            True,
            ["10 mail.example.test."],
            True,
            False,
            False,
            [],
        ),
    )

    result = runner.invoke(cli.app, ["email", "analyst@example.test", "--json"])

    assert result.exit_code == 0
    assert json.loads(result.stdout)["mx_records"] == ["10 mail.example.test."]


def test_metadata_command_reads_local_file(tmp_path):
    sample = tmp_path / "sample.txt"
    sample.write_text("local evidence", encoding="utf-8")

    result = runner.invoke(cli.app, ["metadata", str(sample), "--json"])

    assert result.exit_code == 0
    assert json.loads(result.stdout)["name"] == "sample.txt"


def test_footprint_rejects_invalid_username():
    result = runner.invoke(cli.app, ["footprint", "bad user"])

    assert result.exit_code == 1
    assert "username must be" in result.output


def test_footprint_text_output_shows_status_and_full_url(monkeypatch):
    monkeypatch.setattr(
        footprint_commands,
        "check_username",
        lambda username, sites, delay_seconds, details, audit_token: [
            FootprintResult(
                "instagram",
                "https://www.instagram.com/alice/",
                True,
                200,
                "profile_content_signal",
                "found",
            )
        ],
    )

    result = runner.invoke(cli.app, ["footprint", "alice"])

    assert result.exit_code == 0
    assert "instagram: FOUND https://www.instagram.com/alice/" in result.stdout


def test_web_timeout_has_short_network_error(monkeypatch):
    monkeypatch.setattr(checks, "check_web", lambda url: (_ for _ in ()).throw(httpx.ReadTimeout("timed out")))

    result = runner.invoke(cli.app, ["web", "https://example.test"])

    assert result.exit_code == 1
    assert "Error: network timeout" in result.output


def test_subdomains_network_error_has_short_message(monkeypatch):
    monkeypatch.setattr(
        checks, "enumerate_subdomains", lambda domain: (_ for _ in ()).throw(httpx.ConnectError("boom"))
    )

    result = runner.invoke(cli.app, ["subdomains", "example.test"])

    assert result.exit_code == 1
    assert "Error: network connection failed" in result.output


def test_footprint_rejects_unknown_site_filter():
    result = runner.invoke(cli.app, ["footprint", "alice", "--site", "nosuchsite"])

    assert result.exit_code == 1
    assert "unknown site(s): nosuchsite" in result.output


def test_footprint_requires_username_without_self_test():
    result = runner.invoke(cli.app, ["footprint"])

    assert result.exit_code == 1
    assert "username is required" in result.output


def test_footprint_self_test_output(monkeypatch):
    monkeypatch.setattr(
        footprint_commands,
        "run_self_test",
        lambda registry: [
            {"site": "github", "present": "found", "absent": "not_found", "status": "ok"},
            {"site": "x", "present": "found", "absent": "found", "status": "broken"},
        ],
    )

    result = runner.invoke(cli.app, ["footprint", "--self-test"])

    assert result.exit_code == 0
    assert "x: BROKEN (present=found, absent=found)" in result.stdout
    assert "1 of 2 rules not broken." in result.stdout


def test_footprint_details_are_printed(monkeypatch):
    monkeypatch.setattr(
        footprint_commands,
        "check_username",
        lambda username, sites, delay_seconds, details, audit_token: [
            FootprintResult(
                "devto",
                "https://dev.to/alice",
                True,
                200,
                "http_status_200",
                "found",
                confidence="confirmed",
                profile={"display_name": "Alice", "declared_accounts": {"x": "alice_x"}},
            )
        ],
    )

    result = runner.invoke(cli.app, ["footprint", "alice", "--details"])

    assert result.exit_code == 0
    assert "  Name: Alice" in result.stdout
    assert "  Self-declared accounts (not verified): x: alice_x" in result.stdout


def test_footprint_checks_several_usernames(monkeypatch):
    calls = []

    def fake_check(username, sites, delay_seconds, details, audit_token):
        calls.append(username)
        return [FootprintResult("github", f"https://github.com/{username}", True, 200, "http_status_200", "found")]

    monkeypatch.setattr(footprint_commands, "check_username", fake_check)

    text = runner.invoke(cli.app, ["footprint", "alice", "bob", "alice"])
    as_json = runner.invoke(cli.app, ["footprint", "alice", "bob", "--json"])

    assert text.exit_code == 0
    assert "=== alice" in text.stdout and "=== bob" in text.stdout
    assert calls[:2] == ["alice", "bob"] and len(calls) == 4
    assert [entry["username"] for entry in json.loads(as_json.stdout)] == ["alice", "bob"]


def test_search_links_command():
    result = runner.invoke(cli.app, ["search-links", "alice", "--json"])

    payload = json.loads(result.stdout)
    assert result.exit_code == 0
    assert payload["search_engines"]["duckduckgo"] == "https://duckduckgo.com/?q=%22alice%22"
    assert "github" in payload["archived_profiles"]


def test_footprint_found_only_hides_other_states(monkeypatch):
    monkeypatch.setattr(
        footprint_commands,
        "check_username",
        lambda username, sites, delay_seconds, details, audit_token: [
            FootprintResult("github", "https://github.com/alice", False, 404, "http_status_404", "not_found"),
            FootprintResult("instagram", "https://www.instagram.com/alice/", True, 200, "profile_marker", "found"),
            FootprintResult("youtube", "https://www.youtube.com/@alice", False, 200, "consent", "unknown"),
        ],
    )

    text = runner.invoke(cli.app, ["footprint", "alice", "--found-only"])
    as_json = runner.invoke(cli.app, ["footprint", "alice", "--found-only", "--json"])

    assert text.exit_code == 0
    assert "instagram: FOUND" in text.stdout
    assert "github" not in text.stdout and "youtube" not in text.stdout
    assert "Found on 1 of 3 sites; 1 could not be determined." in text.stdout
    assert [result["site"] for result in json.loads(as_json.stdout)] == ["instagram"]


def test_footprint_save_reports_changes_between_runs(monkeypatch, tmp_path):
    monkeypatch.setenv("MINIMAL_RECON_HOME", str(tmp_path))
    states = iter(["not_found", "found"])

    def fake_check(username, sites, delay_seconds, details, audit_token):
        state = next(states)
        return [FootprintResult("github", f"https://github.com/{username}", state == "found", 200, "x", state)]

    monkeypatch.setattr(footprint_commands, "check_username", fake_check)

    first = runner.invoke(cli.app, ["footprint", "alice", "--save"])
    second = runner.invoke(cli.app, ["footprint", "alice", "--save"])
    listing = runner.invoke(cli.app, ["history", "list"])

    assert "First saved run for this target" in first.stdout
    assert "Changes since" in second.stdout
    assert "~ results.github.state: not_found -> found" in second.stdout
    assert sum(1 for line in listing.stdout.splitlines() if "  footprint  alice" in line) == 2


def test_watch_once_saves_and_alerts(monkeypatch, tmp_path):
    monkeypatch.setenv("MINIMAL_RECON_HOME", str(tmp_path))
    first_report = {"target": "example.test", "generated_at": "1", "subdomains": {"subdomains": ["a.example.test"]}}
    second_report = {
        "target": "example.test",
        "generated_at": "2",
        "subdomains": {"subdomains": ["a.example.test", "new.example.test"]},
        "tls": {"days_until_expiry": 5, "verified": True},
    }
    snapshots = iter([first_report, second_report])
    monkeypatch.setattr(reports, "build_report", lambda domain, username, footprint_details: next(snapshots))

    first = runner.invoke(cli.app, ["watch", "example.test", "--once"])
    second = runner.invoke(cli.app, ["watch", "example.test", "--once"])

    assert first.exit_code == 0 and "First saved run" in first.stdout
    assert "! New subdomain: new.example.test" in second.stdout
    assert "! TLS certificate expires in 5 day(s)" in second.stdout


def test_history_diff_show_and_clear(monkeypatch, tmp_path):
    from minimal_recon.services import history

    monkeypatch.setenv("MINIMAL_RECON_HOME", str(tmp_path))
    old = history.save("report", "example.test", {"target": "example.test", "dns": {"A": ["1"]}})
    new = history.save("report", "example.test", {"target": "example.test", "dns": {"A": ["2"]}})

    diff = runner.invoke(cli.app, ["history", "diff", new.id])
    shown = runner.invoke(cli.app, ["history", "show", old.id])
    refused = runner.invoke(cli.app, ["history", "clear"])
    cleared = runner.invoke(cli.app, ["history", "clear", "--yes"])

    assert "+ dns.A: 2" in diff.stdout and "- dns.A: 1" in diff.stdout
    assert json.loads(shown.stdout)["data"]["dns"] == {"A": ["1"]}
    assert refused.exit_code == 1
    assert "Deleted 2 saved run(s)." in cleared.stdout


@pytest.mark.parametrize("text, seconds", [("30m", 1800), ("6h", 21600), ("1d", 86400), (" 2H ", 7200)])
def test_parse_interval(text, seconds):
    assert reports.parse_interval(text) == seconds


@pytest.mark.parametrize("text", ["1m", "abc", "10s", ""])
def test_parse_interval_rejects_bad_values(text):
    with pytest.raises(ValueError):
        reports.parse_interval(text)
