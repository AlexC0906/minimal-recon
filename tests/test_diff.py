import json

import pytest
from typer.testing import CliRunner

from minimal_recon import cli
from minimal_recon.services.diff import Change, diff_reports, load_report

runner = CliRunner()

OLD = {
    "target": "example.test",
    "generated_at": "2026-01-01T00:00:00+00:00",
    "dns": {"records": {"A": ["192.0.2.10"], "MX": ["10 mail.example.test."]}},
    "subdomains": {"subdomains": ["api.example.test", "old.example.test"]},
    "tls": {"days_until_expiry": 80, "issuer": "commonName=CA One"},
    "public_files": [
        {"path": "/robots.txt", "found": True, "status_code": 200},
        {"path": "/security.txt", "found": False, "status_code": 404},
    ],
    "username_footprint": [{"site": "github", "state": "found", "checked_at": "2026-01-01T00:00:01+00:00"}],
}

NEW = {
    "target": "example.test",
    "generated_at": "2026-02-01T00:00:00+00:00",
    "dns": {"records": {"A": ["192.0.2.20"], "MX": ["10 mail.example.test."]}},
    "subdomains": {"subdomains": ["api.example.test", "new.example.test"]},
    "tls": {"days_until_expiry": 49, "issuer": "commonName=CA One"},
    "public_files": [
        {"path": "/security.txt", "found": True, "status_code": 200},
        {"path": "/robots.txt", "found": True, "status_code": 200},
    ],
    "username_footprint": [{"site": "github", "state": "found", "checked_at": "2026-02-01T00:00:01+00:00"}],
    "email": {"valid": True},
}


def test_diff_reports_lists_added_removed_and_changed_values():
    changes = diff_reports(OLD, NEW)

    assert Change("dns.records.A", "added", new="192.0.2.20") in changes
    assert Change("dns.records.A", "removed", old="192.0.2.10") in changes
    assert Change("subdomains.subdomains", "added", new="new.example.test") in changes
    assert Change("subdomains.subdomains", "removed", old="old.example.test") in changes
    assert Change("tls.days_until_expiry", "changed", 80, 49) in changes
    assert Change("email", "added", new={"valid": True}) in changes


def test_diff_reports_matches_records_by_identity_not_position():
    changes = diff_reports(OLD, NEW)

    assert Change("public_files./security.txt.found", "changed", False, True) in changes
    assert not any(change.path.startswith("public_files./robots.txt") for change in changes)


def test_diff_reports_ignores_run_timestamps():
    paths = [change.path for change in diff_reports(OLD, NEW)]

    assert "generated_at" not in paths
    assert not any("checked_at" in path for path in paths)
    assert diff_reports(OLD, dict(OLD, generated_at="later")) == []


def test_load_report_rejects_files_that_are_not_reports(tmp_path):
    not_json = tmp_path / "broken.json"
    not_json.write_text("{", encoding="utf-8")
    not_report = tmp_path / "list.json"
    not_report.write_text("[1, 2]", encoding="utf-8")

    with pytest.raises(ValueError, match="not valid JSON"):
        load_report(not_json)
    with pytest.raises(ValueError, match="not a Minimal Recon report"):
        load_report(not_report)


def test_diff_command_prints_changes_and_json(tmp_path):
    old_path = tmp_path / "old.json"
    new_path = tmp_path / "new.json"
    old_path.write_text(json.dumps(OLD), encoding="utf-8")
    new_path.write_text(json.dumps(NEW), encoding="utf-8")

    text = runner.invoke(cli.app, ["diff", str(old_path), str(new_path)])
    as_json = runner.invoke(cli.app, ["diff", str(old_path), str(new_path), "--json"])

    assert text.exit_code == 0
    assert "+ subdomains.subdomains: new.example.test" in text.stdout
    assert "- subdomains.subdomains: old.example.test" in text.stdout
    assert "~ tls.days_until_expiry: 80 -> 49" in text.stdout
    payload = json.loads(as_json.stdout)
    assert payload["old_generated_at"] == OLD["generated_at"]
    assert {"path": "tls.days_until_expiry", "change": "changed", "old": 80, "new": 49} in payload["changes"]


def test_diff_command_reports_identical_reports_and_missing_files(tmp_path):
    path = tmp_path / "report.json"
    path.write_text(json.dumps(OLD), encoding="utf-8")

    same = runner.invoke(cli.app, ["diff", str(path), str(path)])
    missing = runner.invoke(cli.app, ["diff", str(path), str(tmp_path / "absent.json")])

    assert "No changes." in same.stdout
    assert missing.exit_code == 1
    assert "Error:" in missing.output
