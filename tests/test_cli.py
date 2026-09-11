import json

from typer.testing import CliRunner

from minimal_recon import cli
from minimal_recon.services.email import EmailResult
from minimal_recon.services.footprint import FootprintResult
from minimal_recon.services.lookup import LookupResult


runner = CliRunner()


def test_lookup_json_output(monkeypatch):
    monkeypatch.setattr(
        cli,
        "lookup_target",
        lambda target: LookupResult(target, "domain", ("192.0.2.10",)),
    )

    result = runner.invoke(cli.app, ["lookup", "example.test", "--json"])

    assert result.exit_code == 0
    assert json.loads(result.stdout)["addresses"] == ["192.0.2.10"]


def test_dns_json_output(monkeypatch):
    monkeypatch.setattr(cli, "enumerate_dns", lambda domain: {"A": ["192.0.2.10"]})

    result = runner.invoke(cli.app, ["dns", "example.test", "--json"])

    payload = json.loads(result.stdout)
    assert result.exit_code == 0
    assert payload["records"] == {"A": ["192.0.2.10"]}
    assert payload["summary"]["mail_servers"] == []


def test_email_json_output(monkeypatch):
    monkeypatch.setattr(
        cli,
        "analyze_email",
        lambda address: EmailResult(
            address, "analyst", "example.test", True, ["10 mail.example.test."]
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
    assert "username must be" in result.stdout


def test_footprint_text_output_shows_status_and_full_url(monkeypatch):
    monkeypatch.setattr(
        cli,
        "check_username",
        lambda username, delay_seconds: [
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
