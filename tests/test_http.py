import httpx
import pytest
from typer.testing import CliRunner

from minimal_recon import cli
from minimal_recon.commands import checks
from minimal_recon.services import http
from minimal_recon.services.web import WebCheckResult

runner = CliRunner()


@pytest.fixture(autouse=True)
def reset_timeout():
    yield
    http.configure(None)


def test_new_client_identifies_the_tool_and_follows_redirects():
    with http.new_client(timeout=7) as client:
        assert client.headers["user-agent"].startswith("minimal-recon/")
        assert client.follow_redirects is True
        assert client.timeout == httpx.Timeout(7)


def test_configured_timeout_overrides_service_defaults():
    http.configure(42)

    assert http.resolve_timeout(3) == 42
    with http.new_client(timeout=7) as client:
        assert client.timeout == httpx.Timeout(42)


def test_configure_rejects_non_positive_timeout():
    with pytest.raises(ValueError):
        http.configure(0)


def test_with_client_prefers_injected_client():
    sentinel = object()

    assert http.with_client(lambda client: client, sentinel) is sentinel


def test_cli_timeout_option_applies_to_the_command_and_resets(monkeypatch):
    seen = []

    def fake_check_web(url):
        seen.append(http.resolve_timeout(5))
        return WebCheckResult(url, url, 200, {}, (), None, (), "not_detected", {})

    monkeypatch.setattr(checks, "check_web", fake_check_web)

    with_option = runner.invoke(cli.app, ["--timeout", "30", "web", "https://example.test"])
    without_option = runner.invoke(cli.app, ["web", "https://example.test"])

    assert with_option.exit_code == 0 and without_option.exit_code == 0
    assert seen == [30, 5]
