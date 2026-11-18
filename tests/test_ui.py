import json
import threading

import httpx
import pytest

from minimal_recon.services import footprint
from minimal_recon.services.footprint import FootprintResult
from minimal_recon.ui import server as ui


@pytest.fixture
def running():
    instance = ui.UiServer(0, token="test-token")
    thread = threading.Thread(target=instance.serve_forever, kwargs={"poll_interval": 0.05}, daemon=True)
    thread.start()
    with httpx.Client(base_url=instance.url, timeout=5) as client:
        yield instance, client
    instance.shutdown()
    instance.server_close()


def post(client, path, payload=None, token="test-token", **headers):
    if token is not None:
        headers["X-Recon-Token"] = token
    return client.post(path, json=payload or {}, headers=headers)


def test_page_is_served_with_token_and_security_headers(running):
    _, client = running

    page = client.get("/")
    script = client.get("/app.js")

    assert page.status_code == 200
    assert 'content="test-token"' in page.text
    assert "script-src 'self'" in page.headers["content-security-policy"]
    assert page.headers["x-content-type-options"] == "nosniff"
    assert script.headers["content-type"].startswith("text/javascript")
    assert "textContent" in script.text


def test_api_requires_token(running):
    _, client = running

    assert post(client, "/api/sites", token=None).status_code == 403
    assert post(client, "/api/sites", token="wrong").status_code == 403
    assert post(client, "/api/sites").status_code == 200


def test_foreign_host_header_is_rejected(running):
    _, client = running

    assert client.get("/", headers={"Host": "attacker.test"}).status_code == 403
    assert post(client, "/api/sites", Host="attacker.test:8765").status_code == 403


def test_sites_lists_registry(running):
    _, client = running

    data = post(client, "/api/sites").json()

    assert {"name": "instagram", "label": "Instagram", "source": "html"} in data["sites"]
    assert data["version"]


def test_footprint_endpoint_runs_each_username(running, monkeypatch):
    calls = []

    def fake_check(username, sites, delay_seconds, details, audit_token, on_result=None):
        calls.append((username, sorted(sites), details))
        return [FootprintResult("github", f"https://github.com/{username}", True, 200, "http_status_200", "found")]

    monkeypatch.setattr(footprint, "check_username", fake_check)
    _, client = running

    response = post(
        client, "/api/footprint", {"usernames": "alice, bob alice", "details": True, "sites": ["github", "x"]}
    )

    assert response.status_code == 200
    assert [run["username"] for run in response.json()["runs"]] == ["alice", "bob"]
    assert calls[0] == ("alice", ["github", "x"], True)
    assert response.json()["runs"][0]["results"][0]["url"] == "https://github.com/alice"


def test_footprint_adds_mastodon_servers(running, monkeypatch):
    seen = {}
    monkeypatch.setattr(
        footprint, "check_username", lambda username, sites, **kwargs: seen.update(sites) or []
    )
    _, client = running

    post(client, "/api/footprint", {"usernames": ["alice"], "mastodon": "fosstodon.org"})

    assert "mastodon@fosstodon.org" in seen


@pytest.mark.parametrize(
    "payload, message",
    [
        ({"usernames": ""}, "at least one username"),
        ({"usernames": "bad/name"}, "username must be"),
        ({"usernames": [f"user{i}" for i in range(11)]}, "at most 10"),
        ({"usernames": "alice", "sites": ["nosuchsite"]}, "unknown site"),
        ({"usernames": 42}, "list of strings"),
    ],
)
def test_footprint_rejects_bad_input(running, payload, message):
    _, client = running

    response = post(client, "/api/footprint", payload)

    assert response.status_code == 400
    assert message in response.json()["error"]


def test_network_errors_become_bad_gateway(running, monkeypatch):
    def failing(*args, **kwargs):
        raise httpx.ConnectError("offline")

    monkeypatch.setattr(footprint, "check_username", failing)
    _, client = running

    response = post(client, "/api/footprint", {"usernames": "alice"})

    assert response.status_code == 502
    assert "network error" in response.json()["error"]


def test_invalid_json_body_is_refused(running):
    _, client = running

    response = client.post(
        "/api/sites", content=b"[1, 2]", headers={"X-Recon-Token": "test-token", "Content-Type": "application/json"}
    )

    assert response.status_code == 400


def test_report_endpoint_returns_json_and_html(running, monkeypatch):
    from minimal_recon.services import report

    monkeypatch.setattr(
        report,
        "build_report",
        lambda domain, username, footprint_details: {"target": domain, "generated_at": "now", "dns": {"A": []}},
    )
    _, client = running

    data = post(client, "/api/report", {"domain": "example.test"}).json()

    assert data["report"]["target"] == "example.test"
    assert "<!doctype html>" in data["html"]


def test_search_links_endpoint(running):
    _, client = running

    data = post(client, "/api/search-links", {"username": "alice"}).json()

    assert data["search_engines"]["google"].endswith("%22alice%22")


def tool(client, name, args=None):
    return post(client, "/api/tool", {"tool": name, "args": args or {}})


def test_every_tool_in_the_page_exists_on_the_server(running):
    import re

    _, client = running
    script = client.get("/app.js").text
    # "email", "web" and "verify" are both a tab and a tool; these ids are only tabs or special views.
    tab_only_ids = {"domain", "ip", "file", "compare", "report"}
    page_tools = set(re.findall(r'\bid: "([a-z_]+)"', script)) - tab_only_ids

    assert page_tools <= set(ui.TOOLS)
    assert set(ui.TOOLS) <= page_tools


def test_dns_tool_returns_records_and_summary(running, monkeypatch):
    from minimal_recon.services import dns

    monkeypatch.setattr(dns, "enumerate_dns", lambda domain: {"NS": ["ns1.cloudflare.com."]})
    _, client = running

    data = tool(client, "dns", {"domain": "example.test"}).json()

    assert data["tool"] == "dns"
    assert data["result"]["summary"]["nameserver_providers"] == ["Cloudflare"]


def test_dataclass_results_are_serialized(running, monkeypatch):
    from minimal_recon.services import lookup
    from minimal_recon.services.lookup import LookupResult

    monkeypatch.setattr(lookup, "lookup_target", lambda target: LookupResult(target, "domain", ("192.0.2.1",)))
    _, client = running

    data = tool(client, "lookup", {"target": "example.test"}).json()

    assert data["result"] == {"target": "example.test", "target_type": "domain", "addresses": ["192.0.2.1"],
                              "reverse_name": None}


def test_tool_input_errors_are_bad_requests(running):
    _, client = running

    assert tool(client, "nosuchtool").status_code == 400
    assert "enter" in tool(client, "dns", {}).json()["error"]
    assert tool(client, "dns", {"domain": "https://example.test/x"}).status_code == 400
    assert "whole number" in tool(client, "tls", {"hostname": "example.test", "port": "abc"}).json()["error"]


def test_metadata_tool_reads_uploaded_image(running, tmp_path):
    import base64
    import io

    from PIL import Image

    buffer = io.BytesIO()
    Image.new("RGB", (3, 2)).save(buffer, format="PNG")
    _, client = running

    data = tool(client, "metadata", {"name": "../photo.png", "data": base64.b64encode(buffer.getvalue()).decode()})

    result = data.json()["result"]
    assert result["name"] == "photo.png"
    assert (result["width"], result["height"], result["image_format"]) == (3, 2, "PNG")


def test_metadata_tool_rejects_undecodable_upload(running):
    _, client = running

    assert tool(client, "metadata", {"name": "x.bin", "data": "not base64!"}).status_code == 400


def test_diff_tool_compares_reports(running):
    _, client = running
    old = {"target": "example.test", "generated_at": "1", "subdomains": {"subdomains": ["a.example.test"]}}
    new = {"target": "example.test", "generated_at": "2", "subdomains": {"subdomains": ["b.example.test"]}}

    result = tool(client, "diff", {"old": old, "new": new}).json()["result"]

    added = {"path": "subdomains.subdomains", "change": "added", "old": None, "new": "b.example.test"}
    assert added in result["changes"]
    assert tool(client, "diff", {"old": [1], "new": new}).status_code == 400


def test_verify_tools(running, monkeypatch):
    from minimal_recon.services import verification
    from minimal_recon.services.verification import VerificationResult

    monkeypatch.setattr(
        verification,
        "verify_urls",
        lambda urls, token: [VerificationResult(url, True, 200, "exact verification token found") for url in urls],
    )
    _, client = running

    token = tool(client, "verify_token").json()["result"]["token"]
    checked = tool(client, "verify", {"token": token, "urls": "https://a.test/me\nhttps://b.test/me"}).json()

    assert token.startswith("minimal-recon-verify-")
    assert [item["url"] for item in checked["result"]] == ["https://a.test/me", "https://b.test/me"]


def test_api_key_is_passed_through_not_stored(running, monkeypatch):
    from minimal_recon.services import shodan

    seen = {}
    monkeypatch.setattr(shodan, "lookup_host", lambda ip, api_key=None: seen.update(api_key=api_key) or {"ip": ip})
    _, client = running

    tool(client, "shodan", {"ip": "192.0.2.1", "api_key": " secret "})

    assert seen == {"api_key": "secret"}
    assert "secret" not in client.get("/").text


def test_unexpected_errors_keep_the_server_running(running, monkeypatch):
    from minimal_recon.services import whois

    monkeypatch.setattr(whois, "lookup_whois", lambda domain: 1 / 0)
    _, client = running

    response = tool(client, "whois", {"domain": "example.test"})

    assert response.status_code == 500
    assert "unexpected error" in response.json()["error"]
    assert client.get("/").status_code == 200


def test_small_body_limit_applies_to_other_routes(running):
    _, client = running

    response = post(client, "/api/footprint", {"usernames": "a" * 70_000})

    assert response.status_code == 400
    assert "too large" in response.json()["error"]


@pytest.fixture
def history_home(tmp_path, monkeypatch):
    monkeypatch.setenv("MINIMAL_RECON_HOME", str(tmp_path))
    return tmp_path


def stream_events(client, payload):
    response = post(client, "/api/footprint/stream", payload)
    return response, [json.loads(line) for line in response.text.splitlines() if line.strip()]


def fake_stream_check(username, sites, delay_seconds, details, audit_token, on_result=None):
    results = [
        FootprintResult("x", f"https://x.test/{username}", False, 404, "http_status_404", "not_found"),
        FootprintResult("github", f"https://github.com/{username}", True, 200, "http_status_200", "found"),
    ]
    for result in reversed(results):  # completion order differs from registry order
        on_result(result)
    return results


def test_stream_sends_each_result_then_ordered_results(running, monkeypatch, history_home):
    monkeypatch.setattr(footprint, "check_username", fake_stream_check)
    _, client = running

    response, events = stream_events(client, {"usernames": "alice", "save": True})

    assert response.headers["content-type"].startswith("application/x-ndjson")
    assert [event["type"] for event in events] == ["start", "result", "result", "done", "end"]
    assert [event["result"]["site"] for event in events if event["type"] == "result"] == ["github", "x"]
    done = events[3]
    assert [result["site"] for result in done["results"]] == ["x", "github"]
    assert done["history"]["previous_id"] is None


def test_stream_reports_changes_since_previous_saved_run(running, monkeypatch, history_home):
    monkeypatch.setattr(footprint, "check_username", fake_stream_check)
    _, client = running

    stream_events(client, {"usernames": "alice", "save": True})
    _, events = stream_events(client, {"usernames": "alice", "save": True})

    info = [event for event in events if event["type"] == "done"][0]["history"]
    assert info["previous_id"] and info["changes"] == 0


def test_stream_without_save_writes_nothing(running, monkeypatch, history_home):
    monkeypatch.setattr(footprint, "check_username", fake_stream_check)
    _, client = running

    _, events = stream_events(client, {"usernames": "alice"})

    assert "history" not in [event for event in events if event["type"] == "done"][0]
    assert not (history_home / "history").exists()


def test_stream_rejects_bad_input_before_streaming(running):
    _, client = running

    response = post(client, "/api/footprint/stream", {"usernames": "bad/name"})

    assert response.status_code == 400
    assert "username must be" in response.json()["error"]


def test_stream_turns_failures_into_error_events(running, monkeypatch):
    def failing(*args, **kwargs):
        raise RuntimeError("boom")

    monkeypatch.setattr(footprint, "check_username", failing)
    _, client = running

    _, events = stream_events(client, {"usernames": "alice"})

    assert events[-2] == {"type": "error", "username": "alice", "error": "boom"}
    assert events[-1] == {"type": "end"}


def test_history_endpoints(running, history_home):
    from minimal_recon.services import history

    old = history.save("report", "example.test", {"target": "example.test", "generated_at": "1", "dns": {"A": ["1"]}})
    new = history.save("report", "example.test", {"target": "example.test", "generated_at": "2", "dns": {"A": ["2"]}})
    _, client = running

    listing = post(client, "/api/history/list", {"kind": "report"}).json()
    entry = post(client, "/api/history/get", {"id": new.id}).json()
    versus_previous = post(client, "/api/history/compare", {"new_id": new.id}).json()
    no_previous = post(client, "/api/history/compare", {"new_id": old.id})
    deleted = post(client, "/api/history/delete", {"id": old.id}).json()

    assert [item["id"] for item in listing["entries"]] == [new.id, old.id]
    assert listing["folder"].startswith(str(history_home))
    assert "<!doctype html>" in entry["html"]
    assert {"path": "dns.A", "change": "added", "old": None, "new": "2"} in versus_previous["changes"]
    assert no_previous.status_code == 400
    assert deleted == {"deleted": True}
    assert post(client, "/api/history/get", {"id": "../../etc/passwd"}).status_code == 400


def test_report_endpoint_saves_when_asked(running, monkeypatch, history_home):
    from minimal_recon.services import report

    monkeypatch.setattr(
        report, "build_report", lambda domain, username, footprint_details: {"target": domain, "generated_at": "now"}
    )
    _, client = running

    first = post(client, "/api/report", {"domain": "example.test", "save": True}).json()
    second = post(client, "/api/report", {"domain": "example.test", "save": True}).json()

    assert first["history"]["previous_id"] is None
    assert second["history"]["previous_id"] == first["history"]["id"]


def test_port_cannot_be_shared_with_a_second_server():
    first = ui.UiServer(0, token="a")
    try:
        with pytest.raises(OSError):
            ui.UiServer(first.server_port, token="b")
    finally:
        first.server_close()
