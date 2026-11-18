import json

from minimal_recon.services import report


def test_render_html_escapes_report_content():
    content = {"target": "example.test", "value": "<script>alert(1)</script>"}

    rendered = report.render_html(content)

    assert "&lt;script&gt;" in rendered
    assert "<script>alert" not in rendered


def test_render_html_contains_summary_cards_and_clickable_urls():
    rendered = report.render_html(
        {
            "target": "example.test",
            "generated_at": "2026-01-01T00:00:00Z",
            "links": {"links_found": 1, "external_links": ["https://external.test/page"]},
        }
    )

    assert 'class="summary"' in rendered
    assert 'href="https://external.test/page"' in rendered
    assert 'target="_blank"' in rendered


def test_write_report_creates_json_and_html(tmp_path):
    data = {"target": "example.test", "items": ["a", "b"]}
    json_path = tmp_path / "report.json"
    html_path = tmp_path / "report.html"

    report.write_report(data, json_path, html_path)

    assert json.loads(json_path.read_text(encoding="utf-8")) == data
    assert "Minimal Recon" in html_path.read_text(encoding="utf-8")


def test_build_report_aggregates_passive_checks(monkeypatch):
    monkeypatch.setattr(report, "lookup_target", lambda domain: {"target": domain})
    monkeypatch.setattr(report, "enumerate_dns", lambda domain: {"A": ["192.0.2.10"]})
    monkeypatch.setattr(report, "lookup_whois", lambda domain: {"domain": domain})
    monkeypatch.setattr(report, "enumerate_archive", lambda domain: {"snapshots": []})
    monkeypatch.setattr(report, "enumerate_subdomains", lambda domain: {"subdomains": [domain]})
    monkeypatch.setattr(report, "check_web", lambda url: {"url": url, "status_code": 200})
    monkeypatch.setattr(report, "geolocate_ip", lambda address: {"ip": address})
    monkeypatch.setattr(report, "check_username", lambda username, delay_seconds, details: [username])
    monkeypatch.setattr(report, "analyze_email", lambda address: {"email": address})

    result = report.build_report("example.test", "alice", "alice@example.test")

    assert result["target"] == "example.test"
    assert result["tool_version"] == "0.1.0"
    assert result["dns"]["records"] == {"A": ["192.0.2.10"]}
    assert result["whois"] == {"domain": "example.test"}
    assert result["archive"] == {"snapshots": []}
    assert result["username_footprint"] == ["alice"]
    assert result["email"] == {"email": "alice@example.test"}


def test_build_report_keeps_other_sections_when_one_check_fails(monkeypatch):
    monkeypatch.setattr(report, "lookup_target", lambda domain: {"target": domain})
    monkeypatch.setattr(report, "enumerate_dns", lambda domain: {"A": []})
    monkeypatch.setattr(report, "summarize_dns", lambda records: {})
    monkeypatch.setattr(report, "enumerate_subdomains", lambda domain: {"subdomains": []})
    monkeypatch.setattr(report, "lookup_whois", lambda domain: {"domain": domain})
    monkeypatch.setattr(report, "enumerate_archive", lambda domain: {"snapshots": []})
    monkeypatch.setattr(report, "check_web", lambda url: (_ for _ in ()).throw(OSError("timeout")))

    result = report.build_report("example.test")

    assert result["web"] == {"status": "error", "error": "timeout"}
    assert result["lookup"] == {"target": "example.test"}
    assert result["subdomains"] == {"subdomains": []}


def test_render_html_keeps_query_strings_in_links():
    rendered = report.render_html(
        {"target": "example.test", "subdomains": {"source": "https://crt.sh/?q=%25.example.test&output=json"}}
    )

    assert 'href="https://crt.sh/?q=%25.example.test&amp;output=json"' in rendered


def test_summary_cards_flag_expired_certificates_and_missing_sections():
    rendered = report.render_html(
        {
            "target": "example.test",
            "tls": {"days_until_expiry": -3},
            "web": {"missing_security_headers": ["x-frame-options", "referrer-policy"]},
        }
    )

    assert '<strong class="bad">EXPIRED</strong>' in rendered
    assert '<strong class="warn">2 missing</strong>' in rendered
    assert '<strong class="warn">N/A</strong>' in rendered


def test_build_report_rejects_invalid_domain_before_any_request():
    import pytest

    with pytest.raises(ValueError):
        report.build_report("https://example.test/path")


def test_render_html_shows_records_as_tables_with_escaped_cells():
    rendered = report.render_html(
        {
            "target": "example.test",
            "public_files": [
                {"path": "/robots.txt", "found": True, "status_code": 200},
                {"path": "/<b>.txt", "found": False, "status_code": None},
            ],
            "dns": {"records": {"A": ["192.0.2.10"]}, "summary": {"mail_servers": []}},
        }
    )

    assert "<th>status code</th>" in rendered
    assert "<td>/robots.txt</td><td>yes</td><td>200</td>" in rendered
    assert "/&lt;b&gt;.txt" in rendered and "/<b>.txt" not in rendered
    assert "<li>192.0.2.10</li>" in rendered
    assert "Raw section data" in rendered


def test_summary_card_flags_certificate_that_failed_validation():
    rendered = report.render_html(
        {"target": "example.test", "tls": {"days_until_expiry": 200, "verified": False}}
    )

    assert '<strong class="bad">INVALID</strong>' in rendered


def test_build_report_runs_sections_concurrently(monkeypatch):
    import threading

    barrier = threading.Barrier(3, timeout=5)

    def wait_for_peers(result):
        def check(*args, **kwargs):
            barrier.wait()  # raises BrokenBarrierError unless three sections overlap
            return result

        return check

    monkeypatch.setattr(report, "lookup_target", wait_for_peers({"addresses": ["192.0.2.10", "192.0.2.11"]}))
    monkeypatch.setattr(report, "lookup_whois", wait_for_peers({"domain": "example.test"}))
    monkeypatch.setattr(report, "enumerate_archive", wait_for_peers({"snapshots": []}))
    for name in ("enumerate_dns", "enumerate_subdomains", "check_web", "inspect_tls", "extract_links",
                 "analyze_anti_spoofing", "discover_public_files"):
        monkeypatch.setattr(report, name, lambda *args, **kwargs: {})
    monkeypatch.setattr(report, "geolocate_ip", lambda address: {"ip": address})

    result = report.build_report("example.test")

    assert result["whois"] == {"domain": "example.test"}
    assert result["archive"] == {"snapshots": []}
    assert result["geoip"] == [{"ip": "192.0.2.10"}, {"ip": "192.0.2.11"}]
