import json

from minimal_recon.services import report


def test_render_html_escapes_report_content():
    content = {"target": "example.test", "value": "<script>alert(1)</script>"}

    rendered = report.render_html(content)

    assert "&lt;script&gt;" in rendered
    assert "<script>alert" not in rendered


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
    monkeypatch.setattr(report, "enumerate_subdomains", lambda domain: {"subdomains": [domain]})
    monkeypatch.setattr(report, "check_web", lambda url: {"url": url, "status_code": 200})
    monkeypatch.setattr(report, "check_username", lambda username, delay_seconds: [username])
    monkeypatch.setattr(report, "analyze_email", lambda address: {"email": address})

    result = report.build_report("example.test", "alice", "alice@example.test")

    assert result["target"] == "example.test"
    assert result["dns"]["records"] == {"A": ["192.0.2.10"]}
    assert result["username_footprint"] == ["alice"]
    assert result["email"] == {"email": "alice@example.test"}


def test_build_report_keeps_other_sections_when_one_check_fails(monkeypatch):
    monkeypatch.setattr(report, "lookup_target", lambda domain: {"target": domain})
    monkeypatch.setattr(report, "enumerate_dns", lambda domain: {"A": []})
    monkeypatch.setattr(report, "summarize_dns", lambda records: {})
    monkeypatch.setattr(report, "enumerate_subdomains", lambda domain: {"subdomains": []})
    monkeypatch.setattr(report, "check_web", lambda url: (_ for _ in ()).throw(OSError("timeout")))

    result = report.build_report("example.test")

    assert result["web"] == {"status": "error", "error": "timeout"}
    assert result["lookup"] == {"target": "example.test"}
    assert result["subdomains"] == {"subdomains": []}
