"""Aggregate authorized OSINT checks into portable JSON or HTML reports."""

from dataclasses import asdict, is_dataclass
from datetime import datetime, timezone
import html
import json
from pathlib import Path
import re
from typing import Any, Dict, Optional

from minimal_recon.services.dns import enumerate_dns, summarize_dns
from minimal_recon.services.email import analyze_email
from minimal_recon.services.footprint import check_username
from minimal_recon.services.lookup import lookup_target
from minimal_recon.services.subdomains import enumerate_subdomains
from minimal_recon.services.web import check_web
from minimal_recon.services.geoip import geolocate_ip
from minimal_recon.services.whois import lookup_whois
from minimal_recon.services.archive import enumerate_archive
from minimal_recon.services.tls import inspect_tls
from minimal_recon.services.links import extract_links
from minimal_recon.services.antispoofing import analyze_anti_spoofing
from minimal_recon.services.public_files import discover_public_files
from minimal_recon import __version__


def build_report(
    domain: str,
    username: Optional[str] = None,
    email: Optional[str] = None,
) -> Dict[str, Any]:
    """Collect a read-only report for a domain and optional public identifiers."""
    report: Dict[str, Any] = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "tool_version": __version__,
        "target": domain,
        "lookup": _safe_call(lambda: _serialize(lookup_target(domain))),
        "dns": _safe_call(lambda: _collect_dns(domain)),
        "whois": _safe_call(lambda: _serialize(lookup_whois(domain))),
        "archive": _safe_call(lambda: _serialize(enumerate_archive(domain))),
        "subdomains": _safe_call(lambda: _serialize(enumerate_subdomains(domain))),
        "web": _safe_call(lambda: _serialize(check_web(f"https://{domain}"))),
        "tls": _safe_call(lambda: _serialize(inspect_tls(domain))),
        "links": _safe_call(lambda: _serialize(extract_links(f"https://{domain}"))),
        "anti_spoofing": _safe_call(lambda: _serialize(analyze_anti_spoofing(domain))),
        "public_files": _safe_call(lambda: _serialize(discover_public_files(f"https://{domain}"))),
    }
    report["geoip"] = _safe_call(lambda: _collect_geoip(report["lookup"]))
    if username:
        report["username_footprint"] = _safe_call(
            lambda: _serialize(check_username(username, delay_seconds=0.2))
        )
    if email:
        report["email"] = _safe_call(lambda: _serialize(analyze_email(email)))
    return report


def _collect_dns(domain: str) -> Dict[str, Any]:
    records = enumerate_dns(domain)
    return {"records": records, "summary": summarize_dns(records)}


def _collect_geoip(lookup: Any) -> Any:
    if not isinstance(lookup, dict) or "addresses" not in lookup:
        return {"status": "error", "error": "lookup did not return addresses"}
    return [_serialize(geolocate_ip(address)) for address in lookup["addresses"]]


def _safe_call(operation: Any) -> Any:
    """Return an error object instead of aborting the entire report."""
    try:
        return operation()
    except Exception as error:
        return {"status": "error", "error": str(error)}


def render_html(report: Dict[str, Any]) -> str:
    """Render a dependency-free, escaped and scannable HTML report."""
    title = html.escape(f"Minimal Recon report: {report['target']}")
    sections = []
    for name, value in report.items():
        if name in {"target", "generated_at"}:
            continue
        sections.append(
            f'<section class="panel"><h2>{html.escape(_section_title(name))}</h2>'
            f"{_render_value(value)}</section>"
        )
    summary = _summary_cards(report)
    return (
        "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\">"
        f"<meta name=\"viewport\" content=\"width=device-width,initial-scale=1\"><title>{title}</title>"
        "<style>"
        ":root{color-scheme:dark;--bg:#0b1120;--panel:#111827;--line:#263244;--text:#e5edf7;--muted:#91a0b5;--accent:#67e8f9;--good:#86efac;--warn:#fde68a;--bad:#fca5a5}"
        "*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--text);font:15px system-ui,-apple-system,Segoe UI,sans-serif}"
        ".wrap{max-width:1180px;margin:0 auto;padding:36px 20px 64px}h1{font-size:34px;margin:0 0 8px}h2{font-size:18px;margin:0 0 16px}"
        ".meta{color:var(--muted);margin-bottom:28px}.summary{display:grid;grid-template-columns:repeat(auto-fit,minmax(160px,1fr));gap:12px;margin:18px 0 26px}"
        ".card,.panel{background:var(--panel);border:1px solid var(--line);border-radius:10px}.card{padding:16px}.card strong{display:block;font-size:24px;color:var(--accent)}.card span{color:var(--muted);font-size:12px;text-transform:uppercase;letter-spacing:.06em}"
        ".panel{padding:20px;margin:14px 0}.panel pre{margin:0;white-space:pre-wrap;overflow:auto;color:#cbd5e1;line-height:1.55;font:13px ui-monospace,SFMono-Regular,Consolas,monospace}"
        ".status{display:inline-block;border-radius:999px;padding:3px 9px;font-size:12px;font-weight:700}.good{color:var(--good)}.warn{color:var(--warn)}.bad{color:var(--bad)}"
        "a{color:var(--accent);overflow-wrap:anywhere}details{margin-top:12px}summary{cursor:pointer;color:var(--muted)}"
        "@media(max-width:600px){.wrap{padding:24px 12px 40px}h1{font-size:28px}.panel{padding:15px}}"
        "</style></head><body><main class=\"wrap\"><h1>Minimal Recon</h1>"
        f"<div class=\"meta\"><strong>{title}</strong><br>Generated: {html.escape(str(report.get('generated_at', 'unknown')))}</div>"
        f"<div class=\"summary\">{summary}</div>{''.join(sections)}</main></body></html>"
    )


def _section_title(name: str) -> str:
    return name.replace("_", " ").title()


def _summary_cards(report: Dict[str, Any]) -> str:
    cards = []
    for name in ("dns", "whois", "tls", "anti_spoofing", "web", "subdomains", "links"):
        value = report.get(name)
        if isinstance(value, dict) and value.get("status") == "error":
            metric, style = "ERROR", "bad"
        elif name == "tls" and isinstance(value, dict):
            metric, style = f"{value.get('days_until_expiry', '?')} days", "good"
        elif name == "subdomains" and isinstance(value, dict):
            metric, style = str(len(value.get("subdomains", []))), "good"
        elif name == "links" and isinstance(value, dict):
            metric, style = str(value.get("links_found", 0)), "good"
        else:
            metric, style = "OK", "good"
        cards.append(f'<div class="card"><strong class="{style}">{html.escape(metric)}</strong><span>{html.escape(_section_title(name))}</span></div>')
    return "".join(cards)


def _render_value(value: Any) -> str:
    if isinstance(value, dict) and value.get("status") == "error":
        return f'<p class="status bad">ERROR</p><pre>{html.escape(str(value.get("error", "unknown error")))}</pre>'
    serialized = html.escape(json.dumps(value, indent=2, sort_keys=True, default=str))
    return f"<details open><summary>Raw section data</summary><pre>{_linkify(serialized)}</pre></details>"


def _linkify(escaped_text: str) -> str:
    return re.sub(
        r"(https?://[^\s<&]+)",
        r'<a href="\1" target="_blank" rel="noopener noreferrer">\1</a>',
        escaped_text,
    )


def write_report(report: Dict[str, Any], output: Optional[Path] = None, html_output: Optional[Path] = None) -> None:
    """Write selected report formats to disk."""
    if output:
        output.write_text(json.dumps(report, indent=2, sort_keys=True), encoding="utf-8")
    if html_output:
        html_output.write_text(render_html(report), encoding="utf-8")


def _serialize(value: Any) -> Any:
    if is_dataclass(value):
        return asdict(value)
    if isinstance(value, list):
        return [_serialize(item) for item in value]
    return value
