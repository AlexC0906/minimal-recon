"""Aggregate authorized OSINT checks into portable JSON or HTML reports."""

from concurrent.futures import ThreadPoolExecutor
from dataclasses import asdict, is_dataclass
from datetime import datetime, timezone
import html
import json
from pathlib import Path
import re
from typing import Any, Callable, Dict, List, Optional

from minimal_recon import __version__
from minimal_recon.services.antispoofing import analyze_anti_spoofing
from minimal_recon.services.archive import enumerate_archive
from minimal_recon.services.dns import enumerate_dns, normalize_domain, summarize_dns
from minimal_recon.services.email import analyze_email
from minimal_recon.services.footprint import check_username
from minimal_recon.services.geoip import geolocate_ip
from minimal_recon.services.links import extract_links
from minimal_recon.services.lookup import lookup_target
from minimal_recon.services.public_files import discover_public_files
from minimal_recon.services.subdomains import enumerate_subdomains
from minimal_recon.services.tls import inspect_tls
from minimal_recon.services.web import check_web
from minimal_recon.services.whois import lookup_whois

# Sections talk to different hosts, so running them side by side adds no load
# on any single service; the report takes as long as its slowest section.
MAX_WORKERS = 8

_METADATA_KEYS = frozenset({"target", "generated_at", "tool_version"})


def build_report(
    domain: str,
    username: Optional[str] = None,
    email: Optional[str] = None,
    footprint_details: bool = False,
) -> Dict[str, Any]:
    """Collect a read-only report for a domain and optional public identifiers."""
    domain = normalize_domain(domain.lower())
    url = f"https://{domain}"
    tasks: Dict[str, Callable[[], Any]] = {
        "lookup": lambda: _serialize(lookup_target(domain)),
        "dns": lambda: _collect_dns(domain),
        "whois": lambda: _serialize(lookup_whois(domain)),
        "archive": lambda: _serialize(enumerate_archive(domain)),
        "subdomains": lambda: _serialize(enumerate_subdomains(domain)),
        "web": lambda: _serialize(check_web(url)),
        "tls": lambda: _serialize(inspect_tls(domain)),
        "links": lambda: _serialize(extract_links(url)),
        "anti_spoofing": lambda: _serialize(analyze_anti_spoofing(domain)),
        "public_files": lambda: _serialize(discover_public_files(url)),
    }
    if username:
        tasks["username_footprint"] = lambda: _serialize(
            check_username(username, delay_seconds=0.2, details=footprint_details)
        )
    if email:
        tasks["email"] = lambda: _serialize(analyze_email(email))

    report: Dict[str, Any] = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "tool_version": __version__,
        "target": domain,
    }
    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as pool:
        futures = {name: pool.submit(_safe_call, operation) for name, operation in tasks.items()}
        for name, future in futures.items():
            report[name] = future.result()
        report["geoip"] = _safe_call(lambda: _collect_geoip(report["lookup"], pool))
    return report


def _collect_dns(domain: str) -> Dict[str, Any]:
    records = enumerate_dns(domain)
    return {"records": records, "summary": summarize_dns(records)}


def _collect_geoip(lookup: Any, pool: ThreadPoolExecutor) -> Any:
    if not isinstance(lookup, dict) or "addresses" not in lookup:
        return {"status": "error", "error": "lookup did not return addresses"}
    return list(pool.map(lambda address: _serialize(geolocate_ip(address)), lookup["addresses"]))


def _safe_call(operation: Callable[[], Any]) -> Any:
    """Return an error object instead of aborting the entire report."""
    try:
        return operation()
    except Exception as error:
        return {"status": "error", "error": str(error)}


def _is_error(value: Any) -> bool:
    return isinstance(value, dict) and value.get("status") == "error"


def render_html(report: Dict[str, Any]) -> str:
    """Render a dependency-free, escaped and scannable HTML report."""
    title = html.escape(f"Minimal Recon report: {report['target']}")
    sections = []
    for name, value in report.items():
        if name in _METADATA_KEYS:
            continue
        sections.append(
            f'<section class="panel"><h2>{html.escape(_section_title(name))}</h2>'
            f"{_render_value(value)}</section>"
        )
    summary = _summary_cards(report)
    return (
        "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\">"
        f"<meta name=\"viewport\" content=\"width=device-width,initial-scale=1\"><title>{title}</title>"
        f"<style>{_STYLE}</style></head><body><main class=\"wrap\"><h1>Minimal Recon</h1>"
        f"<div class=\"meta\"><strong>{title}</strong><br>"
        f"Generated: {html.escape(str(report.get('generated_at', 'unknown')))}"
        f" &middot; Tool version: {html.escape(str(report.get('tool_version', 'unknown')))}</div>"
        f"<div class=\"summary\">{summary}</div>{''.join(sections)}</main></body></html>"
    )


_STYLE = "".join(
    (
        ":root{color-scheme:dark;--bg:#0b1120;--panel:#111827;--line:#263244;--text:#e5edf7;",
        "--muted:#91a0b5;--accent:#67e8f9;--good:#86efac;--warn:#fde68a;--bad:#fca5a5}",
        "*{box-sizing:border-box}",
        "body{margin:0;background:var(--bg);color:var(--text);font:15px system-ui,-apple-system,Segoe UI,sans-serif}",
        ".wrap{max-width:1180px;margin:0 auto;padding:36px 20px 64px}",
        "h1{font-size:34px;margin:0 0 8px}h2{font-size:18px;margin:0 0 16px}",
        ".meta{color:var(--muted);margin-bottom:28px}",
        ".summary{display:grid;grid-template-columns:repeat(auto-fit,minmax(160px,1fr));gap:12px;margin:18px 0 26px}",
        ".card,.panel{background:var(--panel);border:1px solid var(--line);border-radius:10px}",
        ".card{padding:16px}.card strong{display:block;font-size:24px;color:var(--accent)}",
        ".card span{color:var(--muted);font-size:12px;text-transform:uppercase;letter-spacing:.06em}",
        ".panel{padding:20px;margin:14px 0}",
        ".panel pre{margin:0;white-space:pre-wrap;overflow:auto;color:#cbd5e1;line-height:1.55;",
        "font:13px ui-monospace,SFMono-Regular,Consolas,monospace}",
        ".scroll{max-height:460px;overflow:auto}",
        "table{border-collapse:collapse;width:100%;font-size:14px}",
        "th,td{text-align:left;vertical-align:top;padding:6px 10px;border-bottom:1px solid var(--line)}",
        "th{color:var(--muted);font-weight:600;white-space:nowrap}td{overflow-wrap:anywhere}",
        "tr:last-child>th,tr:last-child>td{border-bottom:0}",
        "td ul{margin:0;padding-left:18px}.muted{color:var(--muted)}",
        ".status{display:inline-block;border-radius:999px;padding:3px 9px;font-size:12px;font-weight:700}",
        ".card strong.good,.good{color:var(--good)}.card strong.warn,.warn{color:var(--warn)}",
        ".card strong.bad,.bad{color:var(--bad)}",
        "a{color:var(--accent);overflow-wrap:anywhere}details{margin-top:12px}summary{cursor:pointer;color:var(--muted)}",
        "@media(max-width:600px){.wrap{padding:24px 12px 40px}h1{font-size:28px}.panel{padding:15px}}",
    )
)


def _section_title(name: str) -> str:
    return name.replace("_", " ").title()


def _summary_cards(report: Dict[str, Any]) -> str:
    cards = []
    names = ["dns", "whois", "tls", "anti_spoofing", "web", "subdomains", "links"]
    if "username_footprint" in report:
        names.append("username_footprint")
    for name in names:
        metric, style = _card_metric(name, report.get(name))
        cards.append(
            f'<div class="card"><strong class="{style}">{html.escape(metric)}</strong>'
            f"<span>{html.escape(_section_title(name))}</span></div>"
        )
    return "".join(cards)


def _card_metric(name: str, value: Any) -> "tuple[str, str]":
    """Return the headline text and severity class for one summary card."""
    if _is_error(value):
        return "ERROR", "bad"
    if value is None:
        return "N/A", "warn"
    if name == "username_footprint" and isinstance(value, list):
        found = sum(1 for item in value if isinstance(item, dict) and item.get("found"))
        return f"{found} found", "good"
    if not isinstance(value, dict):
        return "OK", "good"
    if name == "tls":
        days = value.get("days_until_expiry")
        if isinstance(days, int) and days < 0:
            return "EXPIRED", "bad"
        if value.get("verified") is False:
            return "INVALID", "bad"
        if not isinstance(days, int):
            return "? days", "warn"
        return f"{days} days", "warn" if days < 30 else "good"
    if name == "anti_spoofing":
        findings = len(value.get("findings") or [])
        return (f"{findings} findings", "warn") if findings else ("OK", "good")
    if name == "web":
        missing = len(value.get("missing_security_headers") or [])
        return (f"{missing} missing", "warn") if missing else ("OK", "good")
    if name == "subdomains":
        return str(len(value.get("subdomains", []))), "good"
    if name == "links":
        return str(value.get("links_found", 0)), "good"
    return "OK", "good"


def _render_value(value: Any) -> str:
    if _is_error(value):
        return f'<p class="status bad">ERROR</p><pre>{html.escape(str(value.get("error", "unknown error")))}</pre>'
    serialized = html.escape(json.dumps(value, indent=2, sort_keys=True, default=str))
    return (
        f'<div class="scroll">{_render_structured(value)}</div>'
        f"<details><summary>Raw section data</summary><pre>{_linkify(serialized)}</pre></details>"
    )


def _render_structured(value: Any) -> str:
    """Render JSON-like data as nested tables and lists with all text escaped."""
    if isinstance(value, dict):
        if not value:
            return '<span class="muted">none</span>'
        rows = "".join(
            f"<tr><th>{html.escape(_label(key))}</th><td>{_render_structured(item)}</td></tr>"
            for key, item in value.items()
        )
        return f"<table>{rows}</table>"
    if isinstance(value, (list, tuple)):
        if not value:
            return '<span class="muted">none</span>'
        if all(isinstance(item, dict) for item in value):
            return _render_records(list(value))
        return "<ul>" + "".join(f"<li>{_render_structured(item)}</li>" for item in value) + "</ul>"
    if value is None or value == "":
        return '<span class="muted">&mdash;</span>'
    if isinstance(value, bool):
        return "yes" if value else "no"
    return _linkify(html.escape(str(value)))


def _render_records(records: List[Dict[str, Any]]) -> str:
    """Render a list of objects as one table with a column per field."""
    columns: List[str] = []
    for record in records:
        columns.extend(key for key in record if key not in columns)
    head = "".join(f"<th>{html.escape(_label(column))}</th>" for column in columns)
    body = "".join(
        "<tr>" + "".join(f"<td>{_render_structured(record.get(column))}</td>" for column in columns) + "</tr>"
        for record in records
    )
    return f"<table><tr>{head}</tr>{body}</table>"


def _label(key: Any) -> str:
    return str(key).replace("_", " ")


def _linkify(escaped_text: str) -> str:
    # The text is already HTML-escaped: a literal "&" appears as "&amp;" and must
    # stay part of the URL, while "&quot;" (the closing JSON quote) ends it.
    return re.sub(
        r"(https?://(?:[^\s<&\\]|&amp;)+)",
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
    if is_dataclass(value) and not isinstance(value, type):
        return asdict(value)
    if isinstance(value, list):
        return [_serialize(item) for item in value]
    return value
