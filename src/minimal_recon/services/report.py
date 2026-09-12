"""Aggregate authorized OSINT checks into portable JSON or HTML reports."""

from dataclasses import asdict, is_dataclass
from datetime import datetime, timezone
import html
import json
from pathlib import Path
from typing import Any, Dict, Optional

from minimal_recon.services.dns import enumerate_dns, summarize_dns
from minimal_recon.services.email import analyze_email
from minimal_recon.services.footprint import check_username
from minimal_recon.services.lookup import lookup_target
from minimal_recon.services.subdomains import enumerate_subdomains
from minimal_recon.services.web import check_web
from minimal_recon.services.geoip import geolocate_ip
from minimal_recon.services.whois import lookup_whois


def build_report(
    domain: str,
    username: Optional[str] = None,
    email: Optional[str] = None,
) -> Dict[str, Any]:
    """Collect a read-only report for a domain and optional public identifiers."""
    report: Dict[str, Any] = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "target": domain,
        "lookup": _safe_call(lambda: _serialize(lookup_target(domain))),
        "dns": _safe_call(lambda: _collect_dns(domain)),
        "whois": _safe_call(lambda: _serialize(lookup_whois(domain))),
        "subdomains": _safe_call(lambda: _serialize(enumerate_subdomains(domain))),
        "web": _safe_call(lambda: _serialize(check_web(f"https://{domain}"))),
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
    """Render a dependency-free, escaped HTML report."""
    title = html.escape(f"Minimal Recon report: {report['target']}")
    body = html.escape(json.dumps(report, indent=2, sort_keys=True))
    return (
        "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\">"
        f"<title>{title}</title><style>body{{font:15px monospace;max-width:1100px;"
        "margin:2rem auto;padding:0 1rem}}pre{white-space:pre-wrap;line-height:1.5}"
        "</style></head><body><h1>Minimal Recon</h1>"
        f"<h2>{title}</h2><pre>{body}</pre></body></html>"
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
