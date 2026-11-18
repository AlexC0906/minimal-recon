"""Local web interface for Minimal Recon, served on 127.0.0.1 only.

The server uses only the standard library. Each run creates a random API
token that is embedded in the page, and every API call must send it back.
Together with the Host header check, this keeps other websites open in the
same browser from driving the tool (cross-site requests, DNS rebinding).
"""

import base64
import binascii
from dataclasses import asdict, is_dataclass
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from importlib import resources
import json
from pathlib import Path
import re
import secrets
import tempfile
from typing import Any, Callable, Dict, List, Optional, Tuple
from urllib.parse import urlsplit
import webbrowser

import httpx
from PIL import Image

from minimal_recon import __version__
from minimal_recon.services import antispoofing as antispoofing_service
from minimal_recon.services import archive as archive_service
from minimal_recon.services import diff as diff_service
from minimal_recon.services import dns as dns_service
from minimal_recon.services import email as email_service
from minimal_recon.services import footprint as footprint_service
from minimal_recon.services import geoip as geoip_service
from minimal_recon.services import links as links_service
from minimal_recon.services import lookup as lookup_service
from minimal_recon.services import metadata as metadata_service
from minimal_recon.services import public_files as public_files_service
from minimal_recon.services import report as report_service
from minimal_recon.services import shodan as shodan_service
from minimal_recon.services import subdomains as subdomains_service
from minimal_recon.services import threatintel as threatintel_service
from minimal_recon.services import tls as tls_service
from minimal_recon.services import verification as verification_service
from minimal_recon.services import web as web_service
from minimal_recon.services import whois as whois_service

HOST = "127.0.0.1"
MAX_USERNAMES = 10
MAX_BODY_BYTES = 64_000
TOKEN_HEADER = "X-Recon-Token"
_TOKEN_PLACEHOLDER = "__API_TOKEN__"

STATIC_FILES: Dict[str, Tuple[str, str]] = {
    "/": ("index.html", "text/html; charset=utf-8"),
    "/app.js": ("app.js", "text/javascript; charset=utf-8"),
    "/app.css": ("app.css", "text/css; charset=utf-8"),
}

# Scripts only from this server; inline styles are needed by the embedded HTML report.
CONTENT_SECURITY_POLICY = (
    "default-src 'none'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; "
    "connect-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'"
)


def _string_list(value: Any, field: str, limit: int) -> List[str]:
    """Accept a list of strings or one string separated by spaces, commas or new lines."""
    if value is None or value == "":
        return []
    if isinstance(value, str):
        items = [item for item in re.split(r"[\s,]+", value) if item]
    elif isinstance(value, list) and all(isinstance(item, str) for item in value):
        items = [item.strip() for item in value if item.strip()]
    else:
        raise ValueError(f"{field} must be a list of strings")
    items = list(dict.fromkeys(items))
    if len(items) > limit:
        raise ValueError(f"at most {limit} {field} per request")
    return items


def api_sites(payload: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "version": __version__,
        "sites": [{"name": rule.name, "source": rule.source} for rule in footprint_service.SITES.values()],
    }


def api_footprint(payload: Dict[str, Any]) -> Dict[str, Any]:
    usernames = _string_list(payload.get("usernames"), "usernames", MAX_USERNAMES)
    if not usernames:
        raise ValueError("enter at least one username")
    for username in usernames:
        footprint_service.validate_username(username)

    registry: Dict[str, footprint_service.SiteRule] = dict(footprint_service.SITES)
    selected = _string_list(payload.get("sites"), "sites", len(registry))
    if selected:
        unknown = sorted(set(selected) - set(registry))
        if unknown:
            raise ValueError(f"unknown site(s): {', '.join(unknown)}")
        registry = {name: rule for name, rule in registry.items() if name in selected}
    for server in _string_list(payload.get("mastodon"), "Mastodon servers", 5):
        rule = footprint_service.mastodon_rule(server)
        registry[rule.name] = rule

    audit_token = payload.get("audit_token") or None
    runs = []
    for username in usernames:
        results = footprint_service.check_username(
            username,
            sites=registry,
            delay_seconds=0.2,
            details=bool(payload.get("details")),
            audit_token=audit_token,
        )
        runs.append({"username": username, "results": [asdict(result) for result in results]})
    return {"runs": runs}


def api_search_links(payload: Dict[str, Any]) -> Dict[str, Any]:
    return footprint_service.search_links(str(payload.get("username", "")))


def api_self_test(payload: Dict[str, Any]) -> Dict[str, Any]:
    return {"rules": footprint_service.run_self_test()}


def api_report(payload: Dict[str, Any]) -> Dict[str, Any]:
    domain = str(payload.get("domain", "")).strip()
    if not domain:
        raise ValueError("enter a domain such as example.com")
    username = str(payload.get("username") or "").strip() or None
    if username:
        footprint_service.validate_username(username)
    report = report_service.build_report(domain, username, footprint_details=bool(payload.get("details")))
    return {"report": report, "html": report_service.render_html(report)}


def _text(args: Dict[str, Any], name: str, label: Optional[str] = None) -> str:
    value = str(args.get(name) or "").strip()
    if not value:
        raise ValueError(f"enter {label or name.replace('_', ' ')}")
    return value


def _int(args: Dict[str, Any], name: str, default: int) -> int:
    value = args.get(name)
    if value in (None, ""):
        return default
    try:
        return int(str(value).strip())
    except ValueError as error:
        raise ValueError(f"{name} must be a whole number") from error


def _serialize(value: Any) -> Any:
    if is_dataclass(value) and not isinstance(value, type):
        return asdict(value)
    if isinstance(value, list):
        return [_serialize(item) for item in value]
    return value


def _tool_dns(args: Dict[str, Any]) -> Any:
    records = dns_service.enumerate_dns(_text(args, "domain"))
    return {"records": records, "summary": dns_service.summarize_dns(records)}


def _tool_metadata(args: Dict[str, Any]) -> Any:
    """Inspect an uploaded file in a temporary copy that is deleted afterwards."""
    name = Path(_text(args, "name", "a file")).name
    try:
        data = base64.b64decode(_text(args, "data", "a file"), validate=True)
    except (binascii.Error, ValueError) as error:
        raise ValueError("the uploaded file could not be decoded") from error
    with tempfile.TemporaryDirectory(prefix="minimal-recon-") as folder:
        path = Path(folder) / (re.sub(r"[^A-Za-z0-9._-]", "_", name) or "upload")
        path.write_bytes(data)
        try:
            result = metadata_service.extract_metadata(path)
        except Image.DecompressionBombError as error:
            raise ValueError("image is too large to inspect safely") from error
    result["name"] = name
    return result


def _tool_diff(args: Dict[str, Any]) -> Any:
    old, new = args.get("old"), args.get("new")
    for label, report in (("earlier", old), ("later", new)):
        if not isinstance(report, dict) or "target" not in report:
            raise ValueError(f"the {label} file is not a Minimal Recon JSON report")
    assert isinstance(old, dict) and isinstance(new, dict)
    return {
        "target": new.get("target"),
        "old_generated_at": old.get("generated_at"),
        "new_generated_at": new.get("generated_at"),
        "changes": [asdict(change) for change in diff_service.diff_reports(old, new)],
    }


def _selectors(args: Dict[str, Any]) -> List[str]:
    return _string_list(args.get("selectors"), "DKIM selectors", 20)


# Every tool the interface can run, keyed by the name the page sends.
TOOLS: Dict[str, Callable[[Dict[str, Any]], Any]] = {
    "dns": _tool_dns,
    "whois": lambda args: whois_service.lookup_whois(_text(args, "domain")),
    "subdomains": lambda args: subdomains_service.enumerate_subdomains(_text(args, "domain")),
    "archive": lambda args: archive_service.enumerate_archive(_text(args, "domain"), limit=_int(args, "limit", 100)),
    "tls": lambda args: tls_service.inspect_tls(_text(args, "hostname"), _int(args, "port", 443)),
    "anti_spoofing": lambda args: antispoofing_service.analyze_anti_spoofing(_text(args, "domain"), _selectors(args)),
    "lookup": lambda args: lookup_service.lookup_target(_text(args, "target", "an IP address or domain")),
    "geoip": lambda args: geoip_service.geolocate_ip(_text(args, "ip", "an IP address")),
    "reputation": lambda args: threatintel_service.check_reputation(
        _text(args, "target", "an IP address or domain"), api_key=str(args.get("api_key") or "").strip() or None
    ),
    "shodan": lambda args: shodan_service.lookup_host(
        _text(args, "ip", "an IP address"), api_key=str(args.get("api_key") or "").strip() or None
    ),
    "web": lambda args: web_service.check_web(_text(args, "url", "a URL")),
    "links": lambda args: links_service.extract_links(
        _text(args, "url", "a URL"), max_links=_int(args, "max_links", 500)
    ),
    "public_files": lambda args: public_files_service.discover_public_files(_text(args, "url", "a URL")),
    "email": lambda args: email_service.analyze_email(_text(args, "address", "an email address")),
    "metadata": _tool_metadata,
    "diff": _tool_diff,
    "verify_token": lambda args: {"token": verification_service.create_token()},
    "verify": lambda args: verification_service.verify_urls(
        _string_list(args.get("urls"), "URLs", 20), _text(args, "token")
    ),
}


def api_tool(payload: Dict[str, Any]) -> Dict[str, Any]:
    name = str(payload.get("tool", ""))
    tool = TOOLS.get(name)
    if tool is None:
        raise ValueError(f"unknown tool: {name or '(none)'}")
    args = payload.get("args") or {}
    if not isinstance(args, dict):
        raise ValueError("args must be an object")
    return {"tool": name, "result": _serialize(tool(args))}


API_ROUTES: Dict[str, Callable[[Dict[str, Any]], Dict[str, Any]]] = {
    "/api/sites": api_sites,
    "/api/footprint": api_footprint,
    "/api/search-links": api_search_links,
    "/api/self-test": api_self_test,
    "/api/report": api_report,
    "/api/tool": api_tool,
}

# Uploaded files (metadata) and saved reports (diff) need larger bodies.
LARGE_BODY_ROUTES = {"/api/tool": 30_000_000}


class UiServer(ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self, port: int = 0, token: Optional[str] = None) -> None:
        self.token = token or secrets.token_urlsafe(24)
        super().__init__((HOST, port), UiRequestHandler)

    @property
    def url(self) -> str:
        return f"http://{HOST}:{self.server_port}/"

    @property
    def allowed_hosts(self) -> Tuple[str, ...]:
        return (f"{HOST}:{self.server_port}", f"localhost:{self.server_port}")


class UiRequestHandler(BaseHTTPRequestHandler):
    server: UiServer
    server_version = f"MinimalRecon/{__version__}"

    def log_message(self, format: str, *args: Any) -> None:  # noqa: A002 - signature set by the base class
        """Keep the terminal quiet; usernames are not written to any log."""

    def do_GET(self) -> None:  # noqa: N802 - name set by the base class
        if not self._host_allowed():
            return self._send_json(HTTPStatus.FORBIDDEN, {"error": "unexpected Host header"})
        path = urlsplit(self.path).path
        if path in STATIC_FILES:
            return self._send_static(*STATIC_FILES[path])
        self._send_json(HTTPStatus.NOT_FOUND, {"error": "not found"})

    def do_POST(self) -> None:  # noqa: N802 - name set by the base class
        if not self._host_allowed():
            self._discard_body()
            return self._send_json(HTTPStatus.FORBIDDEN, {"error": "unexpected Host header"})
        if not secrets.compare_digest(self.headers.get(TOKEN_HEADER, ""), self.server.token):
            self._discard_body()
            return self._send_json(HTTPStatus.FORBIDDEN, {"error": "missing or wrong API token; reload the page"})
        path = urlsplit(self.path).path
        route = API_ROUTES.get(path)
        if route is None:
            self._discard_body()
            return self._send_json(HTTPStatus.NOT_FOUND, {"error": "not found"})
        try:
            payload = self._read_json(LARGE_BODY_ROUTES.get(path, MAX_BODY_BYTES))
            result = route(payload)
        except ValueError as error:
            return self._send_json(HTTPStatus.BAD_REQUEST, {"error": str(error)})
        except httpx.TimeoutException:
            return self._send_json(HTTPStatus.BAD_GATEWAY, {"error": "network timeout; try a larger --timeout"})
        except httpx.HTTPStatusError as error:
            return self._send_json(
                HTTPStatus.BAD_GATEWAY, {"error": f"remote service returned HTTP {error.response.status_code}"}
            )
        except (httpx.HTTPError, OSError) as error:
            return self._send_json(HTTPStatus.BAD_GATEWAY, {"error": f"network error: {error}"})
        except Exception as error:  # keep the server alive and tell the page what failed
            return self._send_json(HTTPStatus.INTERNAL_SERVER_ERROR, {"error": f"unexpected error: {error}"})
        self._send_json(HTTPStatus.OK, result)

    def _host_allowed(self) -> bool:
        return self.headers.get("Host", "") in self.server.allowed_hosts

    def _read_json(self, limit: int = MAX_BODY_BYTES) -> Dict[str, Any]:
        try:
            length = int(self.headers.get("Content-Length", "0"))
        except ValueError as error:
            raise ValueError("invalid Content-Length") from error
        if length > limit:
            self._discard_body()
            raise ValueError(f"request body is too large (limit {limit // 1_000} KB)")
        if not self.headers.get("Content-Type", "").startswith("application/json"):
            raise ValueError("requests must be JSON")
        raw = self.rfile.read(length) if length else b"{}"
        try:
            payload = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, ValueError) as error:
            raise ValueError("request body is not valid JSON") from error
        if not isinstance(payload, dict):
            raise ValueError("request body must be a JSON object")
        return payload

    def _discard_body(self) -> None:
        """Read an unwanted request body before answering.

        Closing a socket with unread data makes Windows reset the connection,
        so the browser would see a network error instead of the error message.
        Bodies above the largest accepted size are not read.
        """
        try:
            remaining = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            return
        if remaining > max(LARGE_BODY_ROUTES.values()):
            return
        while remaining > 0:
            chunk = self.rfile.read(min(remaining, 65_536))
            if not chunk:
                break
            remaining -= len(chunk)

    def _send_static(self, name: str, content_type: str) -> None:
        text = resources.files("minimal_recon.ui").joinpath(f"static/{name}").read_text(encoding="utf-8")
        if name == "index.html":
            text = text.replace(_TOKEN_PLACEHOLDER, self.server.token)
        self._send(HTTPStatus.OK, text.encode("utf-8"), content_type)

    def _send_json(self, status: HTTPStatus, payload: Any) -> None:
        body = json.dumps(payload, default=str).encode("utf-8")
        self._send(status, body, "application/json; charset=utf-8")

    def _send(self, status: HTTPStatus, body: bytes, content_type: str) -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("Content-Security-Policy", CONTENT_SECURITY_POLICY)
        self.end_headers()
        self.wfile.write(body)


def serve(port: int = 8765, open_browser: bool = True, announce: Callable[[str], None] = print) -> None:
    """Run the interface until Ctrl+C."""
    server = UiServer(port)
    announce(f"Minimal Recon UI running at {server.url} (press Ctrl+C to stop)")
    if open_browser:
        webbrowser.open(server.url)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
