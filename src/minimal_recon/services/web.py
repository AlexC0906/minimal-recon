"""Passive checks for public web security headers."""

from dataclasses import dataclass
from typing import Dict, Optional
from urllib.parse import urlparse

import httpx

from minimal_recon.services.http import with_client

SECURITY_HEADERS = (
    "strict-transport-security",
    "content-security-policy",
    "x-frame-options",
    "x-content-type-options",
    "referrer-policy",
    "permissions-policy",
)


@dataclass(frozen=True)
class WebCheckResult:
    url: str
    final_url: str
    status_code: int
    security_headers: Dict[str, str]
    missing_security_headers: tuple[str, ...]
    waf_vendor: Optional[str]
    waf_signals: tuple[str, ...]
    waf_confidence: str
    technologies: Dict[str, tuple[str, ...]]


def validate_url(url: str) -> str:
    """Allow only explicit HTTP(S) URLs for passive web checks."""
    normalized = url.strip()
    parsed = urlparse(normalized)
    if parsed.scheme not in ("http", "https") or not parsed.netloc:
        raise ValueError("URL must include an http:// or https:// scheme")
    return normalized


def check_web(url: str, client: Optional[httpx.Client] = None) -> WebCheckResult:
    """Fetch one public page and report selected response security headers."""
    url = validate_url(url)

    def request(active_client: httpx.Client) -> WebCheckResult:
        response = active_client.get(url)
        headers = {
            name: response.headers[name]
            for name in SECURITY_HEADERS
            if name in response.headers
        }
        missing = tuple(name for name in SECURITY_HEADERS if name not in headers)
        waf_vendor, waf_signals, waf_confidence = detect_waf(response.headers, response.text)
        technologies = detect_technologies(response.headers, response.text)
        return WebCheckResult(
            url,
            str(response.url),
            response.status_code,
            headers,
            missing,
            waf_vendor,
            waf_signals,
            waf_confidence,
            technologies,
        )

    return with_client(request, client, timeout=5)


def detect_waf(headers: httpx.Headers, body: str = "") -> tuple[Optional[str], tuple[str, ...], str]:
    """Infer a WAF vendor from passive response fingerprints only."""
    # Only identifying headers are inspected. Page bodies and policy headers such
    # as CSP routinely mention CDN hostnames (cdnjs.cloudflare.com, *.cloudfront.net)
    # on sites that are not behind that vendor. ``body`` is kept for API
    # compatibility and ignored.
    normalized_headers = {key.lower(): value.lower() for key, value in headers.items()}
    identifying_values = [
        normalized_headers.get(name, "")
        for name in ("server", "via", "x-cache", "x-cdn", "x-served-by", "set-cookie")
    ]
    fingerprints = {
        "Cloudflare": ("cf-ray", "cf-cache-status", "cloudflare"),
        "AWS WAF/CloudFront": ("x-amz-cf-id", "x-amzn-waf-action", "cloudfront"),
        "Akamai": ("akamai-grn", "x-akamai-transformed", "akamaighost"),
        "Imperva": ("x-iinfo", "incap_ses", "visid_incap"),
        "Sucuri": ("x-sucuri-id", "sucuri/cloudproxy"),
        "Fastly": ("fastly-debug-digest", "x-fastly-request-id", "fastly"),
    }
    for vendor, markers in fingerprints.items():
        signals = tuple(
            marker
            for marker in markers
            if marker in normalized_headers or any(marker in value for value in identifying_values)
        )
        if signals:
            return vendor, signals, "heuristic"
    return None, (), "not_detected"


def detect_technologies(headers: httpx.Headers, body: str = "") -> Dict[str, tuple[str, ...]]:
    """Infer technology hints from public headers and HTML fingerprints."""
    normalized_headers = {key.lower(): value.lower() for key, value in headers.items()}
    normalized_body = body.lower()[:500_000]
    fingerprints = {
        "WordPress": ("/wp-content/", "wp-includes", "wordpress"),
        "Drupal": ("drupal-settings-json", "sites/default/files", "drupal"),
        "Joomla": ("/media/system/js/", "joomla"),
        "React": ("data-reactroot", "react.production.min.js", "__next_data__"),
        "Next.js": ("/_next/", "__next_data__"),
        "Vue": ("vue.min.js", "data-v-"),
        "jQuery": ("jquery.min.js", "jquery-"),
    }
    detected: Dict[str, tuple[str, ...]] = {}
    for technology, markers in fingerprints.items():
        signals = tuple(
            marker
            for marker in markers
            if (marker in normalized_body)
            or any(marker in key or marker in value for key, value in normalized_headers.items())
        )
        if signals:
            detected[technology] = signals
    if "server" in normalized_headers:
        detected["Server"] = (normalized_headers["server"],)
    if "x-powered-by" in normalized_headers:
        detected["X-Powered-By"] = (normalized_headers["x-powered-by"],)
        if "php" in normalized_headers["x-powered-by"]:
            detected["PHP"] = ("x-powered-by",)
    if "phpsessid" in normalized_headers.get("set-cookie", ""):
        detected.setdefault("PHP", ("phpsessid cookie",))
    return detected
