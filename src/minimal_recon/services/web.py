"""Passive checks for public web security headers."""

from dataclasses import dataclass
from typing import Dict, Optional
from urllib.parse import urlparse

import httpx


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
        return WebCheckResult(
            url,
            str(response.url),
            response.status_code,
            headers,
            missing,
            waf_vendor,
            waf_signals,
            waf_confidence,
        )

    if client is not None:
        return request(client)
    with httpx.Client(follow_redirects=True, timeout=5) as active_client:
        return request(active_client)


def detect_waf(headers: httpx.Headers, body: str = "") -> tuple[Optional[str], tuple[str, ...], str]:
    """Infer a WAF vendor from passive response fingerprints only."""
    normalized_headers = {key.lower(): value.lower() for key, value in headers.items()}
    normalized_body = body.lower()[:500_000]
    fingerprints = {
        "Cloudflare": ("cf-ray", "cf-cache-status", "cloudflare"),
        "AWS WAF/CloudFront": ("x-amzn-requestid", "x-cache", "cloudfront"),
        "Akamai": ("akamai-grn", "x-akamai-transformed"),
        "Imperva": ("incap_ses", "visid_incap"),
        "Sucuri": ("x-sucuri-id", "sucuri/cloudproxy"),
        "Fastly": ("fastly-debug-digest", "fastly"),
    }
    for vendor, markers in fingerprints.items():
        signals = tuple(
            marker
            for marker in markers
            if marker in normalized_headers or any(marker in value for value in normalized_headers.values()) or marker in normalized_body
        )
        if signals:
            return vendor, signals, "heuristic"
    return None, (), "not_detected"
