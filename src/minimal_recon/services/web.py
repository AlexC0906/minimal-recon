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
        return WebCheckResult(
            url, str(response.url), response.status_code, headers, missing
        )

    if client is not None:
        return request(client)
    with httpx.Client(follow_redirects=True, timeout=5) as active_client:
        return request(active_client)
