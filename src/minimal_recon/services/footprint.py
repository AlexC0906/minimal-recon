"""Explicit, low-volume username footprint checks."""

from dataclasses import dataclass
import re
import time
from typing import Dict, List, Optional

import httpx


@dataclass(frozen=True)
class FootprintResult:
    site: str
    url: str
    found: bool
    status_code: Optional[int] = None


SITES = {"github": "https://github.com/{username}"}


def validate_username(username: str) -> str:
    """Validate a username before interpolating it into public profile URLs."""
    normalized = username.strip()
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,38}", normalized):
        raise ValueError("username must be 1-39 characters and contain only letters, numbers, _, ., or -")
    return normalized


def check_username(
    username: str,
    sites: Optional[Dict[str, str]] = None,
    client: Optional[httpx.Client] = None,
    delay_seconds: float = 0.0,
) -> List[FootprintResult]:
    """Check registered public profiles without bypassing access controls."""
    username = validate_username(username)
    registry = sites or SITES
    results: List[FootprintResult] = []

    def collect(active_client: httpx.Client) -> None:
        for index, (site, template) in enumerate(registry.items()):
            url = template.format(username=username)
            try:
                response = active_client.get(url)
            except httpx.HTTPError:
                results.append(FootprintResult(site, url, False))
            else:
                results.append(FootprintResult(site, url, response.status_code == 200, response.status_code))
            if delay_seconds > 0 and index < len(registry) - 1:
                time.sleep(delay_seconds)

    if client is not None:
        collect(client)
    else:
        with httpx.Client(follow_redirects=True, timeout=5) as active_client:
            collect(active_client)
    return results
