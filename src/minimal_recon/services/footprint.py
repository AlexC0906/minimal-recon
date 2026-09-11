"""Explicit, low-volume username footprint checks."""

from dataclasses import dataclass

import httpx


@dataclass(frozen=True)
class FootprintResult:
    site: str
    url: str
    found: bool


SITES = {"github": "https://github.com/{username}"}


def check_username(username: str) -> list[FootprintResult]:
    """Check registered public profiles without bypassing access controls."""
    results = []
    with httpx.Client(follow_redirects=True, timeout=5) as client:
        for site, template in SITES.items():
            url = template.format(username=username)
            try:
                response = client.get(url)
            except httpx.HTTPError:
                found = False
            else:
                found = response.status_code == 200
            results.append(FootprintResult(site, url, found))
    return results
