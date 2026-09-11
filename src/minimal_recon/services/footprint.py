"""Explicit, low-volume username footprint checks."""

from dataclasses import dataclass
from datetime import datetime, timezone
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
    match_basis: str = "request_error"
    state: str = "unknown"
    checked_at: str = ""


SITES = {
    "github": "https://github.com/{username}",
    "instagram": "https://www.instagram.com/{username}/",
    "reddit": "https://www.reddit.com/user/{username}/",
    "x": "https://x.com/{username}",
    "tiktok": "https://www.tiktok.com/@{username}",
    "youtube": "https://www.youtube.com/@{username}",
    "twitch": "https://www.twitch.tv/{username}",
    "pinterest": "https://www.pinterest.com/{username}/",
    "medium": "https://medium.com/@{username}",
    "devto": "https://dev.to/{username}",
}

NOT_FOUND_MARKERS = (
    "page not found",
    "profile not found",
    "user not found",
    "couldn't find",
    "doesn't exist",
    "does not exist",
    "this page isn't available",
    "channel doesn't exist",
)

CHALLENGE_MARKERS = ("js_challenge", "consent.youtube.com")


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
            checked_at = datetime.now(timezone.utc).isoformat()
            try:
                response = active_client.get(url)
            except httpx.HTTPError:
                results.append(
                    FootprintResult(
                        site, url, False, match_basis="request_error", state="unknown", checked_at=checked_at
                    )
                )
            else:
                body = response.text.lower()
                has_not_found_marker = any(marker in body for marker in NOT_FOUND_MARKERS)
                has_challenge_marker = any(marker in body or marker in str(response.url).lower() for marker in CHALLENGE_MARKERS)
                has_profile_signal = username.lower() in body
                found = response.status_code == 200 and has_profile_signal and not has_not_found_marker and not has_challenge_marker
                if found:
                    match_basis = "profile_content_signal"
                    state = "found"
                elif response.status_code == 404 or has_not_found_marker:
                    match_basis = f"http_status_{response.status_code}"
                    state = "not_found"
                elif has_challenge_marker:
                    match_basis = "platform_challenge_or_consent"
                    state = "unknown"
                elif response.status_code == 200 and not has_not_found_marker:
                    match_basis = "http_status_200_no_profile_signal"
                    state = "unknown"
                else:
                    match_basis = f"http_status_{response.status_code}"
                    state = "unknown"
                results.append(
                    FootprintResult(
                        site,
                        url,
                        found,
                        response.status_code,
                        match_basis,
                        state,
                        checked_at,
                    )
                )
            if delay_seconds > 0 and index < len(registry) - 1:
                time.sleep(delay_seconds)

    if client is not None:
        collect(client)
    else:
        with httpx.Client(follow_redirects=True, timeout=5) as active_client:
            collect(active_client)
    return results
