"""Explicit public proof-of-control verification for user-provided profiles."""

from dataclasses import asdict, dataclass
import secrets
from typing import Any, Dict, List, Optional

import httpx

from minimal_recon.services.http import with_client
from minimal_recon.services.web import validate_url

TOKEN_PREFIX = "minimal-recon-verify-"


@dataclass(frozen=True)
class VerificationResult:
    url: str
    verified: bool
    status_code: Optional[int]
    evidence: str


def create_token() -> str:
    """Create a short-lived-looking token for a user-controlled public profile."""
    return TOKEN_PREFIX + secrets.token_urlsafe(9)


def verify_urls(
    urls: List[str],
    token: str,
    client: Optional[httpx.Client] = None,
) -> List[VerificationResult]:
    """Check an exact token on explicitly supplied public URLs."""
    if not token.strip() or len(token) > 200:
        raise ValueError("token must be between 1 and 200 characters")
    token = token.strip()
    if not urls:
        raise ValueError("at least one profile URL is required")
    # Validate every URL before the first request so bad input never leaves
    # the run half-finished.
    try:
        normalized_urls = [validate_url(url) for url in urls]
    except ValueError as error:
        raise ValueError("profile URLs must use http:// or https://") from error

    def collect(active_client: httpx.Client) -> List[VerificationResult]:
        results = []
        for normalized in normalized_urls:
            try:
                response = active_client.get(normalized)
            except httpx.HTTPError as error:
                results.append(VerificationResult(normalized, False, None, str(error)))
                continue
            verified = token in response.text
            evidence = "exact verification token found" if verified else "token not found"
            results.append(VerificationResult(normalized, verified, response.status_code, evidence))
        return results

    return with_client(collect, client, timeout=5)


def verification_to_dict(result: VerificationResult) -> Dict[str, Any]:
    return asdict(result)
