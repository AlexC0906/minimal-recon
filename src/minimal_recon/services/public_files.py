"""Discovery of intentionally public standard web documents."""

from dataclasses import asdict, dataclass
from typing import Any, Dict, List, Optional
from urllib.parse import urljoin

import httpx

from minimal_recon.services.web import validate_url


STANDARD_PATHS = (
    "/robots.txt",
    "/sitemap.xml",
    "/security.txt",
    "/.well-known/security.txt",
    "/humans.txt",
)


@dataclass(frozen=True)
class PublicFileResult:
    path: str
    url: str
    found: bool
    status_code: Optional[int]
    content_type: str
    size_bytes: int


def discover_public_files(
    url: str,
    client: Optional[httpx.Client] = None,
) -> List[PublicFileResult]:
    """Check a small allowlist of intentionally public web documents."""
    base_url = validate_url(url)

    def request(active_client: httpx.Client) -> List[PublicFileResult]:
        results = []
        for path in STANDARD_PATHS:
            target_url = urljoin(base_url.rstrip("/") + "/", path.lstrip("/"))
            try:
                response = active_client.get(target_url)
            except httpx.HTTPError:
                results.append(PublicFileResult(path, target_url, False, None, "", 0))
                continue
            content_type = response.headers.get("content-type", "").split(";", 1)[0]
            results.append(
                PublicFileResult(
                    path,
                    str(response.url),
                    response.status_code == 200,
                    response.status_code,
                    content_type,
                    len(response.content) if response.status_code == 200 else 0,
                )
            )
        return results

    if client is not None:
        return request(client)
    with httpx.Client(follow_redirects=True, timeout=5) as active_client:
        return request(active_client)


def public_files_to_dict(results: List[PublicFileResult]) -> List[Dict[str, Any]]:
    return [asdict(result) for result in results]
