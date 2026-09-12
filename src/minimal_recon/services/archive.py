"""Public website history from the Internet Archive CDX index."""

from dataclasses import asdict, dataclass
from typing import Any, Dict, List, Optional

import httpx

from minimal_recon.services.dns import normalize_domain


CDX_URL = "https://web.archive.org/cdx/search/cdx"


@dataclass(frozen=True)
class ArchiveSnapshot:
    timestamp: str
    original_url: str
    status_code: str
    mime_type: str
    archive_url: str


@dataclass(frozen=True)
class ArchiveResult:
    domain: str
    snapshots: List[ArchiveSnapshot]
    source: str


def enumerate_archive(
    domain: str,
    client: Optional[httpx.Client] = None,
    limit: int = 100,
) -> ArchiveResult:
    """Return public Wayback snapshots for a domain and its known paths."""
    domain = normalize_domain(domain.lower())
    if limit < 1 or limit > 1000:
        raise ValueError("limit must be between 1 and 1000")
    params = {
        "url": f"{domain}/*",
        "output": "json",
        "fl": "timestamp,original,statuscode,mimetype",
        "filter": "statuscode:200",
        "collapse": "urlkey",
        "limit": str(limit),
    }

    def request(active_client: httpx.Client) -> ArchiveResult:
        response = active_client.get(CDX_URL, params=params)
        response.raise_for_status()
        try:
            rows = response.json()
        except ValueError as error:
            raise ValueError("Wayback Machine returned invalid JSON") from error
        if not isinstance(rows, list):
            raise ValueError("Wayback Machine returned an unexpected response")

        snapshots: List[ArchiveSnapshot] = []
        for row in rows[1:] if rows and rows[0] == params["fl"].split(",") else rows:
            if not isinstance(row, list) or len(row) < 4:
                continue
            timestamp, original_url, status_code, mime_type = row[:4]
            snapshots.append(
                ArchiveSnapshot(
                    timestamp,
                    original_url,
                    status_code,
                    mime_type,
                    f"https://web.archive.org/web/{timestamp}/{original_url}",
                )
            )
        return ArchiveResult(domain, snapshots, CDX_URL)

    if client is not None:
        return request(client)
    with httpx.Client(timeout=15, follow_redirects=True) as active_client:
        return request(active_client)


def archive_to_dict(result: ArchiveResult) -> Dict[str, Any]:
    """Serialize archive history for JSON output."""
    return asdict(result)
