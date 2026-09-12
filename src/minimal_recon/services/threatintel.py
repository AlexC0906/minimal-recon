"""Optional read-only integrations with external security intelligence APIs."""

from dataclasses import asdict, dataclass
import ipaddress
import os
from typing import Any, Dict, Optional

import httpx

from minimal_recon.services.dns import normalize_domain


VT_URL = "https://www.virustotal.com/api/v3/{resource}/{target}"


@dataclass(frozen=True)
class ReputationResult:
    target: str
    target_type: str
    malicious: int
    suspicious: int
    harmless: int
    undetected: int
    reputation: Optional[int]
    source: str


def check_reputation(
    target: str,
    api_key: Optional[str] = None,
    client: Optional[httpx.Client] = None,
) -> ReputationResult:
    """Read VirusTotal reputation data for an IP address or domain."""
    normalized, resource, target_type = _normalize_target(target)
    api_key = api_key or os.getenv("VT_API_KEY")
    if not api_key:
        raise ValueError("VT_API_KEY is required for external reputation checks")

    url = VT_URL.format(resource=resource, target=normalized)
    headers = {"x-apikey": api_key}

    def request(active_client: httpx.Client) -> ReputationResult:
        response = active_client.get(url, headers=headers)
        response.raise_for_status()
        try:
            payload = response.json()
            attributes = payload["data"]["attributes"]
            stats = attributes.get("last_analysis_stats", {})
        except (KeyError, TypeError, ValueError) as error:
            raise ValueError("VirusTotal returned an unexpected response") from error
        return ReputationResult(
            normalized,
            target_type,
            int(stats.get("malicious", 0)),
            int(stats.get("suspicious", 0)),
            int(stats.get("harmless", 0)),
            int(stats.get("undetected", 0)),
            attributes.get("reputation"),
            "https://www.virustotal.com/",
        )

    if client is not None:
        return request(client)
    with httpx.Client(timeout=10, follow_redirects=True) as active_client:
        return request(active_client)


def _normalize_target(target: str) -> tuple[str, str, str]:
    target = target.strip()
    try:
        return str(ipaddress.ip_address(target)), "ip_addresses", "ip"
    except ValueError:
        return normalize_domain(target.lower()), "domains", "domain"


def reputation_to_dict(result: ReputationResult) -> Dict[str, Any]:
    return asdict(result)
