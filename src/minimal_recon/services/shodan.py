"""Optional read-only Shodan host information lookup."""

from dataclasses import asdict, dataclass
import ipaddress
import os
from typing import Any, Dict, List, Optional

import httpx


SHODAN_URL = "https://api.shodan.io/shodan/host/{ip}"


@dataclass(frozen=True)
class ShodanResult:
    ip: str
    organization: Optional[str]
    isp: Optional[str]
    asn: Optional[str]
    country: Optional[str]
    city: Optional[str]
    hostnames: List[str]
    ports: List[int]
    domains: List[str]
    last_update: Optional[str]
    source: str


def lookup_host(
    ip: str,
    api_key: Optional[str] = None,
    client: Optional[httpx.Client] = None,
) -> ShodanResult:
    """Read Shodan's indexed host data for one IP address."""
    try:
        normalized = str(ipaddress.ip_address(ip.strip()))
    except ValueError as error:
        raise ValueError("Shodan lookup requires a valid IP address") from error

    api_key = api_key or os.getenv("SHODAN_API_KEY")
    if not api_key:
        raise ValueError("SHODAN_API_KEY is required for Shodan lookups")
    url = SHODAN_URL.format(ip=normalized)

    def request(active_client: httpx.Client) -> ShodanResult:
        response = active_client.get(url, params={"key": api_key})
        response.raise_for_status()
        try:
            payload = response.json()
        except ValueError as error:
            raise ValueError("Shodan returned invalid JSON") from error
        return ShodanResult(
            normalized,
            payload.get("org"),
            payload.get("isp"),
            payload.get("asn"),
            payload.get("country_name"),
            payload.get("city"),
            sorted(set(payload.get("hostnames", []))),
            sorted(set(payload.get("ports", []))),
            sorted(set(payload.get("domains", []))),
            payload.get("last_update"),
            "https://www.shodan.io/",
        )

    if client is not None:
        return request(client)
    with httpx.Client(timeout=10, follow_redirects=True) as active_client:
        return request(active_client)


def shodan_to_dict(result: ShodanResult) -> Dict[str, Any]:
    return asdict(result)
