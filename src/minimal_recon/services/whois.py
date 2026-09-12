"""Structured domain registration data from RDAP services."""

from dataclasses import dataclass
from typing import Any, Dict, List, Optional

import httpx

from minimal_recon.services.dns import normalize_domain


RDAP_URL = "https://rdap.org/domain/{domain}"


@dataclass(frozen=True)
class WhoisResult:
    domain: str
    registrar: Optional[str]
    registration_date: Optional[str]
    expiration_date: Optional[str]
    last_changed: Optional[str]
    nameservers: List[str]
    source: str


def lookup_whois(domain: str, client: Optional[httpx.Client] = None) -> WhoisResult:
    """Return public registration details where the registry exposes them."""
    domain = normalize_domain(domain.lower())
    source = RDAP_URL.format(domain=domain)

    def request(active_client: httpx.Client) -> WhoisResult:
        response = active_client.get(source)
        response.raise_for_status()
        try:
            payload = response.json()
        except ValueError as error:
            raise ValueError("RDAP returned invalid JSON") from error
        events = {event.get("eventAction"): event.get("eventDate") for event in payload.get("events", [])}
        registrar = _find_registrar(payload.get("entities", []))
        nameservers = sorted(
            {str(item.get("ldhName", "")).lower() for item in payload.get("nameservers", []) if item.get("ldhName")}
        )
        return WhoisResult(
            domain,
            registrar,
            events.get("registration"),
            events.get("expiration"),
            events.get("last changed") or events.get("last update of RDAP database"),
            nameservers,
            source,
        )

    if client is not None:
        return request(client)
    with httpx.Client(timeout=10, follow_redirects=True) as active_client:
        return request(active_client)


def _find_registrar(entities: List[Dict[str, Any]]) -> Optional[str]:
    for entity in entities:
        if "registrar" not in entity.get("roles", []):
            continue
        for item in entity.get("vcardArray", [None, []])[1]:
            if len(item) >= 4 and item[0] == "fn":
                return str(item[3])
    return None
