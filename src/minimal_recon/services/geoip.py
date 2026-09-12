"""Approximate public IP geolocation and network ownership data."""

from dataclasses import dataclass
import ipaddress
from typing import Any, Dict, Optional

import httpx


GEOIP_URL = "https://ipwho.is/{ip}"


@dataclass(frozen=True)
class GeoIpResult:
    ip: str
    country: Optional[str]
    country_code: Optional[str]
    region: Optional[str]
    city: Optional[str]
    latitude: Optional[float]
    longitude: Optional[float]
    isp: Optional[str]
    organization: Optional[str]
    asn: Optional[str]
    source: str


def geolocate_ip(ip: str, client: Optional[httpx.Client] = None) -> GeoIpResult:
    """Return approximate IP location and network ownership information."""
    try:
        normalized = str(ipaddress.ip_address(ip.strip()))
    except ValueError as error:
        raise ValueError("invalid IP address") from error
    source = GEOIP_URL.format(ip=normalized)

    def request(active_client: httpx.Client) -> GeoIpResult:
        response = active_client.get(source)
        response.raise_for_status()
        payload = response.json()
        if payload.get("success") is False:
            raise ValueError(str(payload.get("message", "IP geolocation failed")))
        connection = payload.get("connection", {})
        return GeoIpResult(
            normalized,
            payload.get("country"),
            payload.get("country_code"),
            payload.get("region"),
            payload.get("city"),
            payload.get("latitude"),
            payload.get("longitude"),
            connection.get("isp"),
            connection.get("org"),
            str(connection.get("asn")) if connection.get("asn") is not None else None,
            source,
        )

    if client is not None:
        return request(client)
    with httpx.Client(timeout=10, follow_redirects=True) as active_client:
        return request(active_client)
