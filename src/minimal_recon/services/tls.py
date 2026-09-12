"""Read-only TLS certificate and connection inspection."""

from dataclasses import asdict, dataclass
from datetime import datetime, timezone
import socket
import ssl
from typing import Any, Dict, Optional

from minimal_recon.services.dns import normalize_domain


@dataclass(frozen=True)
class TlsResult:
    hostname: str
    port: int
    tls_version: str
    cipher: str
    subject: str
    issuer: str
    not_before: Optional[str]
    not_after: Optional[str]
    days_until_expiry: Optional[int]
    certificate_source: str


def inspect_tls(hostname: str, port: int = 443, timeout: float = 5.0) -> TlsResult:
    """Inspect one TLS endpoint without sending application data."""
    hostname = normalize_domain(hostname.lower())
    if not 1 <= port <= 65535:
        raise ValueError("port must be between 1 and 65535")
    if timeout <= 0:
        raise ValueError("timeout must be greater than zero")

    context = ssl.create_default_context()
    with socket.create_connection((hostname, port), timeout=timeout) as connection:
        with context.wrap_socket(connection, server_hostname=hostname) as tls_socket:
            certificate = tls_socket.getpeercert()
            cipher_info = tls_socket.cipher() or ("unknown", "", 0)
            not_after = certificate.get("notAfter")
            expiry = _parse_certificate_date(not_after)
            days_until_expiry = (
                (expiry - datetime.now(timezone.utc)).days if expiry else None
            )
            return TlsResult(
                hostname,
                port,
                tls_socket.version() or "unknown",
                cipher_info[0],
                _flatten_name(certificate.get("subject", ())),
                _flatten_name(certificate.get("issuer", ())),
                certificate.get("notBefore"),
                not_after,
                days_until_expiry,
                f"https://{hostname}:{port}/",
            )


def _parse_certificate_date(value: Optional[str]) -> Optional[datetime]:
    if not value:
        return None
    return datetime.strptime(value, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)


def _flatten_name(name: Any) -> str:
    values = []
    for section in name or ():
        for key, value in section:
            values.append(f"{key}={value}")
    return ", ".join(values)


def tls_to_dict(result: TlsResult) -> Dict[str, Any]:
    return asdict(result)
