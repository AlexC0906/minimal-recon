"""Read-only TLS certificate and connection inspection."""

from dataclasses import asdict, dataclass
from datetime import datetime, timezone
import ipaddress
import socket
import ssl
from typing import Any, Dict, Optional

import certifi
from cryptography import x509

from minimal_recon.services.dns import normalize_domain
from minimal_recon.services.http import resolve_timeout


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
    verified: bool = True
    verification_error: Optional[str] = None


def inspect_tls(hostname: str, port: int = 443, timeout: Optional[float] = None) -> TlsResult:
    """Inspect one TLS endpoint without sending application data.

    A certificate that fails validation (expired, self-signed, wrong host) is
    still reported, with ``verified=False`` and the validation error.
    """
    try:
        hostname = str(ipaddress.ip_address(hostname.strip()))
    except ValueError:
        hostname = normalize_domain(hostname.lower())
    if not 1 <= port <= 65535:
        raise ValueError("port must be between 1 and 65535")
    if timeout is None:
        timeout = resolve_timeout(5.0)
    if timeout <= 0:
        raise ValueError("timeout must be greater than zero")

    # Trust the operating system store plus the Mozilla bundle used by the HTTP
    # checks, so a stale local store does not mark a valid public chain invalid.
    context = ssl.create_default_context()
    context.load_verify_locations(certifi.where())
    try:
        return _handshake(hostname, port, timeout, context, None)
    except ssl.SSLCertVerificationError as error:
        verification_error = error.verify_message or str(error)

    # Second handshake with validation off, only to read the certificate that
    # was just rejected. Nothing is sent over the connection.
    unverified = ssl.create_default_context()
    unverified.check_hostname = False
    unverified.verify_mode = ssl.CERT_NONE
    return _handshake(hostname, port, timeout, unverified, verification_error)


def _handshake(
    hostname: str,
    port: int,
    timeout: float,
    context: ssl.SSLContext,
    verification_error: Optional[str],
) -> TlsResult:
    try:
        connection = socket.create_connection((hostname, port), timeout=timeout)
    except socket.gaierror as error:
        raise OSError(f"could not resolve {hostname}") from error
    with connection:
        with context.wrap_socket(connection, server_hostname=hostname) as tls_socket:
            der = tls_socket.getpeercert(binary_form=True)
            cipher_info = tls_socket.cipher() or ("unknown", "", 0)
            tls_version = tls_socket.version() or "unknown"
    if not der:
        raise OSError("server did not present a certificate")

    certificate = x509.load_der_x509_certificate(der)
    not_after = certificate.not_valid_after_utc
    return TlsResult(
        hostname,
        port,
        tls_version,
        cipher_info[0],
        _flatten_name(certificate.subject),
        _flatten_name(certificate.issuer),
        certificate.not_valid_before_utc.isoformat(),
        not_after.isoformat(),
        (not_after - datetime.now(timezone.utc)).days,
        f"https://{_url_host(hostname)}:{port}/",
        verification_error is None,
        verification_error,
    )


def _flatten_name(name: x509.Name) -> str:
    """Render a certificate name as ``commonName=example.com, organizationName=...``."""
    return ", ".join(f"{attribute.oid._name}={attribute.value!s}" for attribute in name)


def _url_host(hostname: str) -> str:
    return f"[{hostname}]" if ":" in hostname else hostname


def tls_to_dict(result: TlsResult) -> Dict[str, Any]:
    return asdict(result)
