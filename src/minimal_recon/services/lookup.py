"""IP and domain lookup operations."""

from dataclasses import dataclass
import ipaddress
import socket
from typing import Optional, Tuple


@dataclass(frozen=True)
class LookupResult:
    target: str
    target_type: str
    addresses: Tuple[str, ...]
    reverse_name: Optional[str] = None


def lookup_target(target: str) -> LookupResult:
    """Resolve a domain or IP using the local resolver."""
    try:
        address = ipaddress.ip_address(target)
    except ValueError:
        addresses = tuple(
            sorted({item[4][0] for item in socket.getaddrinfo(target, None)})
        )
        return LookupResult(target, "domain", addresses)

    try:
        reverse_name = socket.gethostbyaddr(str(address))[0]
    except (OSError, socket.herror, socket.gaierror):
        reverse_name = None
    return LookupResult(target, "IPv4" if address.version == 4 else "IPv6", (target,), reverse_name)
