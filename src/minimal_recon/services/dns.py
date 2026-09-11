"""DNS enumeration operations."""

from typing import Dict, List, Optional

import dns.resolver


RECORD_TYPES = ("A", "AAAA", "MX", "NS", "TXT", "CNAME")


def normalize_domain(domain: str) -> str:
    """Validate and normalize a DNS name for resolver queries."""
    normalized = domain.strip().rstrip(".")
    if not normalized or any(character.isspace() for character in normalized):
        raise ValueError("domain must be a non-empty DNS name")
    if len(normalized) > 253 or any(not label for label in normalized.split(".")):
        raise ValueError("domain is not a valid DNS name")
    return normalized


def enumerate_dns(
    domain: str, resolver: Optional[dns.resolver.Resolver] = None
) -> Dict[str, List[str]]:
    """Return common DNS records, omitting record types with no answer."""
    domain = normalize_domain(domain)
    resolver = resolver or dns.resolver.Resolver()
    results: Dict[str, List[str]] = {}
    for record_type in RECORD_TYPES:
        try:
            answers = resolver.resolve(domain, record_type, lifetime=3)
        except (dns.exception.DNSException, OSError):
            continue
        results[record_type] = [answer.to_text() for answer in answers]
    return results
