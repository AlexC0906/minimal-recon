"""DNS enumeration operations."""

import dns.resolver
from typing import Dict, List


RECORD_TYPES = ("A", "AAAA", "MX", "NS", "TXT", "CNAME")


def enumerate_dns(domain: str) -> Dict[str, List[str]]:
    """Return common DNS records, omitting record types with no answer."""
    results: Dict[str, List[str]] = {}
    for record_type in RECORD_TYPES:
        try:
            answers = dns.resolver.resolve(domain, record_type, lifetime=3)
        except (dns.exception.DNSException, OSError):
            continue
        results[record_type] = [answer.to_text() for answer in answers]
    return results
