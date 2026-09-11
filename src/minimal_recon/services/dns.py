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


def summarize_dns(records: Dict[str, List[str]]) -> Dict[str, object]:
    """Derive useful provider hints from already collected DNS records."""
    nameservers = [value.rstrip(".") for value in records.get("NS", [])]
    mail_servers = []
    for value in records.get("MX", []):
        parts = value.split()
        if parts:
            mail_servers.append(parts[-1].rstrip("."))

    return {
        "nameservers": nameservers,
        "mail_servers": mail_servers,
        "nameserver_providers": sorted({_provider_hint(name) for name in nameservers}),
        "mail_providers": sorted({_provider_hint(name) for name in mail_servers}),
    }


def _provider_hint(hostname: str) -> str:
    """Return a conservative provider hint from a DNS hostname."""
    known_providers = {
        "cloudflare": "Cloudflare",
        "google": "Google",
        "amazon": "Amazon",
        "aws": "Amazon",
        "microsoft": "Microsoft",
        "outlook": "Microsoft",
        "protection.outlook": "Microsoft",
    }
    lowered = hostname.lower()
    for marker, provider in known_providers.items():
        if marker in lowered:
            return provider
    return "Unknown"
