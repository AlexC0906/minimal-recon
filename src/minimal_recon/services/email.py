"""Low-impact email address analysis."""

from dataclasses import asdict, dataclass
import re
from typing import Any, Dict, List, Optional

import dns.resolver

from minimal_recon.services.dns import normalize_domain


EMAIL_PATTERN = re.compile(r"^([^@\s]+)@([^@\s]+)$")


@dataclass(frozen=True)
class EmailResult:
    email: str
    local_part: str
    domain: str
    valid: bool
    mx_records: List[str]


def analyze_email(
    email: str, resolver: Optional[dns.resolver.Resolver] = None
) -> EmailResult:
    """Validate an address and inspect its public MX records only."""
    match = EMAIL_PATTERN.fullmatch(email.strip())
    if not match:
        raise ValueError("email must contain one local part and one domain")

    local_part, domain = match.groups()
    if len(local_part) > 64:
        raise ValueError("email local part is too long")
    domain = normalize_domain(domain.lower())
    resolver = resolver or dns.resolver.Resolver()
    mx_records: List[str] = []
    try:
        answers = resolver.resolve(domain, "MX", lifetime=3)
    except (dns.exception.DNSException, OSError):
        pass
    else:
        mx_records = [answer.to_text() for answer in answers]

    return EmailResult(email.strip(), local_part, domain, True, mx_records)


def email_to_dict(result: EmailResult) -> Dict[str, Any]:
    """Serialize an email analysis result for CLI output."""
    return asdict(result)
