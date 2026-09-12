"""Low-impact email address analysis."""

from dataclasses import asdict, dataclass
import re
from typing import Any, Dict, List, Optional

import dns.resolver

from minimal_recon.services.dns import normalize_domain


EMAIL_PATTERN = re.compile(r"^([^@\s]+)@([^@\s]+)$")
ROLE_PREFIXES = {"admin", "contact", "hello", "info", "noreply", "sales", "support", "security"}
DISPOSABLE_DOMAINS = {
    "10minutemail.com",
    "guerrillamail.com",
    "mailinator.com",
    "tempmail.com",
    "yopmail.com",
}


@dataclass(frozen=True)
class EmailResult:
    email: str
    local_part: str
    domain: str
    valid: bool
    mx_records: List[str]
    mx_available: bool
    is_role_address: bool
    is_disposable_domain: bool
    risk_flags: List[str]


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

    is_role_address = local_part.lower() in ROLE_PREFIXES
    is_disposable_domain = domain in DISPOSABLE_DOMAINS
    risk_flags = []
    if not mx_records:
        risk_flags.append("no_mx_records")
    if is_role_address:
        risk_flags.append("role_address")
    if is_disposable_domain:
        risk_flags.append("disposable_domain")
    return EmailResult(
        email.strip(),
        local_part,
        domain,
        True,
        mx_records,
        bool(mx_records),
        is_role_address,
        is_disposable_domain,
        risk_flags,
    )


def email_to_dict(result: EmailResult) -> Dict[str, Any]:
    """Serialize an email analysis result for CLI output."""
    return asdict(result)
