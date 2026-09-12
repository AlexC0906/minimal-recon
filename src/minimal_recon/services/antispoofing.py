"""Public email anti-spoofing policy checks for SPF, DKIM and DMARC."""

from dataclasses import asdict, dataclass
from typing import Any, Dict, List, Optional

import dns.exception
import dns.resolver

from minimal_recon.services.dns import normalize_domain


@dataclass(frozen=True)
class AntiSpoofingResult:
    domain: str
    spf_record: Optional[str]
    spf_status: str
    dmarc_record: Optional[str]
    dmarc_policy: Optional[str]
    dmarc_status: str
    dkim_selectors: Dict[str, str]
    dkim_status: str
    findings: List[str]


def analyze_anti_spoofing(
    domain: str,
    selectors: Optional[List[str]] = None,
    resolver: Optional[dns.resolver.Resolver] = None,
) -> AntiSpoofingResult:
    """Inspect public email authentication policies without sending mail."""
    domain = normalize_domain(domain.lower())
    resolver = resolver or dns.resolver.Resolver()
    selectors = [item.strip() for item in (selectors or []) if item.strip()]

    spf_records = _query_txt(resolver, domain)
    spf_record = next((record for record in spf_records if record.lower().startswith("v=spf1")), None)
    spf_status = "pass" if spf_record else "missing"

    dmarc_records = _query_txt(resolver, f"_dmarc.{domain}")
    dmarc_record = next((record for record in dmarc_records if record.lower().startswith("v=dmarc1")), None)
    dmarc_policy = _tag_value(dmarc_record, "p") if dmarc_record else None
    if not dmarc_record:
        dmarc_status = "missing"
    elif dmarc_policy in {"reject", "quarantine"}:
        dmarc_status = "strong"
    else:
        dmarc_status = "monitoring"

    dkim_records: Dict[str, str] = {}
    for selector in selectors:
        records = _query_txt(resolver, f"{selector}._domainkey.{domain}")
        if records:
            dkim_records[selector] = records[0]
    if not selectors:
        dkim_status = "not_checked"
    elif len(dkim_records) == len(selectors):
        dkim_status = "found"
    elif dkim_records:
        dkim_status = "partial"
    else:
        dkim_status = "not_found"

    findings = []
    if not spf_record:
        findings.append("SPF record is missing")
    if not dmarc_record:
        findings.append("DMARC record is missing")
    elif dmarc_policy == "none":
        findings.append("DMARC is monitoring only (p=none)")
    if selectors and not dkim_records:
        findings.append("No DKIM record found for the supplied selectors")
    return AntiSpoofingResult(
        domain, spf_record, spf_status, dmarc_record, dmarc_policy,
        dmarc_status, dkim_records, dkim_status, findings,
    )


def _query_txt(resolver: dns.resolver.Resolver, name: str) -> List[str]:
    try:
        answers = resolver.resolve(name, "TXT", lifetime=3)
    except (dns.exception.DNSException, OSError):
        return []
    return [answer.to_text().strip('"') for answer in answers]


def _tag_value(record: Optional[str], tag: str) -> Optional[str]:
    if not record:
        return None
    for part in record.replace(";", " ").split():
        if part.startswith(f"{tag}="):
            return part.split("=", 1)[1].rstrip(";")
    return None


def anti_spoofing_to_dict(result: AntiSpoofingResult) -> Dict[str, Any]:
    return asdict(result)
