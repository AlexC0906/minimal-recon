"""Public email anti-spoofing policy checks for SPF, DKIM and DMARC."""

from dataclasses import asdict, dataclass
import re
from typing import Any, Dict, List, Optional

import dns.exception
import dns.resolver

from minimal_recon.services.dns import normalize_domain
from minimal_recon.services.http import resolve_timeout

_QUOTED_CHUNK = re.compile(r'"((?:[^"\\]|\\.)*)"')


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
    findings: List[str] = []

    spf_records = [record for record in _query_txt(resolver, domain) if _is_spf_record(record)]
    spf_record = spf_records[0] if spf_records else None
    spf_status = _evaluate_spf(spf_records, findings)

    dmarc_records = [
        record
        for record in _query_txt(resolver, f"_dmarc.{domain}")
        if record.lower().startswith("v=dmarc1")
    ]
    dmarc_record = dmarc_records[0] if dmarc_records else None
    dmarc_policy = _tag_value(dmarc_record, "p")
    dmarc_status = _evaluate_dmarc(dmarc_records, dmarc_policy, findings)

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
        findings.append("No DKIM record found for the supplied selectors")

    return AntiSpoofingResult(
        domain, spf_record, spf_status, dmarc_record, dmarc_policy,
        dmarc_status, dkim_records, dkim_status, findings,
    )


def _is_spf_record(record: str) -> bool:
    lowered = record.lower()
    return lowered == "v=spf1" or lowered.startswith("v=spf1 ")


def _evaluate_spf(records: List[str], findings: List[str]) -> str:
    """Classify the published SPF policy as missing, invalid, weak or pass."""
    if not records:
        findings.append("SPF record is missing")
        return "missing"
    if len(records) > 1:
        findings.append(f"{len(records)} SPF records are published; receivers treat this as a permanent error")
        return "invalid"

    terms = records[0].lower().split()[1:]
    all_term = next((term for term in terms if term.lstrip("+-~?") == "all"), None)
    if all_term in ("all", "+all"):
        findings.append("SPF authorizes every sender (+all)")
        return "weak"
    if all_term == "?all":
        findings.append("SPF is neutral for unlisted senders (?all)")
        return "weak"
    if all_term is None and not any(term.startswith("redirect=") for term in terms):
        findings.append("SPF has no terminating all mechanism or redirect")
        return "weak"
    return "pass"


def _evaluate_dmarc(records: List[str], policy: Optional[str], findings: List[str]) -> str:
    """Classify the published DMARC policy as missing, invalid, monitoring or strong."""
    if not records:
        findings.append("DMARC record is missing")
        return "missing"
    if len(records) > 1:
        findings.append(f"{len(records)} DMARC records are published; receivers ignore all of them")
        return "invalid"

    record = records[0]
    if policy not in ("none", "quarantine", "reject"):
        findings.append("DMARC record has no valid policy (p=) tag")
        return "invalid"
    if policy == "none":
        findings.append("DMARC is monitoring only (p=none)")
    percentage = _tag_value(record, "pct")
    if policy != "none" and percentage is not None and percentage.isdigit() and int(percentage) < 100:
        findings.append(f"DMARC policy applies to only {percentage}% of mail (pct={percentage})")
    if not _tag_value(record, "rua"):
        findings.append("DMARC has no aggregate report address (rua)")
    return "monitoring" if policy == "none" else "strong"


def _query_txt(resolver: dns.resolver.Resolver, name: str) -> List[str]:
    try:
        answers = resolver.resolve(name, "TXT", lifetime=resolve_timeout(3))
    except (dns.exception.DNSException, OSError):
        return []
    return [_txt_value(answer) for answer in answers]


def _txt_value(answer: Any) -> str:
    """Join the character-strings of one TXT record into a single value.

    Long records (SPF, DKIM keys) are split into several quoted chunks that
    must be concatenated without a separator.
    """
    strings = getattr(answer, "strings", None)
    if strings:
        return b"".join(strings).decode("utf-8", "replace")
    text = str(answer.to_text())
    chunks = _QUOTED_CHUNK.findall(text)
    return "".join(chunks) if chunks else text


def _tag_value(record: Optional[str], tag: str) -> Optional[str]:
    """Read one tag from a ``tag=value; tag=value`` record (DMARC, DKIM)."""
    if not record:
        return None
    for part in record.split(";"):
        name, separator, value = part.partition("=")
        if separator and name.strip().lower() == tag:
            value = value.strip()
            return value.lower() if tag == "p" else value
    return None


def anti_spoofing_to_dict(result: AntiSpoofingResult) -> Dict[str, Any]:
    return asdict(result)
