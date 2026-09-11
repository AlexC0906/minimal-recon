"""Passive subdomain discovery from Certificate Transparency logs."""

from dataclasses import dataclass, asdict
from typing import Any, Dict, List, Optional

import httpx

from minimal_recon.services.dns import normalize_domain


CRT_SH_URL = "https://crt.sh/?q=%25.{domain}&output=json"


@dataclass(frozen=True)
class SubdomainResult:
    domain: str
    subdomains: List[str]
    source: str


def enumerate_subdomains(
    domain: str, client: Optional[httpx.Client] = None
) -> SubdomainResult:
    """Collect unique in-scope names from public certificate records."""
    domain = normalize_domain(domain.lower())
    source = CRT_SH_URL.format(domain=domain)

    def request(active_client: httpx.Client) -> SubdomainResult:
        response = active_client.get(source)
        response.raise_for_status()
        try:
            certificates = response.json()
        except ValueError as error:
            raise ValueError("Certificate Transparency returned invalid JSON") from error

        suffix = f".{domain}"
        names = set()
        for certificate in certificates:
            for name in str(certificate.get("name_value", "")).splitlines():
                name = name.strip().lower().lstrip("*.")
                if name == domain or name.endswith(suffix):
                    names.add(name)
        return SubdomainResult(domain, sorted(names), source)

    if client is not None:
        return request(client)
    with httpx.Client(timeout=10, follow_redirects=True) as active_client:
        return request(active_client)


def subdomains_to_dict(result: SubdomainResult) -> Dict[str, Any]:
    """Serialize subdomain results for CLI output."""
    return asdict(result)
