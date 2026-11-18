"""Single-page public link extraction without recursive crawling."""

from dataclasses import asdict, dataclass
from html.parser import HTMLParser
from typing import Any, Dict, List, Optional
from urllib.parse import urldefrag, urljoin, urlparse

import httpx

from minimal_recon.services.http import with_client
from minimal_recon.services.web import validate_url


@dataclass(frozen=True)
class LinkResult:
    source_url: str
    final_url: str
    internal_links: List[str]
    external_links: List[str]
    links_found: int


class _LinkParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.hrefs: List[str] = []

    def handle_starttag(self, tag: str, attrs: List[tuple[str, Optional[str]]]) -> None:
        if tag.lower() != "a":
            return
        href = dict(attrs).get("href")
        if href:
            self.hrefs.append(href)


def extract_links(
    url: str,
    client: Optional[httpx.Client] = None,
    max_links: int = 500,
) -> LinkResult:
    """Extract normalized HTTP(S) links from one public HTML page."""
    normalized_url = validate_url(url)
    if max_links < 1 or max_links > 5000:
        raise ValueError("max_links must be between 1 and 5000")

    def request(active_client: httpx.Client) -> LinkResult:
        response = active_client.get(normalized_url)
        response.raise_for_status()
        parser = _LinkParser()
        parser.feed(response.text[:2_000_000])
        final_url = str(response.url)
        origin = urlparse(final_url).netloc.lower()
        links = []
        for href in parser.hrefs:
            try:
                candidate, _ = urldefrag(urljoin(final_url, href.strip()))
                parsed = urlparse(candidate)
            except ValueError:
                # One malformed href (e.g. a broken IPv6 literal) must not fail the page.
                continue
            if parsed.scheme in ("http", "https") and parsed.netloc and candidate not in links:
                links.append(candidate)
            if len(links) >= max_links:
                break
        internal = sorted(link for link in links if urlparse(link).netloc.lower() == origin)
        external = sorted(link for link in links if urlparse(link).netloc.lower() != origin)
        return LinkResult(normalized_url, final_url, internal, external, len(links))

    return with_client(request, client, timeout=10)


def links_to_dict(result: LinkResult) -> Dict[str, Any]:
    return asdict(result)
