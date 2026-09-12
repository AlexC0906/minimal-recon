import httpx
import pytest

from minimal_recon.services.links import extract_links


class FakeClient:
    def get(self, url):
        return httpx.Response(
            200,
            text=(
                '<a href="/about#team">About</a>'
                '<a href="https://example.test/contact">Contact</a>'
                '<a href="https://external.test/page">External</a>'
                '<a href="mailto:test@example.test">Mail</a>'
            ),
            request=httpx.Request("GET", url),
        )


def test_extract_links_normalizes_and_separates_links():
    result = extract_links("https://example.test/", client=FakeClient())

    assert result.internal_links == ["https://example.test/about", "https://example.test/contact"]
    assert result.external_links == ["https://external.test/page"]
    assert result.links_found == 3


@pytest.mark.parametrize("url", ["example.test", "ftp://example.test"])
def test_extract_links_rejects_invalid_url(url):
    with pytest.raises(ValueError):
        extract_links(url, client=FakeClient())
