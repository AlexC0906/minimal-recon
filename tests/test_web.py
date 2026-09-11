import httpx
import pytest

from minimal_recon.services.web import check_web, validate_url


class FakeClient:
    def get(self, url):
        return httpx.Response(
            200,
            headers={
                "strict-transport-security": "max-age=31536000",
                "content-security-policy": "default-src 'self'",
            },
            request=httpx.Request("GET", url),
        )


def test_check_web_reports_security_headers():
    result = check_web("https://example.test", client=FakeClient())

    assert result.status_code == 200
    assert result.security_headers["strict-transport-security"] == "max-age=31536000"
    assert "x-frame-options" in result.missing_security_headers


@pytest.mark.parametrize("url", ["example.test", "ftp://example.test", "https://"])
def test_validate_url_requires_http_scheme_and_host(url):
    with pytest.raises(ValueError):
        validate_url(url)
