import httpx
import pytest

from minimal_recon.services.web import check_web, detect_technologies, detect_waf, validate_url


class FakeClient:
    def get(self, url):
        return httpx.Response(
            200,
            headers={
                "strict-transport-security": "max-age=31536000",
                "content-security-policy": "default-src 'self'",
                "cf-ray": "abc123",
                "server": "nginx",
            },
            request=httpx.Request("GET", url),
        )


def test_check_web_reports_security_headers():
    result = check_web("https://example.test", client=FakeClient())

    assert result.status_code == 200
    assert result.security_headers["strict-transport-security"] == "max-age=31536000"
    assert "x-frame-options" in result.missing_security_headers
    assert result.waf_vendor == "Cloudflare"
    assert result.waf_confidence == "heuristic"
    assert result.technologies["Server"] == ("nginx",)


def test_detect_technologies_reads_html_fingerprints():
    headers = httpx.Headers({"x-powered-by": "PHP/8.2"})
    technologies = detect_technologies(
        headers,
        '<script src="/_next/static/app.js"></script><link href="/wp-content/themes/site.css">',
    )

    assert "Next.js" in technologies
    assert "WordPress" in technologies
    assert technologies["X-Powered-By"] == ("php/8.2",)


def test_detect_waf_returns_not_detected_without_fingerprint():
    vendor, signals, confidence = detect_waf(httpx.Headers({"server": "nginx"}), "plain page")

    assert vendor is None
    assert signals == ()
    assert confidence == "not_detected"


@pytest.mark.parametrize("url", ["example.test", "ftp://example.test", "https://"])
def test_validate_url_requires_http_scheme_and_host(url):
    with pytest.raises(ValueError):
        validate_url(url)
