import httpx
import pytest

from minimal_recon.services.subdomains import enumerate_subdomains


class FakeClient:
    def get(self, url):
        return httpx.Response(
            200,
            json=[
                {"name_value": "*.Example.Test\napi.example.test"},
                {"name_value": "mail.example.test\nexternal.other.test"},
            ],
            request=httpx.Request("GET", url),
        )


def test_enumerate_subdomains_filters_and_deduplicates_names():
    result = enumerate_subdomains("Example.Test.", client=FakeClient())

    assert result.domain == "example.test"
    assert result.subdomains == ["api.example.test", "example.test", "mail.example.test"]
    assert "crt.sh" in result.source


@pytest.mark.parametrize("domain", ["", "example test", "example..test"])
def test_enumerate_subdomains_validates_domain(domain):
    with pytest.raises(ValueError):
        enumerate_subdomains(domain, client=FakeClient())
