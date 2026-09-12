import httpx
import pytest

from minimal_recon.services.shodan import lookup_host


class FakeClient:
    def get(self, url, params):
        assert params == {"key": "test-key"}
        return httpx.Response(
            200,
            json={
                "org": "Example Hosting",
                "isp": "Example ISP",
                "asn": "AS64500",
                "country_name": "Exampleland",
                "city": "Example City",
                "hostnames": ["b.example.test", "a.example.test", "a.example.test"],
                "ports": [443, 80, 443],
                "domains": ["example.test"],
                "last_update": "2026-09-12",
            },
            request=httpx.Request("GET", url),
        )


def test_lookup_host_reads_indexed_host_data():
    result = lookup_host("192.0.2.10", api_key="test-key", client=FakeClient())

    assert result.organization == "Example Hosting"
    assert result.hostnames == ["a.example.test", "b.example.test"]
    assert result.ports == [80, 443]


def test_lookup_host_requires_api_key(monkeypatch):
    monkeypatch.delenv("SHODAN_API_KEY", raising=False)

    with pytest.raises(ValueError, match="SHODAN_API_KEY"):
        lookup_host("192.0.2.10", client=FakeClient())


def test_lookup_host_rejects_domain():
    with pytest.raises(ValueError, match="valid IP"):
        lookup_host("example.test", api_key="test-key", client=FakeClient())
