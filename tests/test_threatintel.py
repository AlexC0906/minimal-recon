import httpx
import pytest

from minimal_recon.services.threatintel import check_reputation


class FakeClient:
    def get(self, url, headers):
        assert headers["x-apikey"] == "test-key"
        return httpx.Response(
            200,
            json={
                "data": {
                    "attributes": {
                        "last_analysis_stats": {
                            "malicious": 1,
                            "suspicious": 2,
                            "harmless": 40,
                            "undetected": 10,
                        },
                        "reputation": -3,
                    }
                }
            },
            request=httpx.Request("GET", url),
        )


def test_check_reputation_reads_external_stats():
    result = check_reputation("192.0.2.10", api_key="test-key", client=FakeClient())

    assert result.target_type == "ip"
    assert result.malicious == 1
    assert result.suspicious == 2
    assert result.reputation == -3


def test_check_reputation_requires_api_key(monkeypatch):
    monkeypatch.delenv("VT_API_KEY", raising=False)

    with pytest.raises(ValueError, match="VT_API_KEY"):
        check_reputation("example.test", client=FakeClient())
