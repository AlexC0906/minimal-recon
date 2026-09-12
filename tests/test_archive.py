import httpx
import pytest

from minimal_recon.services.archive import enumerate_archive


class FakeClient:
    def get(self, url, params):
        return httpx.Response(
            200,
            json=[
                ["timestamp", "original", "statuscode", "mimetype"],
                ["20200101000000", "https://example.test/", "200", "text/html"],
                ["20210101000000", "https://example.test/about", "200", "text/html"],
            ],
            request=httpx.Request("GET", url),
        )


def test_enumerate_archive_parses_snapshots():
    result = enumerate_archive("Example.Test.", client=FakeClient())

    assert result.domain == "example.test"
    assert len(result.snapshots) == 2
    assert result.snapshots[0].archive_url.endswith("/20200101000000/https://example.test/")
    assert result.source.startswith("https://web.archive.org")


@pytest.mark.parametrize("limit", [0, 1001])
def test_enumerate_archive_rejects_invalid_limit(limit):
    with pytest.raises(ValueError):
        enumerate_archive("example.test", client=FakeClient(), limit=limit)
