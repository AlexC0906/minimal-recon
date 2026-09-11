import httpx
import pytest

from minimal_recon.services.footprint import SITES, check_username, validate_username


class FakeClient:
    def __init__(self, status_codes):
        self.status_codes = iter(status_codes)
        self.urls = []

    def get(self, url):
        self.urls.append(url)
        return httpx.Response(next(self.status_codes), request=httpx.Request("GET", url))


def test_check_username_uses_registry_and_records_status():
    client = FakeClient([200, 404])

    results = check_username(
        "alice",
        sites={"one": "https://one.test/{username}", "two": "https://two.test/{username}"},
        client=client,
    )

    assert [result.found for result in results] == [True, False]
    assert [result.status_code for result in results] == [200, 404]
    assert all(result.confidence == "low" for result in results)
    assert all(result.checked_at for result in results)
    assert client.urls == ["https://one.test/alice", "https://two.test/alice"]


def test_default_registry_contains_public_social_sites():
    assert {
        "github",
        "instagram",
        "reddit",
        "x",
        "tiktok",
        "youtube",
        "twitch",
        "pinterest",
        "medium",
        "devto",
    }.issubset(SITES)


@pytest.mark.parametrize("username", ["", "bad user", "<script>", "a" * 40])
def test_validate_username_rejects_unsafe_values(username):
    with pytest.raises(ValueError):
        validate_username(username)
