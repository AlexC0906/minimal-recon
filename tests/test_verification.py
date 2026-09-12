import httpx
import pytest

from minimal_recon.services.verification import create_token, verify_urls


class FakeClient:
    def get(self, url):
        return httpx.Response(
            200,
            text="<html>minimal-recon-verify-demo</html>" if "one" in url else "<html>profile</html>",
            request=httpx.Request("GET", url),
        )


def test_verify_urls_requires_exact_token():
    results = verify_urls(
        ["https://one.example", "https://two.example"],
        "minimal-recon-verify-demo",
        client=FakeClient(),
    )

    assert [item.verified for item in results] == [True, False]
    assert results[0].evidence == "exact verification token found"


def test_create_token_has_expected_prefix():
    assert create_token().startswith("minimal-recon-verify-")


@pytest.mark.parametrize("urls, token", [([], "token"), (["example.test"], "token")])
def test_verify_urls_rejects_invalid_input(urls, token):
    with pytest.raises(ValueError):
        verify_urls(urls, token, client=FakeClient())
