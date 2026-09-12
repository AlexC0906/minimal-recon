import httpx

from minimal_recon.services.public_files import discover_public_files


class FakeClient:
    def get(self, url):
        status = 200 if url.endswith("robots.txt") else 404
        return httpx.Response(
            status,
            content=b"User-agent: *\nDisallow: /private" if status == 200 else b"",
            headers={"content-type": "text/plain"},
            request=httpx.Request("GET", url),
        )


def test_discover_public_files_checks_only_standard_paths():
    results = discover_public_files("https://example.test", client=FakeClient())

    assert results[0].path == "/robots.txt"
    assert results[0].found is True
    assert results[0].size_bytes > 0
    assert all(result.path in {"/robots.txt", "/sitemap.xml", "/security.txt", "/.well-known/security.txt", "/humans.txt"} for result in results)
