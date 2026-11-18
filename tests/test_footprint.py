import json

import httpx
import pytest

from minimal_recon.services import footprint
from minimal_recon.services.footprint import (
    SITES,
    SiteRule,
    check_username,
    classify_response,
    load_registry,
    run_self_test,
    summarize_public_page,
    validate_username,
)


def _response(status_code, url, text="", headers=None):
    return httpx.Response(status_code, text=text, headers=headers, request=httpx.Request("GET", url))


class RoutingClient:
    """Answer by URL so results do not depend on request order across threads."""

    def __init__(self, routes):
        self.routes = routes
        self.urls = []

    def get(self, url):
        self.urls.append(url)
        status_code, text = self.routes[url]
        return _response(status_code, url, text)


def test_check_username_uses_plain_templates_and_keeps_registry_order():
    client = RoutingClient(
        {
            "https://one.test/alice": (200, '<title>Alice Profile</title><meta name="description" content="Hi">alice'),
            "https://two.test/alice": (404, "page not found"),
        }
    )

    results = check_username(
        "alice",
        sites={"one": "https://one.test/{username}", "two": "https://two.test/{username}"},
        client=client,
    )

    assert [result.site for result in results] == ["one", "two"]
    assert [result.state for result in results] == ["found", "not_found"]
    assert results[0].match_basis == "profile_marker"
    assert results[0].page_title == "Alice Profile"
    assert results[0].meta_description == "Hi"
    assert results[0].confidence == "likely"
    assert results[1].match_basis == "http_status_404"
    assert all(result.checked_at for result in results)
    assert sorted(client.urls) == ["https://one.test/alice", "https://two.test/alice"]


def test_api_rule_reports_confirmed_answers_and_profile_url():
    rule = SiteRule(
        name="api",
        url="https://site.test/{username}",
        probe_url="https://api.site.test/users/{username_lower}",
        source="api",
    )
    client = RoutingClient({"https://api.site.test/users/alice": (200, "{}")})

    result = check_username("Alice", sites={"api": rule}, client=client)[0]

    assert result.state == "found"
    assert result.confidence == "confirmed"
    assert result.url == "https://site.test/Alice"
    assert result.final_url == "https://api.site.test/users/alice"
    assert result.page_title == ""


def test_username_invalid_for_site_is_not_requested():
    rule = SiteRule(name="strict", url="https://strict.test/{username}", username_pattern="[a-z]{3,5}")
    client = RoutingClient({})

    result = check_username("a.b", sites={"strict": rule}, client=client)[0]

    assert result.state == "not_applicable"
    assert result.match_basis == "username_not_valid_on_site"
    assert client.urls == []


@pytest.mark.parametrize(
    "rule_options, status_code, text, url, expected",
    [
        ({}, 404, "", "https://s.test/alice", ("not_found", "http_status_404")),
        ({}, 200, "", "https://s.test/alice", ("found", "http_status_200")),
        ({"found_text": '"user":"{username}"'}, 200, '{"USER":"Alice"}', "https://s.test/alice",
         ("found", "profile_marker")),
        ({"found_text": '"user":"{username}"'}, 200, "<html>login</html>", "https://s.test/alice",
         ("unknown", "no_profile_marker")),
        ({"not_found_text": "no such user"}, 200, "No such user here", "https://s.test/alice",
         ("not_found", "not_found_marker")),
        ({"not_found_body": "null"}, 200, " null\n", "https://s.test/alice", ("not_found", "empty_result")),
        ({"unknown_url": "/login"}, 200, "alice", "https://s.test/login?next=alice",
         ("unknown", "platform_challenge_or_consent")),
        ({}, 500, "", "https://s.test/alice", ("unknown", "http_status_500")),
        ({}, 429, "", "https://s.test/alice", ("rate_limited", "http_status_429")),
    ],
)
def test_classify_response(rule_options, status_code, text, url, expected):
    rule = SiteRule(name="s", url="https://s.test/{username}", **rule_options)

    assert classify_response(rule, "alice", _response(status_code, url, text)) == expected


def test_exhausted_api_quota_is_rate_limited():
    rule = SiteRule(name="s", url="https://s.test/{username}")
    response = _response(403, "https://s.test/alice", headers={"x-ratelimit-remaining": "0"})

    assert classify_response(rule, "alice", response)[0] == "rate_limited"


def test_short_retry_after_is_honoured_once(monkeypatch):
    sleeps = []
    monkeypatch.setattr(footprint.time, "sleep", sleeps.append)
    answers = iter([(429, {"retry-after": "2"}), (200, {})])

    class RetryClient:
        def get(self, url):
            status_code, headers = next(answers)
            return _response(status_code, url, headers=headers)

    rule = SiteRule(name="s", url="https://s.test/{username}")
    result = footprint.check_site(rule, "alice", RetryClient())

    assert result.state == "found"
    assert sleeps == [2.0]


def test_long_retry_after_is_reported_without_waiting(monkeypatch):
    monkeypatch.setattr(footprint.time, "sleep", lambda seconds: pytest.fail("should not sleep"))

    class LimitedClient:
        def get(self, url):
            return _response(429, url, headers={"retry-after": "3600"})

    result = footprint.check_site(SiteRule(name="s", url="https://s.test/{username}"), "alice", LimitedClient())

    assert result.state == "rate_limited"


def test_self_test_flags_broken_rules():
    good = SiteRule(name="good", url="https://good.test/{username}", known_present="yes", known_absent="no")
    broken = SiteRule(name="broken", url="https://broken.test/{username}", known_present="yes", known_absent="no")
    blocked = SiteRule(name="blocked", url="https://blocked.test/{username}", known_present="yes", known_absent="no")
    client = RoutingClient(
        {
            "https://good.test/yes": (200, ""),
            "https://good.test/no": (404, ""),
            "https://broken.test/yes": (200, ""),
            "https://broken.test/no": (200, ""),
            "https://blocked.test/yes": (503, ""),
            "https://blocked.test/no": (503, ""),
        }
    )

    report = run_self_test({"good": good, "broken": broken, "blocked": blocked}, client=client)

    assert [(entry["site"], entry["status"]) for entry in report] == [
        ("good", "ok"),
        ("broken", "broken"),
        ("blocked", "inconclusive"),
    ]
    assert report[1]["absent"] == "found"


def test_bundled_registry_rules_are_self_consistent():
    assert {"github", "gitlab", "instagram", "tiktok", "x", "telegram"}.issubset(SITES)
    for rule in SITES.values():
        assert rule.known_present and rule.known_absent, rule.name
        assert rule.accepts(rule.known_present), rule.name
        assert rule.accepts(rule.known_absent), rule.name
        assert rule.request_url("alice").startswith("https://"), rule.name


def test_load_registry_reads_custom_file_and_rejects_bad_rules(tmp_path):
    valid = tmp_path / "sites.json"
    valid.write_text(
        json.dumps({"sites": [{"name": "one", "url": "https://one.test/{username}", "not_found_status": [404, 400]}]}),
        encoding="utf-8",
    )
    missing_placeholder = tmp_path / "bad.json"
    missing_placeholder.write_text(
        json.dumps({"sites": [{"name": "one", "url": "https://one.test/"}]}), encoding="utf-8"
    )
    unknown_key = tmp_path / "typo.json"
    unknown_key.write_text(
        json.dumps({"sites": [{"name": "one", "url": "https://one.test/{username}", "fond_text": "x"}]}),
        encoding="utf-8",
    )

    assert load_registry(valid)["one"].not_found_status == (404, 400)
    with pytest.raises(ValueError, match="contain"):
        load_registry(missing_placeholder)
    with pytest.raises(ValueError, match="fond_text"):
        load_registry(unknown_key)


@pytest.mark.parametrize("username", ["", "bad user", "<script>", "a" * 65, "..", "a/b", "a?b"])
def test_validate_username_rejects_unsafe_values(username):
    with pytest.raises(ValueError):
        validate_username(username)


def test_validate_username_accepts_leading_underscore():
    assert validate_username(" _alice.dev ") == "_alice.dev"


def test_summarize_public_page_tolerates_valueless_meta_attributes():
    assert summarize_public_page("<meta name><meta name=description content><title>Hi</title>") == ("Hi", "")


DETAIL_RULE = SiteRule(
    name="api",
    url="https://site.test/{username}",
    probe_url="https://api.site.test/{username}",
    source="api",
    profile_fields={
        "display_name": "user.name",
        "bio": "user.about",
        "location": "user.location",
        "created_at": "user.created",
        "declared_accounts": {"x": "user.twitter", "github": "user.github"},
    },
)
DETAIL_BODY = json.dumps(
    {
        "user": {
            "name": "  Alice   Example ",
            "about": "<p>Builds &amp; breaks</p>",
            "location": None,
            "created": 1_600_000_000_000,
            "twitter": "alice_x",
            "github": "",
            "email": "alice@example.test",
        }
    }
)


def test_details_extract_only_allowlisted_self_published_fields():
    client = RoutingClient({"https://api.site.test/alice": (200, DETAIL_BODY)})

    result = check_username("alice", sites={"api": DETAIL_RULE}, client=client, details=True)[0]

    assert result.profile == {
        "display_name": "Alice Example",
        "bio": "Builds & breaks",
        "created_at": "2020-09-13T12:26:40+00:00",
        "declared_accounts": {"x": "alice_x"},
    }
    assert "alice@example.test" not in json.dumps(result.profile)


def test_details_are_off_by_default():
    client = RoutingClient({"https://api.site.test/alice": (200, DETAIL_BODY)})

    assert check_username("alice", sites={"api": DETAIL_RULE}, client=client)[0].profile == {}


@pytest.mark.parametrize(
    "options, message",
    [
        ({"source": "api", "profile_fields": {"email": "email"}}, "unsupported profile field"),
        ({"source": "html", "profile_fields": {"bio": "bio"}}, "need an api source"),
    ],
)
def test_profile_fields_are_restricted(options, message):
    with pytest.raises(ValueError, match=message):
        SiteRule(name="s", url="https://s.test/{username}", **options)


def test_stats_accept_only_numbers():
    rule = SiteRule(
        name="api",
        url="https://site.test/{username}",
        source="api",
        profile_fields={"stats": {"followers": "followers", "repos": "repos", "bio": "bio", "flag": "flag"}},
    )
    body = json.dumps({"followers": 12, "repos": "7", "bio": "free text", "flag": True})
    client = RoutingClient({"https://site.test/alice": (200, body)})

    result = check_username("alice", sites={"api": rule}, client=client, details=True)[0]

    assert result.profile == {"stats": {"followers": 12, "repos": 7}}


OPT_OUT_RULE = SiteRule(
    name="fedi",
    url="https://fedi.test/@{username}",
    source="api",
    opt_out_path="noindex",
    profile_fields={"display_name": "display_name"},
)


def test_owner_opt_out_withholds_details():
    body = json.dumps({"display_name": "Alice", "noindex": True})
    client = RoutingClient({"https://fedi.test/@alice": (200, body)})

    result = check_username("alice", sites={"fedi": OPT_OUT_RULE}, client=client, details=True)[0]

    assert result.found is True
    assert result.profile == {}
    assert result.profile_note == footprint.OPT_OUT_NOTE


def test_verified_owner_sees_own_details_despite_opt_out():
    token = "minimal-recon-verify-abcdefgh12"
    body = json.dumps({"display_name": "Alice", "noindex": True, "note": token})
    client = RoutingClient({"https://fedi.test/@alice": (200, body)})

    result = check_username("alice", sites={"fedi": OPT_OUT_RULE}, client=client, audit_token=token)[0]

    assert result.owner_verified is True
    assert result.profile == {"display_name": "Alice"}


AUDIT_TOKEN = "minimal-recon-verify-abcdefgh12"
AUDIT_SITES = {
    "devto": SiteRule(
        name="devto",
        url="https://dev.test/{username}",
        source="api",
        profile_fields={"declared_accounts": {"github": "github", "x": "twitter"}},
    ),
    "github": SiteRule(name="github", url="https://gh.test/{username}", source="api"),
    "x": SiteRule(name="x", url="https://x.test/{username}"),
}


def test_self_audit_follows_declared_accounts_of_verified_profiles_only():
    client = RoutingClient(
        {
            "https://dev.test/alice": (
                200,
                json.dumps({"github": "alice-gh", "twitter": "@alice_x", "bio": AUDIT_TOKEN}),
            ),
            "https://gh.test/alice": (404, ""),
            "https://x.test/alice": (404, ""),
            "https://gh.test/alice-gh": (200, f"<p>{AUDIT_TOKEN}</p>"),
            "https://x.test/alice_x": (200, "no token here"),
        }
    )

    results = check_username("alice", sites=AUDIT_SITES, client=client, audit_token=AUDIT_TOKEN)

    followed = {result.url: result for result in results if result.discovered_from}
    assert results[0].owner_verified is True
    assert followed["https://gh.test/alice-gh"].owner_verified is True
    assert followed["https://gh.test/alice-gh"].discovered_from == "devto:github"
    assert followed["https://x.test/alice_x"].owner_verified is False


def test_declared_accounts_are_not_followed_without_audit_or_verification():
    body = json.dumps({"github": "alice-gh", "twitter": "alice_x"})
    routes = {
        "https://dev.test/alice": (200, body),
        "https://gh.test/alice": (404, ""),
        "https://x.test/alice": (404, ""),
    }

    plain = RoutingClient(dict(routes))
    check_username("alice", sites=AUDIT_SITES, client=plain, details=True)
    unverified = RoutingClient(dict(routes))
    results = check_username("alice", sites=AUDIT_SITES, client=unverified, audit_token=AUDIT_TOKEN)

    assert sorted(plain.urls) == sorted(routes)
    assert sorted(unverified.urls) == sorted(routes)
    assert results[0].owner_verified is False


def test_audit_token_must_look_like_a_generated_token():
    with pytest.raises(ValueError, match="audit token"):
        check_username("alice", sites=AUDIT_SITES, client=RoutingClient({}), audit_token="short")


def test_mastodon_rule_targets_another_server():
    rule = footprint.mastodon_rule("Fosstodon.org")

    assert rule.name == "mastodon@fosstodon.org"
    assert rule.profile_url("alice") == "https://fosstodon.org/@alice"
    assert rule.request_url("alice").startswith("https://fosstodon.org/api/v1/accounts/lookup")
    assert rule.opt_out_path == "noindex"
    with pytest.raises(ValueError):
        footprint.mastodon_rule("https://evil.test/path")


def test_search_links_are_built_without_requests():
    links = footprint.search_links("alice_dev", sites=AUDIT_SITES)

    assert links["search_engines"]["google"] == "https://www.google.com/search?q=%22alice_dev%22"
    assert links["archived_profiles"]["github"] == "https://web.archive.org/web/*/https://gh.test/alice_dev"


INSTAGRAM = SITES["instagram"]


@pytest.mark.parametrize(
    "description, expected",
    [
        (
            '268M Followers, 196 Following, 32K Posts - National Geographic (@natgeo) on Instagram: "Explore"',
            {
                "display_name": "National Geographic",
                "bio": "Explore",
                "stats": {"followers": 268_000_000, "following": 196, "posts": 32_000},
            },
        ),
        (
            "1,234 Followers, 56 Following, 7 Posts - See Instagram photos and videos from Ana Pop (@ana.pop)",
            {"display_name": "Ana Pop", "stats": {"followers": 1234, "following": 56, "posts": 7}},
        ),
        ("Instagram photos and videos", {}),
    ],
)
def test_instagram_meta_description_becomes_profile_details(description, expected):
    assert footprint.extract_meta_profile(INSTAGRAM, description) == expected


@pytest.mark.parametrize("text, expected", [("1,234", 1234), ("32K", 32000), ("2.5M", 2_500_000), ("x", None)])
def test_parse_count(text, expected):
    assert footprint.parse_count(text) == expected


def test_html_details_come_from_meta_description():
    page = (
        '<title>Ana (@ana) • Instagram</title><meta name="description" content="10 Followers, 2 Following, '
        '3 Posts - See Instagram photos and videos from Ana (@ana)">"username":"ana"'
    )
    client = RoutingClient({"https://www.instagram.com/ana/": (200, page)})

    with_details = check_username("ana", sites={"instagram": INSTAGRAM}, client=client, details=True)[0]
    without = check_username("ana", sites={"instagram": INSTAGRAM}, client=client)[0]

    assert with_details.profile == {"display_name": "Ana", "stats": {"followers": 10, "following": 2, "posts": 3}}
    assert without.profile == {}


@pytest.mark.parametrize(
    "options, message",
    [
        ({"source": "api", "meta_pattern": "(?P<bio>.*)"}, "needs an html source"),
        ({"meta_pattern": "(?P<email>.*)"}, "unsupported meta_pattern group"),
    ],
)
def test_meta_pattern_is_restricted(options, message):
    with pytest.raises(ValueError, match=message):
        SiteRule(name="s", url="https://s.test/{username}", **options)
