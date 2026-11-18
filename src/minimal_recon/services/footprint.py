"""Explicit, low-volume username footprint checks driven by per-site rules."""

from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field, replace
from datetime import datetime, timezone
import html
from html.parser import HTMLParser
from importlib import resources
import json
from pathlib import Path
import re
import time
from typing import Any, Dict, List, Mapping, Optional, Tuple, Union
from urllib.parse import quote_plus, urlparse

import httpx

from minimal_recon.services.dns import normalize_domain
from minimal_recon.services.http import with_client

# Result states.
FOUND = "found"
NOT_FOUND = "not_found"
UNKNOWN = "unknown"
NOT_APPLICABLE = "not_applicable"
RATE_LIMITED = "rate_limited"

# Requests to one host are spaced by the caller's delay; different hosts run
# side by side, so no single site sees more than one request at a time.
MAX_WORKERS = 8
MAX_RETRY_AFTER_SECONDS = 10.0
_BODY_LIMIT = 2_000_000


@dataclass(frozen=True)
class FootprintResult:
    site: str
    url: str
    found: bool
    status_code: Optional[int] = None
    match_basis: str = "request_error"
    state: str = UNKNOWN
    checked_at: str = ""
    final_url: str = ""
    page_title: str = ""
    meta_description: str = ""
    # "confirmed" for answers read from a public API, "likely" for answers
    # inferred from an HTML page, empty when the state is not a yes/no answer.
    confidence: str = ""
    # Self-published profile fields, filled only when details were requested.
    profile: Dict[str, Any] = field(default_factory=dict)
    # Why ``profile`` is empty although details were requested (owner opt-out).
    profile_note: str = ""
    # Self-audit mode only: whether the audit token was found on this profile.
    owner_verified: Optional[bool] = None
    # Self-audit mode only: "<site>:<label>" of the verified profile that declared this account.
    discovered_from: str = ""


# The only profile fields ever extracted. They are what a person chose to show
# on that profile, plus public totals the profile displays. Contact data (email,
# phone), employer, avatars, activity times ("last online", "playing now") and
# cross-account proofs are deliberately not collected, even where an API returns them.
PROFILE_FIELDS = ("display_name", "bio", "location", "website", "created_at", "declared_accounts", "stats")
_PROFILE_TEXT_LIMIT = 300
_META_TEXT_FIELDS = ("display_name", "bio", "location", "website")
_COUNT_SUFFIXES = {"k": 1_000, "m": 1_000_000, "b": 1_000_000_000}
OPT_OUT_NOTE ="the profile owner opted out of search indexing; details withheld"

# Declared-account labels that self-audit mode may follow, mapped to registry sites.
DECLARED_ACCOUNT_SITES = {"x": "x", "github": "github"}

SEARCH_ENGINES = {
    "google": "https://www.google.com/search?q={query}",
    "bing": "https://www.bing.com/search?q={query}",
    "duckduckgo": "https://duckduckgo.com/?q={query}",
}


@dataclass(frozen=True)
class SiteRule:
    """How to decide whether a username exists on one site.

    Templates accept ``{username}`` and ``{username_lower}``. Text markers are
    compared case-insensitively against the response body.
    """

    name: str
    url: str
    probe_url: str = ""
    source: str = "html"
    username_pattern: str = r"[A-Za-z0-9_.-]{1,64}"
    found_status: Tuple[int, ...] = (200,)
    not_found_status: Tuple[int, ...] = (404, 410)
    found_text: Optional[str] = None
    not_found_text: Optional[str] = None
    not_found_body: Optional[str] = None
    unknown_url: Optional[str] = None
    known_present: Optional[str] = None
    known_absent: Optional[str] = None
    # Maps PROFILE_FIELDS names to dotted JSON paths in an API response.
    # ``declared_accounts`` and ``stats`` map a label to a path instead.
    profile_fields: Optional[Dict[str, Any]] = field(default=None, compare=False)
    # JSON path of a flag the owner sets to opt out of indexing (e.g. Mastodon "noindex").
    # When it is true, details are withheld unless the owner is verified.
    opt_out_path: Optional[str] = None
    # HTML sources only: regular expression applied to the page's public meta
    # description. Named groups must be PROFILE_FIELDS text fields or ``stats_<label>``.
    meta_pattern: Optional[str] = None
    _pattern: "re.Pattern[str]" = field(init=False, repr=False, compare=False)

    def __post_init__(self) -> None:
        if self.source not in ("api", "html"):
            raise ValueError(f"site {self.name}: source must be 'api' or 'html'")
        for template in (self.url, self.probe_url or self.url):
            if "{username" not in template or urlparse(template).scheme not in ("http", "https"):
                raise ValueError(f"site {self.name}: URLs must be http(s) and contain {{username}}")
        try:
            object.__setattr__(self, "_pattern", re.compile(self.username_pattern))
        except re.error as error:
            raise ValueError(f"site {self.name}: invalid username_pattern") from error
        if self.meta_pattern:
            if self.source != "html":
                raise ValueError(f"site {self.name}: meta_pattern needs an html source")
            try:
                groups = re.compile(self.meta_pattern).groupindex
            except re.error as error:
                raise ValueError(f"site {self.name}: invalid meta_pattern") from error
            invalid = sorted(
                group for group in groups if not group.startswith("stats_") and group not in _META_TEXT_FIELDS
            )
            if invalid:
                raise ValueError(f"site {self.name}: unsupported meta_pattern group(s) {', '.join(invalid)}")
        if self.opt_out_path and self.source != "api":
            raise ValueError(f"site {self.name}: opt_out_path needs an api source")
        if self.profile_fields:
            if self.source != "api":
                raise ValueError(f"site {self.name}: profile_fields need an api source")
            unknown = sorted(set(self.profile_fields) - set(PROFILE_FIELDS))
            if unknown:
                raise ValueError(
                    f"site {self.name}: unsupported profile field(s) {', '.join(unknown)}; "
                    f"allowed: {', '.join(PROFILE_FIELDS)}"
                )

    def accepts(self, username: str) -> bool:
        return self._pattern.fullmatch(username) is not None

    def profile_url(self, username: str) -> str:
        return _fill(self.url, username)

    def request_url(self, username: str) -> str:
        return _fill(self.probe_url or self.url, username)

    @property
    def host(self) -> str:
        return urlparse(self.probe_url or self.url).netloc.lower()


SiteRegistry = Mapping[str, Union[str, SiteRule]]


def _fill(template: str, username: str) -> str:
    return template.replace("{username_lower}", username.lower()).replace("{username}", username)


def load_registry(path: Optional[Path] = None) -> Dict[str, SiteRule]:
    """Load site rules from a JSON file, or the registry bundled with the tool."""
    try:
        if path is None:
            text = resources.files("minimal_recon").joinpath("data/sites.json").read_text(encoding="utf-8")
        else:
            text = path.read_text(encoding="utf-8")
        payload = json.loads(text)
    except ValueError as error:
        raise ValueError(f"site registry {path or 'sites.json'} is not valid JSON") from error

    entries = payload.get("sites") if isinstance(payload, dict) else None
    if not isinstance(entries, list) or not entries:
        raise ValueError("site registry must contain a non-empty 'sites' list")
    registry: Dict[str, SiteRule] = {}
    for entry in entries:
        if not isinstance(entry, dict) or not entry.get("name") or not entry.get("url"):
            raise ValueError("each site needs at least 'name' and 'url'")
        options = {key: value for key, value in entry.items() if not key.startswith("_")}
        for key in ("found_status", "not_found_status"):
            if key in options:
                options[key] = tuple(int(code) for code in options[key])
        try:
            rule = SiteRule(**options)
        except TypeError as error:
            raise ValueError(f"site {entry['name']}: {error}") from error
        if rule.name in registry:
            raise ValueError(f"site {rule.name} is defined twice")
        registry[rule.name] = rule
    return registry


SITES: Dict[str, SiteRule] = load_registry()


class _PageSummaryParser(HTMLParser):
    """Extract only public page title and meta description."""

    def __init__(self) -> None:
        super().__init__()
        self.title_parts: List[str] = []
        self.page_title = ""
        self.meta_description = ""
        self.in_title = False

    def handle_starttag(self, tag: str, attrs: List[Tuple[str, Optional[str]]]) -> None:
        attributes = dict(attrs)
        if tag.lower() == "title":
            self.in_title = True
        # Valueless attributes (<meta name>) are reported by the parser as None.
        if tag.lower() == "meta" and (attributes.get("name") or "").lower() == "description":
            self.meta_description = _compact_text(attributes.get("content") or "")[:300]

    def handle_endtag(self, tag: str) -> None:
        if tag.lower() == "title":
            self.in_title = False
            self.page_title = _compact_text(" ".join(self.title_parts))[:200]

    def handle_data(self, data: str) -> None:
        if self.in_title:
            self.title_parts.append(data)


def _compact_text(value: str) -> str:
    return " ".join(value.split())


def summarize_public_page(content: str) -> Tuple[str, str]:
    """Extract a minimal public page summary without collecting profile content."""
    parser = _PageSummaryParser()
    parser.feed(content[:500_000])
    return parser.page_title, parser.meta_description


def validate_username(username: str) -> str:
    """Validate a username before interpolating it into public profile URLs.

    Only URL-safe characters are accepted, and names made of dots alone are
    refused so they cannot turn into ``/..`` path segments.
    """
    normalized = username.strip()
    if not re.fullmatch(r"[A-Za-z0-9_.-]{1,64}", normalized) or set(normalized) == {"."}:
        raise ValueError("username must be 1-64 characters and contain only letters, numbers, _, ., or -")
    return normalized


def check_username(
    username: str,
    sites: Optional[SiteRegistry] = None,
    client: Optional[httpx.Client] = None,
    delay_seconds: float = 0.0,
    details: bool = False,
    audit_token: Optional[str] = None,
) -> List[FootprintResult]:
    """Check public profiles for one username without bypassing access controls.

    ``sites`` maps names to :class:`SiteRule` objects or to plain URL templates;
    a plain template counts a profile as found when the page mentions the name.
    With ``details``, found API profiles also report their self-published
    fields (see ``PROFILE_FIELDS``). Results keep the registry order.

    ``audit_token`` turns on self-audit mode for someone checking their own
    footprint: profiles that show the token are marked ``owner_verified``, and
    only those profiles' self-declared accounts are checked one hop further.
    """
    username = validate_username(username)
    if audit_token is not None:
        audit_token = _validate_token(audit_token)
        details = True
    rules = [_as_rule(name, value) for name, value in (sites if sites is not None else SITES).items()]

    by_host: Dict[str, List[int]] = {}
    for index, rule in enumerate(rules):
        by_host.setdefault(rule.host, []).append(index)
    results: List[Optional[FootprintResult]] = [None] * len(rules)

    def run_host(active_client: httpx.Client, indexes: List[int]) -> None:
        requested = False
        for index in indexes:
            rule = rules[index]
            if not rule.accepts(username):
                results[index] = _not_applicable(rule, username)
                continue
            if requested and delay_seconds > 0:
                time.sleep(delay_seconds)
            results[index] = check_site(rule, username, active_client, details=details, audit_token=audit_token)
            requested = True

    followed: List[FootprintResult] = []

    def follow_declared(active_client: httpx.Client) -> None:
        """Self-audit only: check accounts declared on owner-verified profiles."""
        rules_by_name = {rule.name: rule for rule in rules}
        seen = {(rule.name, username.lower()) for rule in rules}
        for result in [item for item in results if item is not None and item.owner_verified]:
            for label, handle in result.profile.get("declared_accounts", {}).items():
                target = rules_by_name.get(DECLARED_ACCOUNT_SITES.get(label, ""))
                handle = str(handle).strip().lstrip("@")
                if target is None or (target.name, handle.lower()) in seen or not target.accepts(handle):
                    continue
                try:
                    validate_username(handle)
                except ValueError:
                    continue
                seen.add((target.name, handle.lower()))
                found = check_site(target, handle, active_client, details=True, audit_token=audit_token)
                followed.append(replace(found, discovered_from=f"{result.site}:{label}"))

    def collect(active_client: httpx.Client) -> None:
        workers = max(1, min(MAX_WORKERS, len(by_host)))
        with ThreadPoolExecutor(max_workers=workers) as pool:
            futures = [pool.submit(run_host, active_client, indexes) for indexes in by_host.values()]
            for future in futures:
                future.result()
        if audit_token is not None:
            follow_declared(active_client)

    with_client(collect, client, timeout=10)
    return [result for result in results if result is not None] + followed


def check_site(
    rule: SiteRule,
    username: str,
    client: httpx.Client,
    details: bool = False,
    audit_token: Optional[str] = None,
) -> FootprintResult:
    """Request one site once (plus one retry after a short Retry-After) and classify it."""
    profile_url = rule.profile_url(username)
    checked_at = datetime.now(timezone.utc).isoformat()
    try:
        response = client.get(rule.request_url(username))
        retry_after = _retry_after(response)
        if retry_after is not None:
            time.sleep(retry_after)
            checked_at = datetime.now(timezone.utc).isoformat()
            response = client.get(rule.request_url(username))
    except httpx.HTTPError:
        return FootprintResult(rule.name, profile_url, False, match_basis="request_error", checked_at=checked_at)

    state, basis = classify_response(rule, username, response)
    page_title, meta_description = ("", "")
    if state == FOUND and rule.source == "html":
        page_title, meta_description = summarize_public_page(response.text[:_BODY_LIMIT])
    if state in (FOUND, NOT_FOUND):
        confidence = "confirmed" if rule.source == "api" else "likely"
    else:
        confidence = ""
    owner_verified: Optional[bool] = None
    if audit_token is not None and state == FOUND:
        owner_verified = audit_token in response.text[:_BODY_LIMIT]
    profile: Dict[str, Any] = {}
    profile_note = ""
    if details and state == FOUND and rule.profile_fields:
        if not owner_verified and _owner_opted_out(rule, response):
            profile_note = OPT_OUT_NOTE
        else:
            profile = extract_profile(rule, response)
    elif details and state == FOUND and rule.meta_pattern:
        profile = extract_meta_profile(rule, meta_description)
    return FootprintResult(
        rule.name,
        profile_url,
        state == FOUND,
        response.status_code,
        basis,
        state,
        checked_at,
        str(response.url),
        page_title,
        meta_description,
        confidence,
        profile,
        profile_note,
        owner_verified,
    )


def _owner_opted_out(rule: SiteRule, response: httpx.Response) -> bool:
    if not rule.opt_out_path:
        return False
    try:
        return _json_path(response.json(), rule.opt_out_path) is True
    except ValueError:
        return False


def extract_profile(rule: SiteRule, response: httpx.Response) -> Dict[str, Any]:
    """Read the allowlisted, self-published profile fields from an API response."""
    try:
        payload = response.json()
    except ValueError:
        return {}
    profile: Dict[str, Any] = {}
    for name, path in (rule.profile_fields or {}).items():
        if name == "declared_accounts":
            declared = {
                label: value
                for label, account_path in (path or {}).items()
                if (value := _clean_text(_json_path(payload, account_path)))
            }
            if declared:
                profile[name] = declared
            continue
        if name == "stats":
            stats = {
                label: number
                for label, stat_path in (path or {}).items()
                if (number := _clean_number(_json_path(payload, stat_path))) is not None
            }
            if stats:
                profile[name] = stats
            continue
        raw = _json_path(payload, path)
        value = _clean_timestamp(raw) if name == "created_at" else _clean_text(raw)
        if value:
            profile[name] = value
    return profile


def _json_path(payload: Any, path: str) -> Any:
    """Follow a dotted path such as ``them.0.profile.bio`` through dicts and lists."""
    current = payload
    for part in path.split("."):
        if isinstance(current, list) and part.isdigit() and int(part) < len(current):
            current = current[int(part)]
        elif isinstance(current, dict) and part in current:
            current = current[part]
        else:
            return None
    return current


def _clean_text(value: Any) -> str:
    """Flatten a value to short plain text: tags removed, entities decoded, whitespace compacted."""
    if value is None or isinstance(value, (dict, list, bool)):
        return ""
    text = html.unescape(re.sub(r"<[^>]+>", " ", str(value)))
    return _compact_text(text)[:_PROFILE_TEXT_LIMIT]


def extract_meta_profile(rule: SiteRule, meta_description: str) -> Dict[str, Any]:
    """Read allowlisted fields from the public meta description of a profile page."""
    match = re.match(rule.meta_pattern or "", meta_description, re.DOTALL) if rule.meta_pattern else None
    if match is None:
        return {}
    profile: Dict[str, Any] = {}
    stats: Dict[str, int] = {}
    for group, raw in match.groupdict().items():
        if raw is None:
            continue
        if group.startswith("stats_"):
            count = parse_count(raw)
            if count is not None:
                stats[group[len("stats_"):]] = count
        elif value := _clean_text(raw):
            profile[group] = value
    if stats:
        profile["stats"] = stats
    return profile


def parse_count(text: str) -> Optional[int]:
    """Turn display counts such as ``1,234``, ``32K`` or ``2.5M`` into integers.

    Abbreviated counts are approximate, exactly as the site shows them.
    """
    match = re.fullmatch(r"\s*([\d.,]+)\s*([kKmMbB]?)\s*", text)
    if not match:
        return None
    number, suffix = match.groups()
    try:
        if suffix:
            return int(float(number.replace(",", "")) * _COUNT_SUFFIXES[suffix.lower()])
        return int(number.replace(",", "").replace(".", ""))
    except ValueError:
        return None


def _clean_number(value: Any) -> Optional[Union[int, float]]:
    """Accept only numeric totals, so a ``stats`` path can never leak free text."""
    if isinstance(value, bool):
        return None
    if isinstance(value, (int, float)):
        return value
    if isinstance(value, str) and value.strip().isdigit():
        return int(value.strip())
    return None


def _clean_timestamp(value: Any) -> str:
    """Normalize Unix seconds or milliseconds to an ISO date; keep other text as is."""
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        seconds = value / 1000 if value > 10**11 else value
        try:
            return datetime.fromtimestamp(seconds, timezone.utc).isoformat()
        except (OverflowError, OSError, ValueError):
            return ""
    return _clean_text(value)


def classify_response(rule: SiteRule, username: str, response: httpx.Response) -> Tuple[str, str]:
    """Return ``(state, match_basis)`` for one response according to its site rule."""
    status = response.status_code
    final_url = str(response.url).lower()
    if _is_rate_limited(response):
        return RATE_LIMITED, f"http_status_{status}"
    if rule.unknown_url and rule.unknown_url.lower() in final_url:
        return UNKNOWN, "platform_challenge_or_consent"
    if status in rule.not_found_status:
        return NOT_FOUND, f"http_status_{status}"

    body = response.text[:_BODY_LIMIT].lower()
    if rule.not_found_body is not None and body.strip() == rule.not_found_body.lower():
        return NOT_FOUND, "empty_result"
    if rule.not_found_text and _fill(rule.not_found_text, username).lower() in body:
        return NOT_FOUND, "not_found_marker"
    if status not in rule.found_status:
        return UNKNOWN, f"http_status_{status}"
    if rule.found_text is None:
        return FOUND, f"http_status_{status}"
    if _fill(rule.found_text, username).lower() in body:
        return FOUND, "profile_marker"
    return UNKNOWN, "no_profile_marker"


def run_self_test(
    sites: Optional[SiteRegistry] = None,
    client: Optional[httpx.Client] = None,
) -> List[Dict[str, Any]]:
    """Check each rule against its known present and known absent usernames."""
    rules = [_as_rule(name, value) for name, value in (sites if sites is not None else SITES).items()]
    report: List[Dict[str, Any]] = [{} for _ in rules]

    def test_rule(active_client: httpx.Client, index: int) -> None:
        rule = rules[index]
        entry: Dict[str, Any] = {"site": rule.name, "present": None, "absent": None}
        if rule.known_present:
            entry["present"] = check_site(rule, rule.known_present, active_client).state
        if rule.known_absent:
            entry["absent"] = check_site(rule, rule.known_absent, active_client).state
        if not rule.known_present or not rule.known_absent:
            entry["status"] = "untested"
        elif entry["present"] == FOUND and entry["absent"] == NOT_FOUND:
            entry["status"] = "ok"
        elif entry["present"] == NOT_FOUND or entry["absent"] == FOUND:
            # A definite answer that is wrong: the site changed and the rule must be fixed.
            entry["status"] = "broken"
        elif RATE_LIMITED in (entry["present"], entry["absent"]):
            entry["status"] = "rate_limited"
        else:
            # No answer either way (challenge, consent page, unexpected status).
            entry["status"] = "inconclusive"
        report[index] = entry

    def collect(active_client: httpx.Client) -> None:
        with ThreadPoolExecutor(max_workers=max(1, min(MAX_WORKERS, len(rules)))) as pool:
            for future in [pool.submit(test_rule, active_client, index) for index in range(len(rules))]:
                future.result()

    with_client(collect, client, timeout=10)
    return report


def mastodon_rule(server: str, base: Optional[SiteRule] = None) -> SiteRule:
    """Build a rule for another Mastodon server from the bundled mastodon.social rule."""
    server = normalize_domain(server.strip().lower())
    base = base or SITES["mastodon"]
    return replace(
        base,
        name=f"mastodon@{server}",
        url=base.url.replace("mastodon.social", server),
        probe_url=base.probe_url.replace("mastodon.social", server),
        known_present=None,
        known_absent=None,
    )


def search_links(username: str, sites: Optional[SiteRegistry] = None) -> Dict[str, Any]:
    """Build links for manual follow-up. Nothing is requested.

    Returns exact-match web searches and Wayback Machine history pages for
    every profile URL the username is valid on.
    """
    username = validate_username(username)
    query = quote_plus(f'"{username}"')
    rules = [_as_rule(name, value) for name, value in (sites if sites is not None else SITES).items()]
    return {
        "username": username,
        "search_engines": {name: template.format(query=query) for name, template in SEARCH_ENGINES.items()},
        "archived_profiles": {
            rule.name: f"https://web.archive.org/web/*/{rule.profile_url(username)}"
            for rule in rules
            if rule.accepts(username)
        },
    }


def _validate_token(token: str) -> str:
    token = token.strip()
    if not 16 <= len(token) <= 200:
        raise ValueError("audit token must be 16-200 characters; create one with `recon verify-token`")
    return token


def _as_rule(name: str, value: Union[str, SiteRule]) -> SiteRule:
    if isinstance(value, SiteRule):
        return value
    return SiteRule(name=name, url=value, found_text="{username}")


def _not_applicable(rule: SiteRule, username: str) -> FootprintResult:
    return FootprintResult(
        rule.name,
        rule.profile_url(username),
        False,
        match_basis="username_not_valid_on_site",
        state=NOT_APPLICABLE,
        checked_at=datetime.now(timezone.utc).isoformat(),
    )


def _is_rate_limited(response: httpx.Response) -> bool:
    if response.status_code == 429:
        return True
    return response.status_code == 403 and response.headers.get("x-ratelimit-remaining") == "0"


def _retry_after(response: httpx.Response) -> Optional[float]:
    """Seconds to wait before the single retry, or None when no retry is due."""
    if response.status_code != 429:
        return None
    try:
        seconds = float(response.headers.get("retry-after", ""))
    except ValueError:
        return None
    return seconds if 0 <= seconds <= MAX_RETRY_AFTER_SECONDS else None
