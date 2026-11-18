# Minimal Recon

[![CI](https://github.com/AlexC0906/minimal-recon/actions/workflows/ci.yml/badge.svg)](https://github.com/AlexC0906/minimal-recon/actions/workflows/ci.yml)

Minimal Recon is a modular, read-only OSINT command-line utility written in Python.
It is designed as a portfolio project with small services that can be extended without
coupling the CLI to network or file-system logic.

## Features

- `lookup`: basic IP/domain resolution and reverse DNS
- `dns`: common DNS record enumeration (`A`, `AAAA`, `MX`, `NS`, `TXT`, `CNAME`)
- `footprint`: username checks on 36 public sites with per-site rules, optional profile details and a self-test
- `search-links`: manual-review search and Wayback links for a username
- `ui`: local web interface for username searches, domain reports and the rule self-test
- `email`: email format validation and public MX record analysis
- `metadata`: local filesystem metadata plus image dimensions and readable EXIF fields
- `web`: passive web security headers, WAF and technology fingerprint detection
- `subdomains`: passive discovery from Certificate Transparency logs
- `report`: consolidated JSON or HTML audit report
- `diff`: offline comparison of two saved JSON reports
- `whois`: public RDAP registration, registrar, dates and nameservers
- `geoip`: approximate IP location and network ownership information
- `archive`: public website history from the Wayback Machine
- `verify`: explicit proof-of-control verification for supplied profile URLs
- `reputation`: optional read-only VirusTotal IP/domain reputation lookup
- `shodan`: optional read-only Shodan indexed host lookup
- `tls`: read-only TLS version and certificate inspection, including invalid certificates
- `links`: single-page surface link extraction without recursive crawling
- `anti-spoofing`: public SPF, DMARC and selected DKIM policy analysis with weakness findings
- `public-files`: checks intentionally public standard web documents

## Setup

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -e ".[dev]"
```

## Local Testing

Run the automated tests, linter and type checker:

```powershell
python -m pytest
python -m ruff check .
python -m mypy
```

Test commands without external requests:

```powershell
python -m minimal_recon.cli --help
python -m minimal_recon.cli lookup 192.0.2.10 --json
python -m minimal_recon.cli metadata pyproject.toml --json
```

For network-backed commands, use only authorized targets:

```powershell
python -m minimal_recon.cli lookup example.com --json
python -m minimal_recon.cli dns example.com --json
python -m minimal_recon.cli footprint octocat --delay 0.5 --json
python -m minimal_recon.cli web https://example.com --json
python -m minimal_recon.cli subdomains example.com --json
python -m minimal_recon.cli whois example.com --json
python -m minimal_recon.cli geoip 1.1.1.1 --json
python -m minimal_recon.cli archive example.com --json
python -m minimal_recon.cli tls example.com --json
python -m minimal_recon.cli links https://example.com --max-links 100 --json
python -m minimal_recon.cli report example.com --username alex576_ --output audit.json --html audit.html
```

## Web Interface

```powershell
recon ui
```

This opens `http://127.0.0.1:8765/` in your browser. Every command has a place in it:

| Tab | Tools |
| --- | --- |
| Username | Footprint on all sites or a selection, profile details, "Found only" filter, search links, Mastodon servers, self-audit |
| Domain | Full report (shown in the page, JSON and HTML download), DNS, WHOIS, subdomains, archive, TLS, email spoofing (SPF/DMARC/DKIM) |
| IP | Lookup, geolocation, VirusTotal, Shodan |
| Web | Security headers and technologies, links, public files |
| Email | Email address analysis |
| File | Metadata of a file you choose (inspected locally in a temporary copy, then deleted) |
| Compare | Differences between two saved JSON reports |
| Verify | Create a verification token and check it on your profiles |
| Rules | Site-rule self-test |

Each result can be exported as JSON. VirusTotal and Shodan use `VT_API_KEY` and
`SHODAN_API_KEY` from the environment, or a key typed in the form for that request only;
keys are never saved.

Stop it with `Ctrl+C`. Use `recon ui --port 9000` for another port, `--no-browser` to
open it yourself, and `recon --timeout 30 ui` for slow networks.

The interface listens on `127.0.0.1` only, so it is not reachable from other machines.
Each run creates a random API token that the page sends with every request, and requests
with a different `Host` header are refused, so other websites open in the same browser
cannot use it. It needs no extra dependencies.

## Usage

```powershell
recon --help
recon --version
recon lookup example.com
recon lookup example.com --json
recon dns example.com
recon footprint octocat
recon footprint octocat --delay 0.5 --json
python -m minimal_recon.cli email analyst@example.com --json
python -m minimal_recon.cli web https://example.com --json
recon metadata .\sample.jpg
```

Every lookup command supports `--json` for scripting and pipeline integration;
`report` prints JSON by default or writes files with `--output` and `--html`.
Domain arguments take a bare hostname such as `example.com`, while `web`, `links`,
`public-files` and `verify` take full `http(s)://` URLs.
Each check has its own default timeout (3 to 15 seconds). The global `--timeout`
option, placed before the command, replaces all of them for HTTP, DNS and TLS:

```powershell
recon --timeout 30 subdomains example.com
```

HTTP requests identify the tool with a `minimal-recon/<version>` User-Agent and do
not imitate a browser, so some platforms answer with a challenge page.
For `dns --json`, the response includes the raw records and a derived `summary`
with nameservers, mail servers and conservative provider hints.
Footprint checks use an explicit registry of 36 public sites, each with its own
detection rule (see [Footprint](#footprint) below).
Metadata inspection is local-only and does not upload files anywhere.
Email analysis does not verify mailbox existence or query breach databases; it only
checks the address format and public MX records. It also flags missing MX records,
role-based addresses and a small built-in list of disposable email domains. These
are heuristics, not proof that a mailbox exists or is compromised.
Web checks make one normal HTTP request and report selected response headers; they do
not scan ports, crawl pages or attempt to bypass access controls.
Subdomain discovery uses public Certificate Transparency records and does not scan
the discovered hosts.
Reports combine the passive checks into portable JSON and HTML files with timestamps
and source URLs. Sections run in parallel, each against its own service, and a
failed section is recorded as an error without stopping the others. The HTML report
shows summary cards, a table per section and the raw JSON underneath.
Saved JSON reports can be compared later without any network access:

```powershell
recon report example.com --output monday.json
recon report example.com --output friday.json
recon diff monday.json friday.json
```

`diff` lists added (`+`), removed (`-`) and changed (`~`) values by section, such
as new subdomains, changed DNS records or fewer days until certificate expiry.
Run timestamps are ignored.
WHOIS data comes from RDAP and may omit private or registry-restricted fields.
IP geolocation is approximate and usually identifies the network, CDN or hosting
provider rather than a precise physical location.
Archive history uses the public Wayback CDX index and returns snapshot links; it does
not download archived pages.
TLS checks connect only to the requested host and port, report the negotiated protocol,
cipher and certificate dates, and do not scan other ports. A certificate that fails
validation (expired, self-signed, wrong host) is still reported, marked as not valid
together with the reason. Validation trusts the system store and the Mozilla CA bundle.
WAF detection is passive and heuristic: it uses identifying response headers only
(not page content), so `not_detected` does not prove that a site has no WAF.
Technology detection is also heuristic and reports only public fingerprints such as
response headers, meta/script paths and framework markers.
Link extraction reads one HTML page, removes fragments, separates internal and
external HTTP(S) links, and never follows the discovered links automatically.
Anti-spoofing checks inspect DNS records only. They flag a missing or duplicated SPF
record, SPF that ends in `+all` or `?all` or has no terminator, and DMARC that is
missing, duplicated, monitoring-only, partially enforced (`pct` below 100) or has no
aggregate report address. SPF `include` chains are not followed. DKIM requires known
selectors, which can be supplied explicitly:

```powershell
recon anti-spoofing example.com --selectors google,default --json
```

Public file discovery checks only a small allowlist of standard documents such as
`robots.txt`, `sitemap.xml` and `security.txt`. It does not brute-force hidden paths
or request sensitive files such as `.env`, backups or configuration dumps.
Ownership verification is opt-in: generate a token, publish it temporarily on each
profile you control, then pass those exact URLs to `verify`. It does not discover or
link accounts automatically.

```powershell
recon verify-token
recon verify --token minimal-recon-verify-... --url https://github.com/your-user --url https://www.instagram.com/your-user --json
```

External reputation checks use a user-provided VirusTotal API key and never upload
files. Set it locally before running:

```powershell
$env:VT_API_KEY = "your-api-key"
recon reputation example.com --json
recon reputation 1.1.1.1 --json
```

Shodan lookups are also optional and require a user-provided API key:

```powershell
$env:SHODAN_API_KEY = "your-api-key"
recon shodan 1.1.1.1 --json
```

The integration reads Shodan's existing indexed data only; it does not launch scans.

## Responsible Use

Only use this tool against systems, domains, files and identities you are authorized
to investigate. The first version intentionally avoids brute force, stealth and
access-control bypass techniques.

## Footprint

`footprint` checks whether a username is registered on each site in
[`sites.json`](src/minimal_recon/data/sites.json):

| Source | Sites | Confidence |
| --- | --- | --- |
| Public API | GitHub, GitLab, Codeberg, Dev.to, Hacker News, Bluesky (`*.bsky.social` handles), Keybase, Docker Hub, Lichess, Chess.com, Medium, Mastodon (mastodon.social), Gravatar, Codewars, Hugging Face, Launchpad, Wikipedia (English) | `confirmed` |
| Public profile page | X, Instagram, TikTok, Pinterest, Twitch, Steam (custom URL), Telegram, YouTube, HackerOne, Kaggle, Pastebin, Vimeo, SoundCloud, Dribbble, Linktree, itch.io, SourceHut, Patreon, Flickr | `likely` |

```powershell
recon footprint octocat
recon footprint octocat octocat-dev octo_cat
recon footprint octocat --found-only --details
recon footprint octocat --site github --site gitlab --json
recon footprint octocat --mastodon fosstodon.org --mastodon infosec.exchange
recon footprint --self-test
recon footprint octocat --sites .\my-sites.json
```

Several usernames can be checked in one run; with `--json` and more than one name the
output is a list of `{"username": ..., "results": [...]}`. Mastodon accounts live on
separate servers, so `--mastodon` adds servers to the default `mastodon.social` check.
Site pages that share a path with a username (such as `vimeo.com/about`) can give a
`likely` match that is really a site page.

Each result has one of these states:

- `FOUND` / `NOT FOUND`: the site's rule gave a definite answer.
- `UNKNOWN`: the site answered with a challenge, consent or login page, or with a page
  the rule does not recognize. YouTube is always `UNKNOWN` from the EU, where it
  redirects to a consent page first.
- `RATE LIMITED`: the site refused because of request volume. A short `Retry-After`
  (up to 10 seconds) is retried once. The GitHub API allows 60 unauthenticated
  requests per hour.
- `N/A`: the username breaks that site's naming rules (for example, a `.` on GitHub),
  so no request is sent.

Sites run in parallel, one request at a time per host; `--delay` spaces requests to the
same host. For profile pages, only the page title and meta description are kept.

`--details` adds the fields a person chose to publish on a profile, read from the site's
public API where the account was found: display name, bio, location, website, join date,
public totals (followers, posts, repositories, karma and similar), and accounts the
profile itself lists (such as an X handle on GitHub or Dev.to). Listed accounts are shown
as self-declared and are not followed or checked. Instagram has no public API, so its
details (display name, bio, followers, following, posts) are read from the description
Instagram publishes on the profile page for search engines; abbreviated counts such as
`32K` are approximate. Private accounts show only what that description shows.

```powershell
recon footprint octocat --details
recon report example.com --username octocat --details --html audit.html
```

Some API data is deliberately not collected even when the API returns it: email
addresses, phone numbers, employer, avatars, activity times (last online, game in
progress) and cross-account proofs. When a profile owner has opted out of search
indexing (Mastodon's `noindex`), the account is still reported but its details are not.

`search-links` prints exact-match search links for Google, Bing and DuckDuckGo and a
Wayback Machine history link for each possible profile, for manual review. It sends no
requests.

```powershell
recon search-links octocat
```

### Self-audit

To see what your own accounts expose, prove that you control them first:

```powershell
recon verify-token
# put the token in the bio of each profile you own, then:
recon footprint your-name --audit-token minimal-recon-verify-...
```

In this mode, `--details` is on, and each found profile is marked as verified when the
token appears in its public data. Accounts declared on a verified profile (its X or
GitHub handle) are checked one step further and marked with the profile that declared
them. Declared accounts of profiles without the token are never followed. Opt-out flags
do not hide details of a profile verified as yours. Remove the token from your profiles
afterwards.

A matching username is not proof that the accounts belong to the same person. Running
`recon footprint octocat --details` shows profiles with different names and cities
behind the same username. The tool does not link accounts to each other; use `verify`
when someone proves control of their profiles.

Sites change their pages without notice. `--self-test` checks every rule against a
username known to exist and one known not to. It reports `OK`, `BROKEN` (a wrong
definite answer, so the rule needs fixing), `INCONCLUSIVE` (no answer) or `RATE_LIMITED`.
Reddit, npm and PyPI are not included because they block automated clients.

### Footprint registry format

`--sites` replaces the bundled registry with a JSON file of the same shape:

```json
{
  "sites": [
    {
      "name": "example",
      "url": "https://example.com/u/{username}",
      "probe_url": "https://api.example.com/users/{username_lower}",
      "source": "api",
      "username_pattern": "[A-Za-z0-9_]{3,20}",
      "not_found_status": [404],
      "found_text": "\"login\":\"{username}\"",
      "known_present": "admin",
      "known_absent": "zq7xk2vq9wplm3"
    }
  ]
}
```

| Field | Meaning |
| --- | --- |
| `name`, `url` | Required. `url` is the public profile link shown in results. |
| `probe_url` | URL actually requested, such as an API endpoint. Defaults to `url`. |
| `source` | `api` (answers are `confirmed`) or `html` (answers are `likely`). Default `html`. |
| `username_pattern` | Regular expression the whole username must match, otherwise `N/A`. |
| `found_status`, `not_found_status` | HTTP codes. Defaults `[200]` and `[404, 410]`. |
| `found_text` | Required in the body for `FOUND`; without it the result is `UNKNOWN`. |
| `not_found_text`, `not_found_body` | Text in the body, or the entire body, that means `NOT FOUND`. |
| `unknown_url` | Text in the final URL that marks a login, consent or challenge page. |
| `known_present`, `known_absent` | Usernames used by `--self-test`. |
| `profile_fields` | API sources only. Maps `display_name`, `bio`, `location`, `website` and `created_at` to dotted JSON paths (`them.0.profile.bio`), and `declared_accounts` and `stats` to `{label: path}`. `stats` keeps numbers only. Other field names are rejected. |
| `meta_pattern` | HTML sources only. Regular expression for the page's public meta description; named groups `display_name`, `bio`, `location`, `website` or `stats_<label>` become `--details` fields. |
| `opt_out_path` | API sources only. Path of the owner's "do not index" flag; when it is `true`, details are withheld. |

URLs and text accept `{username}` and `{username_lower}`; text is matched
case-insensitively.

## Roadmap

1. Add scheduled monitoring on top of `diff`.
2. Add packaging and release automation.

## Why Typer?

Typer is a good fit here because it provides modern type-hint-based command definitions,
help generation and shell-friendly errors while keeping each CLI command thin. It is
less verbose than `argparse`, and the project can add nested command groups later
without losing a clean service layer.
