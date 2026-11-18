# Changelog

All notable changes to Minimal Recon are documented here.

## [Unreleased]

### Added

- `ui` command: local web interface on `127.0.0.1` covering every command (username
  footprint, domain report and checks, IP, web, email, file metadata, report comparison,
  ownership verification, rule self-test), protected by a per-run API token and a Host check.

- `diff` command: offline comparison of two saved JSON reports, with `--json` output.
- Global `--timeout` option that replaces the per-check HTTP, DNS and TLS timeouts.
- `tls` reports certificates that fail validation instead of only erroring, with
  `verified` and `verification_error` fields. Adds the `cryptography` dependency.
- Anti-spoofing findings for permissive or unterminated SPF, duplicate SPF or DMARC
  records, DMARC without a valid policy, partial enforcement (`pct`) and missing `rua`.
  New statuses: SPF `weak` / `invalid`, DMARC `invalid`.
- HTML report sections are rendered as tables, with the raw JSON kept underneath.
- Ruff and mypy configuration, a CI lint job, and Python 3.13 in the test matrix.
- `footprint` per-site rules in a bundled JSON registry (`src/minimal_recon/data/sites.json`),
  replaceable with `--sites`, filterable with `--site`, and checked with `--self-test`.
- `footprint` sites: GitLab, Codeberg, Hacker News, Bluesky, Keybase, Docker Hub,
  Lichess, Chess.com, Steam and Telegram.
- `footprint --details`: self-published profile fields (display name, bio, location,
  website, join date, self-declared accounts) from the public APIs of 10 sites, in a new
  `profile` result field. Fields are limited to an allowlist; email, employer, avatars,
  activity times and cross-account proofs are not collected.
- `footprint` sites: Mastodon, Gravatar, Codewars, Hugging Face, Launchpad, Wikipedia,
  HackerOne, Kaggle, Pastebin, Vimeo, SoundCloud, Dribbble, Linktree, itch.io, SourceHut,
  Patreon and Flickr (36 in total). `--mastodon SERVER` checks further Mastodon servers.
- `footprint --details` public stats (followers, posts, repositories, karma, edits).
- `footprint --details` for Instagram: display name, bio and follower, following and post
  counts read from the profile page's public meta description (new `meta_pattern` rule field).
- `footprint` accepts several usernames in one run.
- `footprint --found-only` lists only the sites where the username was found.
- `footprint --audit-token`: self-audit of your own accounts, verified with a
  `recon verify-token` token. Only verified profiles have their declared accounts checked.
- Profile details are withheld when the owner opted out of indexing (Mastodon `noindex`),
  unless the profile is verified as yours.
- `search-links` command: exact-match search links and Wayback links, with no requests.
- `report --details` and a username footprint summary card in the HTML report.
- `footprint` result field `confidence` (`confirmed` from APIs, `likely` from pages) and
  states `rate_limited` and `not_applicable` (username invalid on that site).

### Changed

- `footprint` reads GitHub, Dev.to and Medium through their public APIs or feeds, checks
  sites in parallel, and applies `--delay` only between requests to the same host.
- `footprint` no longer uses shared "not found" phrases or "the name appears on the page";
  each site has its own markers. This fixes Instagram reporting every username as found.
- `footprint` accepts usernames of up to 64 characters, including a leading `_`, and
  rejects names made only of dots. Match basis values changed: `profile_marker`,
  `no_profile_marker`, `empty_result`, `username_not_valid_on_site`.
- Reddit is no longer checked: it blocks automated clients, so it was always `unknown`.

- `report` runs its sections in parallel.
- All HTTP requests go through one shared client and send a `minimal-recon/<version>`
  User-Agent instead of the `python-httpx` default.
- `tls` certificate dates are ISO 8601 (`2030-01-01T00:00:00+00:00`) instead of the
  OpenSSL text format, and validation also trusts the Mozilla CA bundle.
- In the report JSON, `geoip` is now the last section.

- Domain arguments are validated as real hostnames; URLs and malformed labels are
  rejected with a clear message instead of being sent to resolvers or API URLs.
  Internationalized names are converted to punycode.
- WAF detection reads identifying headers only, so pages that merely load assets
  from a CDN (or list one in their CSP) are no longer reported as protected by it.
  A bare `x-cache` header is no longer attributed to CloudFront.
- HTML report summary cards flag expired or soon-expiring certificates, missing
  security headers and anti-spoofing findings instead of always showing `OK`.
- Footprint results use the `not_found_marker` match basis for soft-404 pages.
- `lookup` reports unresolvable names as `could not resolve <name>`.
- `tls` accepts IP addresses, including IPv6.

### Fixed

- PHP was never detected by technology fingerprinting.
- Report links with query strings were truncated at the first `&`.
- `subdomains` and `report` printed a traceback on network errors.
- `verify` validated URLs one by one, so a bad URL aborted the run after earlier
  requests had already been sent.
- One malformed `href` made `links` fail for the whole page.
- Unexpected crt.sh payloads crashed `subdomains`.
- Tests run from a fresh checkout without installing the package first.
- TXT records split into several strings (long SPF or DKIM values) were parsed with
  stray quotes in the middle.
- DMARC tags written with spaces around `=` or in upper case were not read.
- A `<meta name>` tag without a value crashed `footprint`.
- Summary cards in the HTML report ignored their status colour.

## [0.1.0] - 2026-09-12

### Added

- Modular Typer CLI with JSON output and version reporting.
- IP/domain lookup, DNS enumeration and provider hints.
- RDAP registration data and approximate IP geolocation.
- SPF, DMARC and selected DKIM anti-spoofing checks.
- TLS certificate inspection, WAF detection and technology fingerprinting.
- Passive subdomain discovery through Certificate Transparency.
- Wayback Machine snapshot history and single-page link extraction.
- Public standard-file checks for `robots.txt`, `sitemap.xml` and `security.txt`.
- Username footprinting across an explicit public-site registry.
- Optional VirusTotal and Shodan read-only integrations.
- JSON and visual HTML reports with resilient section-level errors.
- Explicit profile ownership verification using a user-controlled token.
- Automated tests and GitHub Actions CI for Python 3.9 and 3.12.

### Notes

- Network checks are passive, rate-limited and intended for authorized targets.
- External APIs require user-provided keys and are never called implicitly by the standard report.
- IP geolocation, WAF and technology detection are heuristic indicators.
