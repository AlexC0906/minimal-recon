# Changelog

All notable changes to Minimal Recon are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses
[semantic versioning](https://semver.org/).

## [Unreleased]

## [0.2.0] - 2026-11-18

A local web interface, a rebuilt username footprint, saved history with change
monitoring, and many accuracy fixes.

### Added

**Web interface**

- `recon ui` opens a local web interface on `127.0.0.1` covering every command: username
  footprint, domain report and individual domain checks, IP, web, email, file metadata,
  report comparison, ownership verification, history and the rule self-test.
- Username results appear live, site by site, with a progress bar.
- Each run creates a random API token that the page must send, and requests with another
  `Host` header are refused, so other websites in the same browser cannot use the tool.

**History and monitoring**

- `--save` on `footprint` and `report` keeps runs on this computer and shows what changed
  since the last saved run of the same target. The interface saves by default.
- `recon history list | show | diff | delete | clear` and a History tab to view runs,
  compare any two, or compare a run with the previous one.
- `recon watch DOMAIN` re-runs the report on an interval (or once, for Task Scheduler and
  cron) and alerts on new subdomains, DNS changes, expiring or invalid certificates, new
  email-spoofing findings, dropped security headers and registrar changes.
- `recon diff OLD.json NEW.json` compares two saved JSON reports offline.

**Username footprint**

- 36 sites, each with its own rule in a bundled registry
  (`src/minimal_recon/data/sites.json`): 17 read through public APIs (`confirmed`) and 19
  from public profile pages (`likely`). `--sites` loads your own registry.
- `--self-test` checks every rule against a known existing and a known missing account.
- `--details` adds what a person chose to publish on the profile (display name, bio,
  location, website, join date, self-declared accounts) and public totals such as
  followers or posts. Instagram details come from its public page description.
- Several usernames per run, `--found-only`, `--site` filters and `--mastodon SERVER`.
- `--audit-token` for auditing your own accounts: profiles showing a `recon verify-token`
  token are marked as yours, and only their declared accounts are checked one step further.
- `recon search-links USERNAME` prints exact-match web searches and Wayback links for
  manual review, without sending requests.
- New result fields `confidence`, `profile` and `profile_note`, and states `rate_limited`
  and `not_applicable` (username invalid on that site, so no request is sent).

**Checks and reports**

- Global `--timeout` option for every HTTP, DNS and TLS operation.
- `tls` reports certificates that fail validation, with `verified` and
  `verification_error`, and accepts IP addresses including IPv6.
- Anti-spoofing findings for SPF `+all`, `?all` or missing terminator, duplicate SPF or
  DMARC records, DMARC without a valid policy, partial enforcement (`pct`) and missing `rua`.
- HTML report sections are tables, with the raw JSON underneath; summary cards flag
  expired or expiring certificates, missing security headers and anti-spoofing findings.
- `report --details` and a username footprint card in the HTML report.

**Project**

- MIT license, project metadata and a release workflow that tests, builds and publishes
  a GitHub release with the wheel and source archive for each version tag.
- Ruff and mypy in CI, and Python 3.13 in the test matrix.

### Changed

- `report` runs its sections in parallel and `footprint` checks sites in parallel, one
  request at a time per host; `--delay` spaces requests to the same host.
- All HTTP requests share one client and identify the tool with a
  `minimal-recon/<version>` User-Agent.
- Domain arguments must be real hostnames: URLs and malformed labels are rejected, and
  internationalized names are converted to punycode.
- WAF detection reads identifying headers only, so sites that merely load assets from a
  CDN are no longer reported as protected by it.
- `tls` dates are ISO 8601 (`2030-01-01T00:00:00+00:00`) and validation also trusts the
  Mozilla CA bundle. Adds the `cryptography` and `certifi` dependencies.
- `footprint` no longer guesses from generic "not found" phrases or from the username
  appearing on the page, which made Instagram report every username as found.
- `footprint` accepts usernames of up to 64 characters, including a leading `_`, and
  rejects names made only of dots. Match basis values changed to `profile_marker`,
  `no_profile_marker`, `not_found_marker`, `empty_result` and `username_not_valid_on_site`.
- Reddit is no longer checked: it blocks automated clients, so it was always `unknown`.
- `lookup` reports unresolvable names as `could not resolve <name>`.
- In the report JSON, `geoip` is now the last section.
- The CLI is split into `minimal_recon.commands` modules; `recon` is unchanged.

### Fixed

- PHP was never detected by technology fingerprinting.
- Report links with query strings were cut at the first `&`.
- `subdomains` and `report` printed a traceback on network errors.
- `verify` sent requests before finding an invalid URL later in the list.
- One malformed link made `links` fail for the whole page.
- Unexpected Certificate Transparency responses crashed `subdomains`.
- TXT records split into several strings (long SPF or DKIM values) kept stray quotes.
- DMARC tags written with spaces around `=` or in upper case were not read.
- A `<meta name>` tag without a value crashed `footprint`.
- Summary cards in the HTML report ignored their status colour.
- Tests now run from a fresh checkout without installing the package.

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

[Unreleased]: https://github.com/AlexC0906/minimal-recon/compare/v0.2.0...HEAD
[0.2.0]: https://github.com/AlexC0906/minimal-recon/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/AlexC0906/minimal-recon/releases/tag/v0.1.0
