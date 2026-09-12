# Changelog

All notable changes to Minimal Recon are documented here.

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
