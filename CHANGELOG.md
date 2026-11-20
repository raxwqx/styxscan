# Changelog

## 0.2.0 - 2026-11-20

### Added

- RFC 9116 `security.txt` discovery via `/.well-known/security.txt` with `/security.txt` as a fallback, including `Contact`, `Expires`, `Policy`, `Canonical`, and `Preferred-Languages` fields.
- Findings for a missing `security.txt`, missing `Contact`, missing or invalid `Expires`, and an expired file. Discovery is enabled by default and can be disabled with `--no-security-txt`.
- TLS certificate-verified handshake with an unverified fallback for expired, self-signed, or hostname-mismatched certificates, so certificate details are still reported.
- TLS findings for unverified certificates, expiry within 30 days, expired certificates, obsolete protocol versions, and weak cipher suites.
- DNS resolver diagnostics: NXDOMAIN, timeouts, and nameserver failures are reported as warnings instead of being silently treated as empty records.
- Parent-zone DNSKEY lookup so DNSSEC is detected for subdomains of a signed zone.
- SPF checks for multiple records, `+all`, and `?all`; DMARC checks for `p=none` and invalid policy values.
- Case-insensitive HTTP header detection for security headers, cookies, and CORS.
- Cookie findings for `SameSite=None` without `Secure`, plus `__Host-` and `__Secure-` prefix violations.
- CORS findings for `null` origins, invalid origin values, and a missing `Vary: Origin` on credentialed specific-origin responses.
- HTTPS-to-HTTP redirect downgrade detection.
- Bounded response-body reads (512 KB by default) with `content_truncated` and `content_type` metadata.
- `--version` and an `argv` parameter on `main()` for embedding and testing.
- Turkish `README.md`, English `README_EN.md`, `CHANGELOG.md`, `LICENSE`, and CI for Linux, macOS, and Windows on Python 3.10-3.13.
- Network-free tests for URL validation, DNS behavior, TLS parsing and fallback, cookies, CORS, headers, technology detection, HTTP bounds, `security.txt`, HTML escaping, and CLI output/exit codes.

### Fixed

- Targets are validated before any request: unsupported schemes, credentials, whitespace, control characters, backslashes, empty/overlong labels, invalid ports, and leading/trailing hyphens are rejected. Internationalized names are converted to punycode.
- The HTTP error path now returns exit code `1`; invalid input returns `2`; an HTML write failure returns `1` instead of reporting success.
- `--json --html` no longer silently skips the HTML report. JSON stays on standard output and the save confirmation goes to standard error.
- HTML reports now include HTTP information, redirects, security headers, TLS, DNS, DNS security, `security.txt`, cookies, CORS, technology, the severity summary, and findings.
- HTML output escapes all untrusted values, including HTTP status, header values, and TLS day counts.
- Terminal output wraps untrusted values in Rich `Text` and strips control characters, preventing markup injection through DNS records, headers, cookies, technology evidence, or findings.
- HTTP header lookups are case-insensitive; lowercase server headers are no longer missed.
- Technology detection no longer reports React, Vue.js, or Angular from ordinary words such as `reaction`, `value`, or `angular momentum`. Non-HTML content is not fingerprinted and duplicate entries are removed.
- TLS inspection honors the CLI timeout instead of a hardcoded 10 seconds, rejects invalid ports and timeouts, converts IDN hostnames, and uses a narrow exception set.
- TLS is skipped automatically for `http://` targets.
- DNS lookups are bounded by the CLI timeout and no longer use bare `except Exception` for every record type.
- Header value validation catches zero/missing HSTS `max-age`, CSP `unsafe-inline`/`unsafe-eval`, and invalid `X-Content-Type-Options` / `X-Frame-Options` values.
- The legacy `styxscan.py` entry point now delegates to the packaged CLI instead of maintaining a second, divergent implementation.
- Package metadata now declares the README, MIT license, authors, keywords, classifiers, project URLs, dependency ranges, and a `dev` extra.
- The test suite no longer depends on live DNS or live HTTP.

### Changed

- Package version is now `0.2.0` in `pyproject.toml` and `styxscan.__version__`.
- `requirements.txt` uses declared supported ranges instead of fully pinned transitive versions.
- The default user agent is derived from the package version.
- The terminal banner reports the real package version instead of a hardcoded `v0.1`.
