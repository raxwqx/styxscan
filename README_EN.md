# 🕷️ StyxScan

**Lightweight HTTP, TLS, DNS, and security reconnaissance toolkit.**

[Türkçe dokümantasyon](README.md)

StyxScan is a lightweight Python toolkit for security researchers, penetration testers, and curious developers. It passively inspects a target's publicly accessible HTTP/HTTPS response, security headers, cookies, CORS configuration, TLS certificate, DNS records, and `security.txt` file.

<p>
  <img alt="Python 3.10+" src="https://img.shields.io/badge/Python-3.10%2B-3776AB?logo=python&logoColor=white" />
  <img alt="MIT License" src="https://img.shields.io/badge/License-MIT-14B8A6.svg" />
  <a href="https://github.com/raxwqx/styxscan/actions/workflows/tests.yml"><img alt="Tests" src="https://github.com/raxwqx/styxscan/actions/workflows/tests.yml/badge.svg?branch=main" /></a>
</p>

---

## ✨ Features

### 🌐 HTTP / HTTPS

- HTTP status, final URL, and redirect history
- Server and `X-Powered-By` detection
- Content type and a bounded response body (512 KB by default)
- HTTPS-to-HTTP redirect downgrade detection
- Configurable timeout (10 seconds by default, 60 maximum)

### 🛡️ Security Analysis

- HSTS, CSP, `X-Content-Type-Options`, `X-Frame-Options`, `Referrer-Policy`, `Permissions-Policy`
- Case-insensitive header lookup
- Additional findings for weak HSTS `max-age`, CSP `unsafe-inline`/`unsafe-eval`, and invalid `X-Content-Type-Options` / `X-Frame-Options` values
- Severity-ranked finding summary (CRITICAL / HIGH / MEDIUM / LOW / INFO)

### 🍪 Cookie Analysis

- `Secure`, `HttpOnly`, `SameSite`
- `SameSite=None` without `Secure`
- `__Host-` and `__Secure-` prefix rules

### 🔐 TLS Inspection

- **Certificate-verified** handshake first
- Unverified fallback handshake for expired, self-signed, or hostname-mismatched certificates so details are still reported
- TLS version, cipher, subject, issuer, serial number, and SAN
- Validity window, days remaining, and expiry flag
- Findings for obsolete TLS versions and weak ciphers

### 🌍 DNS Reconnaissance

- A, AAAA, MX, NS, and TXT records
- SPF: missing record, multiple records, `+all`, and `?all` checks
- DMARC: missing record, `p=none`, and invalid policy checks
- DNSSEC: DNSKEY lookup up to the parent zone for subdomains
- Resolver failures are no longer silently swallowed; NXDOMAIN, timeouts, and nameserver failures become warnings

### 📜 security.txt (RFC 9116) — new

- Discovery of `/.well-known/security.txt` with `/security.txt` as a fallback
- `Contact`, `Expires`, `Policy`, `Canonical`, and `Preferred-Languages` fields
- Findings for missing `Contact`, missing/invalid `Expires`, and an expired file
- Enabled by default; disable it with `--no-security-txt`

### ↪️ CORS Analysis

- `Access-Control-Allow-Origin` / `-Credentials` / `-Methods` / `-Headers`
- Wildcard with credentials
- `null` origins and invalid origin values
- Missing `Vary: Origin` for a specific origin with credentials

### 🧬 Technology Detection

- Server and `X-Powered-By` fingerprints
- WordPress, Joomla, Drupal, Next.js, React, Vue.js, Angular, jQuery, Bootstrap, Tailwind CSS, Laravel, and Django
- Narrow patterns that avoid false positives; `vue` inside `"value"` is no longer reported as Vue.js
- Duplicate technology entries are removed

### 📊 Reporting

- Rich terminal output
- JSON output
- Full HTML report
- Control-character sanitization and HTML escaping in reports

---

## 📦 Requirements

- Python 3.10 or newer
- `requests`, `dnspython`, `rich`
- Access to the system resolver for DNS queries
- TCP access to port 443 (or the port in the URL) for TLS inspection

## 🚀 Installation

```bash
git clone https://github.com/raxwqx/styxscan.git
cd styxscan
python3 -m venv .venv
source .venv/bin/activate
pip install -e .
```

On Windows:

```powershell
.venv\Scripts\activate
```

Alternatively, install only the dependencies and run it as a module:

```bash
pip install -r requirements.txt
python -m styxscan example.com
```

## ⚡ Usage

Basic scan:

```bash
styxscan example.com
# or
python -m styxscan example.com
```

JSON output:

```bash
styxscan example.com --json
```

HTML report:

```bash
styxscan example.com --html report.html
```

JSON and HTML together:

```bash
styxscan example.com --json --html report.html
```

> JSON is written to standard output and the HTML save confirmation to standard error, so the output remains valid JSON in a pipeline.

Disable analyses:

```bash
styxscan example.com --no-dns
styxscan example.com --no-tls
styxscan example.com --no-security-txt
```

Timeout:

```bash
styxscan example.com --timeout 15
```

Help and version:

```bash
styxscan --help
styxscan --version
```

> TLS inspection is skipped automatically for `http://` targets. `security.txt` discovery is enabled by default and may make two extra HTTP requests.

## 🖥️ Example output

```text
STYXSCAN v0.2.0
Security Research Toolkit

Target       https://example.com
Status       200
Final URL    https://example.com/
Server       cloudflare

Security Overview

Security Headers    REVIEW      0/6 present
TLS                 VALID       TLSv1.3
DNS Records         OK          5/5 types found
DNS Security        OK          0 finding(s)
security.txt        MISSING     No security.txt found
Cookies             OK          0 detected, 0 finding(s)
CORS                OK          0 finding(s)

Security Summary

CRITICAL    0
HIGH        0
MEDIUM      2
LOW         5
INFO        0
TOTAL       7
```

## 📜 security.txt discovery

StyxScan requests `https://target/.well-known/security.txt` first, then falls back to `https://target/security.txt`. RFC 9116 fields are parsed and the following conditions are reported:

| Condition | Severity | Description |
| --------- | -------- | ----------- |
| File missing | LOW | Neither path returned a successful response |
| Missing `Contact` | MEDIUM | No security contact is defined |
| Missing `Expires` | LOW | Required expiry field is absent |
| Invalid `Expires` | LOW | Not a valid ISO 8601 value |
| Expired | MEDIUM | The file has not been refreshed |

Network errors are reported as warnings, not security findings. The content of `security.txt` is never executed.

## 📦 JSON output

JSON output includes tool/version metadata, HTTP, headers, DNS, TLS, cookies, CORS, `security_txt`, technology, findings, and the summary.

```json
{
  "tool": "styxscan",
  "version": "0.2.0",
  "target": "https://example.com",
  "http": {
    "status": 200,
    "url": "https://example.com/",
    "content_type": "text/html; charset=utf-8",
    "content_truncated": false,
    "scheme_downgrade": false
  },
  "tls": {
    "connected": true,
    "verified": true,
    "verification_error": null,
    "version": "TLSv1.3",
    "cipher": "TLS_AES_256_GCM_SHA384",
    "days_left": 35,
    "expired": false
  },
  "security_txt": {
    "found": true,
    "url": "https://example.com/.well-known/security.txt",
    "status": 200,
    "contacts": ["mailto:security@example.com"],
    "expires_at": "2027-01-01T00:00:00+00:00",
    "expired": false,
    "valid": true
  },
  "security_summary": {
    "CRITICAL": 0,
    "HIGH": 0,
    "MEDIUM": 0,
    "LOW": 0,
    "INFO": 0,
    "total": 0
  }
}
```

Notes:

- `tls.skipped` is `true` only with `--no-tls` or for an `http://` target.
- `security_txt.skipped` is `true` only with `--no-security-txt`.
- Raw DNS and HTTP values are preserved in JSON; terminal and HTML output sanitize and escape them.

## 🚦 Exit codes

| Code | Meaning |
| ---- | ------- |
| `0` | Scan completed (TLS/security.txt findings do not fail the process) |
| `1` | HTTP request failed or the HTML report could not be written |
| `2` | Invalid target, timeout, or command-line usage |

## 🛡️ Target validation and limits

- Only `http://` and `https://` schemes are accepted; a missing scheme gets `https://`.
- URL credentials are rejected.
- Whitespace, control characters, backslashes, empty labels, labels longer than 63 characters, and leading/trailing hyphens are rejected.
- The hostname may be at most 253 characters.
- Internationalized names are converted to punycode.
- Ports must be between 1 and 65535.
- `--timeout` must be greater than 0 and at most 60 seconds.
- Response bodies are limited to 512 KB by default.
- Redirects are followed; an HTTPS-to-HTTP downgrade is reported as a HIGH finding.

## 🧪 Tests

Tests do not require network access; HTTP, DNS, TLS, and `security.txt` layers are mocked.

```bash
pip install -e ".[dev]"
python -m pytest -q
```

CI runs compilation, tests, and a CLI version check on Linux, macOS, and Windows with Python 3.10–3.13.

## 📁 Project structure

```text
styxscan/
├── styxscan/
│   ├── __init__.py
│   ├── __main__.py
│   ├── cli.py
│   ├── cookies.py
│   ├── cors.py
│   ├── dns.py
│   ├── findings.py
│   ├── headers.py
│   ├── html_reporter.py
│   ├── http.py
│   ├── reporter.py
│   ├── sanitize.py
│   ├── security_txt.py
│   ├── technology.py
│   └── tls.py
├── tests/
├── .github/workflows/tests.yml
├── CHANGELOG.md
├── LICENSE
├── README.md
├── README_EN.md
├── pyproject.toml
├── requirements.txt
└── styxscan.py
```

## 🧠 Design philosophy

StyxScan focuses on **passive reconnaissance**. It collects only information reachable through normal HTTP/HTTPS requests, DNS queries, and TLS handshakes. It does not attempt exploitation, modify the target, or access authenticated areas.

## ⚠️ Disclaimer

StyxScan is intended for **authorized security testing, research, and educational purposes only**. Do not use it against systems, networks, or applications you do not own or have permission to test. The developer is not responsible for misuse or damage caused by this tool.

## 📜 License

MIT. See the [`LICENSE`](LICENSE) file for details.
