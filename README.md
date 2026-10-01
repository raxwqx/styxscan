# 🕷️ StyxScan

> Lightweight HTTP, TLS, DNS & Security Reconnaissance Toolkit.

**StyxScan** is a lightweight Python-based security research toolkit designed to collect and analyze publicly accessible information from web targets.

It performs passive reconnaissance across HTTP/HTTPS, security headers, cookies, CORS, TLS, DNS, redirects, and basic technology detection.

Built for security researchers, penetration testers, and curious hackers.

---

## ⚡ Features

### 🌐 HTTP / HTTPS

* HTTP status code detection
* Final URL detection
* Response header analysis
* Server detection
* `X-Powered-By` detection
* Redirect history tracking
* Configurable request timeout

### 🛡️ Security Analysis

* Security header analysis
* HSTS detection
* Content Security Policy detection
* CSP Report-Only detection
* `X-Content-Type-Options` detection
* `X-Frame-Options` detection
* `Referrer-Policy` detection
* `Permissions-Policy` detection
* Cookie security analysis
* CORS analysis
* Security findings
* Severity-based security summary

### 🍪 Cookie Analysis

StyxScan analyzes common cookie security attributes, including:

* `Secure`
* `HttpOnly`
* `SameSite`

### 🔐 TLS Inspection

* TLS version
* Cipher suite
* Certificate subject
* Certificate issuer
* Certificate issue date
* Certificate expiration date
* Remaining certificate lifetime

### 🌍 DNS Reconnaissance

StyxScan can inspect:

* A records
* AAAA records
* MX records
* NS records
* TXT records
* SPF
* DMARC
* DNSSEC / DNSKEY indicators

### ↪️ Redirect Analysis

StyxScan tracks HTTP redirects and displays:

* Redirect status codes
* Redirect URLs
* Final destination
* Number of redirects

### 🧬 Technology Detection

Basic technology fingerprinting based on publicly accessible HTTP information.

### 📊 Reporting

StyxScan provides:

* Rich terminal output
* JSON output
* HTML report generation
* Security findings with severity levels

---

## 📦 Installation

Clone the repository:

```bash
git clone https://github.com/raxwqx/styxscan.git
cd styxscan
```

Install the dependencies:

```bash
pip install -r requirements.txt
```

Or install the project directly:

```bash
pip install .
```

---

## 🚀 Usage

### Basic Scan

```bash
python -m styxscan https://example.com
```

### Show Help

```bash
python -m styxscan --help
```

### Custom Timeout

Set the HTTP request timeout in seconds:

```bash
python -m styxscan https://example.com --timeout 10
```

### Disable DNS Analysis

```bash
python -m styxscan https://example.com --no-dns
```

### Disable TLS Inspection

```bash
python -m styxscan https://example.com --no-tls
```

### JSON Output

Generate machine-readable JSON output:

```bash
python -m styxscan https://example.com --json
```

### HTML Report

Generate an HTML security report:

```bash
python -m styxscan https://example.com --html report.html
```

---

## 📊 Example

Example terminal output:

```text
STYXSCAN v0.1
Security Research Toolkit

Target       https://example.com
Status       200
Final URL    https://example.com/
Server       Example

Security Overview

Security Headers    REVIEW
TLS                 VALID
DNS Records         OK
DNS Security        REVIEW
Cookies             OK
CORS                OK

Security Summary

CRITICAL    0
HIGH        0
MEDIUM      0
LOW         0
INFO        0
TOTAL       0
```

> Results depend on the target's HTTP response, DNS configuration, TLS configuration, and enabled scan options.

---

## 🔎 Security Findings

StyxScan performs passive security checks against publicly accessible information.

Example findings may include:

```text
MEDIUM   HSTS is missing
MEDIUM   CSP is missing
LOW      X-Content-Type-Options is missing
LOW      Referrer-Policy is missing
LOW      Permissions-Policy is missing
LOW      Cookie is missing Secure
LOW      Cookie is missing HttpOnly
LOW      Cookie has no SameSite attribute
```

Findings use the following severity levels:

```text
CRITICAL
HIGH
MEDIUM
LOW
INFO
```

> A finding is a security observation and does not necessarily mean that the target contains an exploitable vulnerability.

---

## 🧪 Testing

Run the automated test suite with:

```bash
pytest
```

The project includes tests covering the core functionality of StyxScan.

---

## 🗂️ Project Structure

```text
styxscan/
├── styxscan/
│   ├── __init__.py
│   ├── __main__.py
│   ├── cli.py
│   ├── http.py
│   ├── headers.py
│   ├── cookies.py
│   ├── cors.py
│   ├── dns.py
│   ├── tls.py
│   ├── technology.py
│   ├── findings.py
│   ├── reporter.py
│   └── html_reporter.py
│
├── tests/
│   └── ...
│
├── pyproject.toml
├── requirements.txt
├── LICENSE
└── README.md
```

---

## 🧠 Design Philosophy

StyxScan is designed around **passive reconnaissance**.

The tool focuses on information that can be obtained through normal HTTP/HTTPS requests and DNS/TLS inspection.

It does not attempt to exploit vulnerabilities or modify the target system.

The goal is to provide a lightweight overview of a target's externally observable security posture.

---

## ⚠️ Legal Disclaimer

StyxScan is intended for **authorized security testing, research, and educational purposes only**.

Do not scan systems, networks, or applications without explicit permission from the owner.

The author is not responsible for misuse or damage caused by this tool.

---

## 📜 License

This project is licensed under the **MIT License**.

See the [`LICENSE`](LICENSE) file for details.

---

## 🕷️ Project

**StyxScan v0.1.0**

Developed by **raxwqx**

GitHub: https://github.com/raxwqx/styxscan
