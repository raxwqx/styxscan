"""Finding severity model and security checks."""

from __future__ import annotations

import re

from .sanitize import sanitize

HEADER_SEVERITY = {
    "HSTS": "MEDIUM",
    "CSP": "MEDIUM",
    "X-Content-Type-Options": "LOW",
    "X-Frame-Options": "LOW",
    "Referrer-Policy": "LOW",
    "Permissions-Policy": "LOW",
}

SEVERITY_ORDER = [
    "CRITICAL",
    "HIGH",
    "MEDIUM",
    "LOW",
    "INFO",
]

_HSTS_MAX_AGE_RE = re.compile(r"max-age\s*=\s*(\d+)", re.IGNORECASE)


def _header_finding(name: str, severity: str, message: str) -> dict:
    return {
        "type": "security-header",
        "name": name,
        "severity": severity,
        "message": message,
    }


def analyze_headers(headers: list[dict]) -> list[dict]:
    """Create findings for missing or weakly configured security headers."""

    findings = []

    for header in headers or []:
        name = header.get("name", "")
        value = header.get("value")

        if not header.get("present"):
            if name == "CSP" and header.get("report_only"):
                message = "CSP is missing (CSP Report-Only is present)"
            else:
                message = f"{name} is missing"

            findings.append(
                _header_finding(
                    name,
                    HEADER_SEVERITY.get(name, "INFO"),
                    message,
                )
            )
            continue

        text = str(value or "")
        lowered = text.lower()

        if name == "HSTS":
            match = _HSTS_MAX_AGE_RE.search(text)
            if not match or int(match.group(1)) == 0:
                findings.append(
                    _header_finding(
                        name,
                        "MEDIUM",
                        "HSTS has a missing or zero max-age",
                    )
                )

        elif name == "CSP":
            weak = []
            if "unsafe-inline" in lowered:
                weak.append("unsafe-inline")
            if "unsafe-eval" in lowered:
                weak.append("unsafe-eval")

            if weak:
                findings.append(
                    _header_finding(
                        name,
                        "LOW",
                        f"CSP allows {', '.join(weak)}",
                    )
                )

        elif name == "X-Content-Type-Options":
            if lowered.strip() != "nosniff":
                findings.append(
                    _header_finding(
                        name,
                        "LOW",
                        "X-Content-Type-Options is not set to nosniff",
                    )
                )

        elif name == "X-Frame-Options":
            if lowered.strip() not in ("deny", "sameorigin") and not lowered.startswith(
                "allow-from "
            ):
                findings.append(
                    _header_finding(
                        name,
                        "LOW",
                        "X-Frame-Options has an invalid value",
                    )
                )

    return findings


def analyze_tls(tls: dict) -> list[dict]:
    """Turn TLS inspection output into severity-ranked findings."""

    if not tls or tls.get("skipped"):
        return []

    findings = []

    if "error" in tls:
        findings.append(
            {
                "type": "tls",
                "name": "TLS",
                "severity": "MEDIUM",
                "message": (
                    "TLS inspection failed: "
                    f"{sanitize(tls.get('error', 'unknown error'))}"
                ),
            }
        )
        return findings

    if tls.get("verified") is False:
        findings.append(
            {
                "type": "tls",
                "name": "TLS",
                "severity": "MEDIUM",
                "message": (
                    "TLS certificate could not be verified: "
                    f"{sanitize(tls.get('verification_error') or 'unknown error')}"
                ),
            }
        )

    days_left = tls.get("days_left")
    if days_left is not None and days_left < 0:
        findings.append(
            {
                "type": "tls",
                "name": "TLS",
                "severity": "HIGH",
                "message": "TLS certificate has expired",
            }
        )
    elif days_left is not None and days_left <= 30:
        findings.append(
            {
                "type": "tls",
                "name": "TLS",
                "severity": "LOW",
                "message": (
                    f"TLS certificate expires in {days_left} day(s)"
                ),
            }
        )

    version = str(tls.get("version") or "")
    if version.upper() in ("TLSV1", "TLSV1.1", "SSLV2", "SSLV3"):
        findings.append(
            {
                "type": "tls",
                "name": "TLS",
                "severity": "HIGH",
                "message": f"Obsolete TLS protocol version: {version}",
            }
        )

    cipher = str(tls.get("cipher") or "")
    weak_markers = ("RC4", "3DES", "DES_", "NULL", "MD5", "EXPORT")
    if any(marker in cipher.upper() for marker in weak_markers):
        findings.append(
            {
                "type": "tls",
                "name": "TLS",
                "severity": "HIGH",
                "message": f"Weak TLS cipher suite: {cipher}",
            }
        )

    return findings


def summarize(findings: list[dict]) -> dict:
    summary = {severity: 0 for severity in SEVERITY_ORDER}

    for finding in findings:
        severity = finding.get("severity", "INFO")

        if severity not in summary:
            severity = "INFO"

        summary[severity] += 1

    summary["total"] = len(findings)

    return summary


def highest_severity(findings: list[dict]) -> str | None:
    """Return the most severe finding level, or ``None`` when empty."""

    present = {
        finding.get("severity", "INFO")
        for finding in findings or []
    }
    for severity in SEVERITY_ORDER:
        if severity in present:
            return severity
    return None
