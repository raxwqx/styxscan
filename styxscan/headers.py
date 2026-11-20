"""Security header detection."""

from __future__ import annotations

SECURITY_HEADERS = {
    "Strict-Transport-Security": "HSTS",
    "Content-Security-Policy": "CSP",
    "X-Content-Type-Options": "X-Content-Type-Options",
    "X-Frame-Options": "X-Frame-Options",
    "Referrer-Policy": "Referrer-Policy",
    "Permissions-Policy": "Permissions-Policy",
}


def get_header(headers, name: str, default=None):
    """Return a header value using a case-insensitive lookup."""

    if not headers:
        return default

    getter = getattr(headers, "get", None)
    if getter is not None:
        value = getter(name)
        if value is not None:
            return value

    for key, value in headers.items():
        if str(key).lower() == name.lower():
            return value

    return default


def analyze(headers) -> list[dict]:
    """Report which security headers are present and their raw values."""

    headers = headers or {}
    results = []

    for header, name in SECURITY_HEADERS.items():
        value = get_header(headers, header)
        present = value is not None and str(value).strip() != ""

        result = {
            "name": name,
            "header": header,
            "present": present,
            "value": value,
        }

        if name == "CSP":
            report_only = get_header(
                headers,
                "Content-Security-Policy-Report-Only",
            )
            result["report_only"] = report_only is not None
            result["report_only_value"] = report_only

        results.append(result)

    return results
