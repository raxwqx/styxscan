"""Technology fingerprinting from HTTP responses."""

from __future__ import annotations

import re

from .headers import get_header

_HTML_PATTERNS = (
    (
        "WordPress",
        "CMS",
        "high",
        re.compile(r"wp-(?:content|includes)/", re.IGNORECASE),
        "HTML references WordPress asset paths",
    ),
    (
        "Joomla",
        "CMS",
        "medium",
        re.compile(r"joomla|/media/system/js/", re.IGNORECASE),
        "HTML contains a Joomla fingerprint",
    ),
    (
        "Drupal",
        "CMS",
        "high",
        re.compile(r"drupal-settings-json", re.IGNORECASE),
        "HTML contains drupal-settings-json",
    ),
    (
        "Next.js",
        "Framework",
        "high",
        re.compile(r"__next_data__|/_next/static/", re.IGNORECASE),
        "HTML contains a Next.js fingerprint",
    ),
    (
        "React",
        "JavaScript Framework",
        "medium",
        re.compile(
            r"/react(?:\.production|\.development)?(?:\.min)?\.js"
            r"|data-reactroot|react-dom",
            re.IGNORECASE,
        ),
        "HTML contains a React fingerprint",
    ),
    (
        "Vue.js",
        "JavaScript Framework",
        "medium",
        re.compile(
            r"vue(?:\.global|\.min)?\.js|data-v-[0-9a-f]{8}"
            r"|v-cloak|data-v-app",
            re.IGNORECASE,
        ),
        "HTML contains a Vue fingerprint",
    ),
    (
        "Angular",
        "JavaScript Framework",
        "medium",
        re.compile(
            r"angular(?:\.min)?\.js|ng-version=|app-root",
            re.IGNORECASE,
        ),
        "HTML contains an Angular fingerprint",
    ),
    (
        "jQuery",
        "JavaScript Library",
        "medium",
        re.compile(
            r"jquery(?:-[\d.]+)?(?:\.min)?\.js",
            re.IGNORECASE,
        ),
        "HTML contains a jQuery fingerprint",
    ),
    (
        "Bootstrap",
        "CSS Framework",
        "medium",
        re.compile(
            r"bootstrap(?:\.bundle)?(?:\.min)?\.(?:css|js)",
            re.IGNORECASE,
        ),
        "HTML contains a Bootstrap fingerprint",
    ),
    (
        "Tailwind CSS",
        "CSS Framework",
        "medium",
        re.compile(r"tailwind(?:css)?", re.IGNORECASE),
        "HTML contains a Tailwind fingerprint",
    ),
    (
        "Laravel",
        "Framework",
        "medium",
        re.compile(r"laravel_session|laravel", re.IGNORECASE),
        "HTML contains a Laravel fingerprint",
    ),
    (
        "Django",
        "Framework",
        "medium",
        re.compile(r"csrfmiddlewaretoken|django", re.IGNORECASE),
        "HTML contains a Django fingerprint",
    ),
)


def _add(technologies: list[dict], seen: set[str], technology: dict) -> None:
    name = technology["name"]
    if name in seen:
        return
    seen.add(name)
    technologies.append(technology)


def analyze(http_result: dict) -> dict:
    """Fingerprint common servers, runtimes, and frontend frameworks.

    Patterns are deliberately narrow. Substring checks such as ``"vue" in
    html`` match ordinary words like ``value`` or ``reaction`` and are not
    used here.
    """

    technologies: list[dict] = []
    seen: set[str] = set()

    headers = http_result.get("headers", {}) or {}
    server = get_header(headers, "Server", "") or ""
    powered_by = get_header(headers, "X-Powered-By", "") or ""

    server_lower = str(server).lower()
    powered_lower = str(powered_by).lower()

    if "cloudflare" in server_lower:
        _add(
            technologies,
            seen,
            {
                "name": "Cloudflare",
                "category": "CDN / Proxy",
                "confidence": "high",
                "evidence": f"Server: {server}",
            },
        )
    elif "nginx" in server_lower:
        _add(
            technologies,
            seen,
            {
                "name": "Nginx",
                "category": "Web Server",
                "confidence": "high",
                "evidence": f"Server: {server}",
            },
        )
    elif "openresty" in server_lower:
        _add(
            technologies,
            seen,
            {
                "name": "OpenResty",
                "category": "Web Server",
                "confidence": "high",
                "evidence": f"Server: {server}",
            },
        )
    elif "apache" in server_lower:
        _add(
            technologies,
            seen,
            {
                "name": "Apache",
                "category": "Web Server",
                "confidence": "high",
                "evidence": f"Server: {server}",
            },
        )
    elif "microsoft-iis" in server_lower:
        _add(
            technologies,
            seen,
            {
                "name": "Microsoft IIS",
                "category": "Web Server",
                "confidence": "high",
                "evidence": f"Server: {server}",
            },
        )

    if "php" in powered_lower:
        _add(
            technologies,
            seen,
            {
                "name": "PHP",
                "category": "Runtime",
                "confidence": "high",
                "evidence": f"X-Powered-By: {powered_by}",
            },
        )
    elif "express" in powered_lower:
        _add(
            technologies,
            seen,
            {
                "name": "Express",
                "category": "Framework",
                "confidence": "high",
                "evidence": f"X-Powered-By: {powered_by}",
            },
        )
    elif "asp.net" in powered_lower:
        _add(
            technologies,
            seen,
            {
                "name": "ASP.NET",
                "category": "Framework",
                "confidence": "high",
                "evidence": f"X-Powered-By: {powered_by}",
            },
        )

    content_type = http_result.get("content_type")
    content = http_result.get("content", "") or ""
    if content_type and not any(
        marker in str(content_type).lower()
        for marker in ("text/html", "application/xhtml+xml", "text/plain")
    ):
        content = ""

    for name, category, confidence, pattern, evidence in _HTML_PATTERNS:
        if pattern.search(content):
            _add(
                technologies,
                seen,
                {
                    "name": name,
                    "category": category,
                    "confidence": confidence,
                    "evidence": evidence,
                },
            )

    return {
        "technologies": technologies,
        "findings": [],
    }
