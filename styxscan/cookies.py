"""Cookie security analysis."""

from __future__ import annotations

from http.cookies import CookieError, SimpleCookie

from .headers import get_header
from .sanitize import sanitize


def _cookie_header(response) -> list[str]:
    set_cookie_headers = response.get("set_cookie", []) or []

    if not set_cookie_headers:
        set_cookie = get_header(response.get("headers", {}), "Set-Cookie")
        if set_cookie:
            set_cookie_headers = [set_cookie]

    return list(set_cookie_headers)


def analyze(response: dict) -> dict:
    """Inspect ``Set-Cookie`` values for missing security attributes."""

    findings = []
    cookies = []

    for set_cookie in _cookie_header(response):
        cookie = SimpleCookie()

        try:
            cookie.load(set_cookie)
        except (CookieError, ValueError):
            continue

        for name, morsel in cookie.items():
            secure = bool(morsel["secure"])
            httponly = bool(morsel["httponly"])
            samesite = morsel["samesite"]
            path = morsel["path"]
            domain = morsel["domain"]
            display_name = sanitize(name, 64)

            cookies.append(
                {
                    "name": name,
                    "secure": secure,
                    "httponly": httponly,
                    "samesite": samesite or None,
                }
            )

            if not secure:
                findings.append(
                    {
                        "type": "cookie",
                        "name": name,
                        "severity": "MEDIUM",
                        "message": f"Cookie {display_name} is missing Secure",
                    }
                )

            if not httponly:
                findings.append(
                    {
                        "type": "cookie",
                        "name": name,
                        "severity": "LOW",
                        "message": f"Cookie {display_name} is missing HttpOnly",
                    }
                )

            if not samesite:
                findings.append(
                    {
                        "type": "cookie",
                        "name": name,
                        "severity": "LOW",
                        "message": (
                            f"Cookie {display_name} has no SameSite attribute"
                        ),
                    }
                )
            elif samesite.lower() == "none" and not secure:
                findings.append(
                    {
                        "type": "cookie",
                        "name": name,
                        "severity": "HIGH",
                        "message": (
                            f"Cookie {display_name} uses SameSite=None "
                            "without Secure"
                        ),
                    }
                )

            if name.startswith("__Host-"):
                problems = []
                if not secure:
                    problems.append("Secure")
                if path != "/":
                    problems.append("Path=/")
                if domain:
                    problems.append("a Domain attribute")

                if problems:
                    findings.append(
                        {
                            "type": "cookie",
                            "name": name,
                            "severity": "HIGH",
                            "message": (
                                f"Cookie {display_name} violates the __Host- "
                                f"prefix rules: missing or invalid "
                                f"{', '.join(problems)}"
                            ),
                        }
                    )
            elif name.startswith("__Secure-") and not secure:
                findings.append(
                    {
                        "type": "cookie",
                        "name": name,
                        "severity": "HIGH",
                        "message": (
                            f"Cookie {display_name} uses the __Secure- prefix "
                            "without Secure"
                        ),
                    }
                )

    return {
        "cookies": cookies,
        "findings": findings,
    }
