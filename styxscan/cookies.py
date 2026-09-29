from http.cookies import SimpleCookie


def analyze(response):
    findings = []
    cookies = []

    raw_headers = response.get(
        "headers",
        {}
    )

    set_cookie_headers = response.get(
        "set_cookie",
        []
    )

    if not set_cookie_headers:
        set_cookie = raw_headers.get(
            "Set-Cookie"
        )

        if set_cookie:
            set_cookie_headers = [
                set_cookie
            ]

    for set_cookie in set_cookie_headers:
        cookie = SimpleCookie()

        try:
            cookie.load(set_cookie)
        except Exception:
            continue

        for name, morsel in cookie.items():
            secure = bool(
                morsel["secure"]
            )

            httponly = bool(
                morsel["httponly"]
            )

            samesite = morsel["samesite"]

            cookie_info = {
                "name": name,
                "secure": secure,
                "httponly": httponly,
                "samesite": samesite or None,
            }

            cookies.append(cookie_info)

            if not secure:
                findings.append({
                    "type": "cookie",
                    "name": name,
                    "severity": "MEDIUM",
                    "message": (
                        f"Cookie {name} "
                        "is missing Secure"
                    ),
                })

            if not httponly:
                findings.append({
                    "type": "cookie",
                    "name": name,
                    "severity": "LOW",
                    "message": (
                        f"Cookie {name} "
                        "is missing HttpOnly"
                    ),
                })

            if not samesite:
                findings.append({
                    "type": "cookie",
                    "name": name,
                    "severity": "LOW",
                    "message": (
                        f"Cookie {name} "
                        "has no SameSite attribute"
                    ),
                })

    return {
        "cookies": cookies,
        "findings": findings,
    }
