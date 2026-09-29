SECURITY_HEADERS = {
    "Strict-Transport-Security": "HSTS",
    "Content-Security-Policy": "CSP",
    "X-Content-Type-Options": "X-Content-Type-Options",
    "X-Frame-Options": "X-Frame-Options",
    "Referrer-Policy": "Referrer-Policy",
    "Permissions-Policy": "Permissions-Policy",
}


def analyze(headers):
    results = []

    for header, name in SECURITY_HEADERS.items():
        results.append({
            "name": name,
            "present": header in headers,
        })

    return results
