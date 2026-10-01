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
        present = header in headers

        result = {
            "name": name,
            "present": present,
        }

        if name == "CSP":
            result["report_only"] = (
                "Content-Security-Policy-Report-Only"
                in headers
            )

        results.append(result)

    return results
