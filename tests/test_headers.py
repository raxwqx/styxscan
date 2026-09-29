from styxscan.headers import analyze


def test_all_security_headers_present():
    headers = {
        "Strict-Transport-Security": "max-age=31536000",
        "Content-Security-Policy": "default-src 'self'",
        "X-Content-Type-Options": "nosniff",
        "X-Frame-Options": "DENY",
        "Referrer-Policy": "strict-origin",
        "Permissions-Policy": "geolocation=()",
    }

    result = analyze(headers)

    assert len(result) == 6
    assert all(
        header["present"]
        for header in result
    )


def test_missing_security_headers():
    headers = {}

    result = analyze(headers)

    assert len(result) == 6
    assert all(
        not header["present"]
        for header in result
    )
