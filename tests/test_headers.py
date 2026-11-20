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


def test_header_lookup_is_case_insensitive():
    headers = {
        "strict-transport-security": "max-age=31536000",
        "content-security-policy-report-only": "default-src 'self'",
    }

    result = analyze(headers)
    by_name = {header["name"]: header for header in result}

    assert by_name["HSTS"]["present"] is True
    assert by_name["HSTS"]["value"] == "max-age=31536000"
    assert by_name["CSP"]["present"] is False
    assert by_name["CSP"]["report_only"] is True


def test_header_findings_flag_weak_values():
    from styxscan.findings import analyze_headers

    headers = analyze(
        {
            "Strict-Transport-Security": "max-age=0",
            "Content-Security-Policy": "default-src 'self' 'unsafe-inline'",
            "X-Content-Type-Options": "sniff",
            "X-Frame-Options": "ALLOWALL",
        }
    )

    findings = analyze_headers(headers)
    messages = [finding["message"] for finding in findings]

    assert "HSTS has a missing or zero max-age" in messages
    assert "CSP allows unsafe-inline" in messages
    assert "X-Content-Type-Options is not set to nosniff" in messages
    assert "X-Frame-Options has an invalid value" in messages
