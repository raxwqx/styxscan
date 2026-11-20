from styxscan.cors import analyze


def test_cors_wildcard():
    headers = {
        "Access-Control-Allow-Origin": "*"
    }

    result = analyze(headers)

    findings = result["findings"]

    assert any(
        finding["type"] == "cors"
        for finding in findings
    )


def test_cors_wildcard_with_credentials():
    headers = {
        "Access-Control-Allow-Origin": "*",
        "Access-Control-Allow-Credentials": "true",
    }

    result = analyze(headers)

    findings = result["findings"]

    assert len(findings) == 2

    assert any(
        finding["severity"] == "MEDIUM"
        for finding in findings
    )


def test_no_cors_finding():
    headers = {}

    result = analyze(headers)

    assert result["findings"] == []


def test_cors_headers_are_returned():
    headers = {
        "Access-Control-Allow-Origin": "https://example.com",
        "Access-Control-Allow-Methods": "GET, POST",
        "Access-Control-Allow-Headers": "Content-Type",
    }

    result = analyze(headers)

    assert (
        result["headers"]["Access-Control-Allow-Origin"]
        == "https://example.com"
    )

    assert (
        result["headers"]["Access-Control-Allow-Methods"]
        == "GET, POST"
    )

    assert (
        result["headers"]["Access-Control-Allow-Headers"]
        == "Content-Type"
    )


def test_cors_null_origin_is_medium():
    result = analyze({"Access-Control-Allow-Origin": "null"})

    assert any(
        finding["severity"] == "MEDIUM"
        and "null origin" in finding["message"]
        for finding in result["findings"]
    )


def test_cors_specific_origin_with_credentials_requires_vary():
    result = analyze(
        {
            "Access-Control-Allow-Origin": "https://app.example.com",
            "Access-Control-Allow-Credentials": "true",
        }
    )

    assert any(
        "Vary does not include Origin" in finding["message"]
        for finding in result["findings"]
    )


def test_cors_vary_origin_avoids_finding():
    result = analyze(
        {
            "Access-Control-Allow-Origin": "https://app.example.com",
            "Access-Control-Allow-Credentials": "true",
            "Vary": "Origin",
        }
    )

    assert result["findings"] == []


def test_cors_lookup_is_case_insensitive():
    result = analyze(
        {
            "access-control-allow-origin": "*",
        }
    )

    assert result["headers"]["Access-Control-Allow-Origin"] == "*"
    assert result["findings"]
