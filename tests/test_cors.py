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
