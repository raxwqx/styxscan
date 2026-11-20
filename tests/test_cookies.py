from styxscan.cookies import analyze


def test_secure_cookie():
    response = {
        "headers": {
            "Set-Cookie": (
                "session=abc123; "
                "Secure; "
                "HttpOnly; "
                "SameSite=Lax"
            )
        }
    }

    result = analyze(response)

    assert len(result["cookies"]) == 1

    cookie = result["cookies"][0]

    assert cookie["name"] == "session"
    assert cookie["secure"] is True
    assert cookie["httponly"] is True
    assert cookie["samesite"] == "Lax"

    assert result["findings"] == []


def test_insecure_cookie_creates_findings():
    response = {
        "headers": {
            "Set-Cookie": "session=abc123"
        }
    }

    result = analyze(response)

    assert len(result["cookies"]) == 1

    findings = result["findings"]

    assert any(
        "Secure" in finding["message"]
        for finding in findings
    )

    assert any(
        "HttpOnly" in finding["message"]
        for finding in findings
    )

    assert any(
        "SameSite" in finding["message"]
        for finding in findings
    )


def test_multiple_cookies():
    response = {
        "set_cookie": [
            (
                "session=abc123; "
                "Secure; "
                "HttpOnly; "
                "SameSite=Lax"
            ),
            (
                "csrf=xyz789; "
                "Secure; "
                "HttpOnly; "
                "SameSite=Strict"
            ),
        ],
        "headers": {},
    }

    result = analyze(response)

    assert len(result["cookies"]) == 2

    names = [
        cookie["name"]
        for cookie in result["cookies"]
    ]

    assert "session" in names
    assert "csrf" in names

    assert result["findings"] == []


def test_multiple_cookies_with_findings():
    response = {
        "set_cookie": [
            "session=abc123; Secure; HttpOnly; SameSite=Lax",
            "tracking=xyz789",
        ],
        "headers": {},
    }

    result = analyze(response)

    assert len(result["cookies"]) == 2

    findings = result["findings"]

    assert any(
        finding["name"] == "tracking"
        and "Secure" in finding["message"]
        for finding in findings
    )

    assert any(
        finding["name"] == "tracking"
        and "HttpOnly" in finding["message"]
        for finding in findings
    )

    assert any(
        finding["name"] == "tracking"
        and "SameSite" in finding["message"]
        for finding in findings
    )


def test_no_cookie():
    response = {
        "headers": {}
    }

    result = analyze(response)

    assert result["cookies"] == []
    assert result["findings"] == []


def test_samesite_none_without_secure_is_high_severity():
    result = analyze(
        {
            "set_cookie": [
                "session=abc; HttpOnly; SameSite=None",
            ],
            "headers": {},
        }
    )

    assert any(
        finding["severity"] == "HIGH"
        and "SameSite=None" in finding["message"]
        for finding in result["findings"]
    )


def test_host_prefix_rules_are_enforced():
    result = analyze(
        {
            "set_cookie": [
                "__Host-session=abc; Secure; HttpOnly; SameSite=Lax",
            ],
            "headers": {},
        }
    )

    assert any(
        finding["severity"] == "HIGH"
        and "__Host-" in finding["message"]
        and "Path=/" in finding["message"]
        for finding in result["findings"]
    )


def test_secure_prefix_requires_secure():
    result = analyze(
        {
            "set_cookie": [
                "__Secure-session=abc; HttpOnly; SameSite=Lax",
            ],
            "headers": {},
        }
    )

    assert any(
        finding["severity"] == "HIGH"
        and "__Secure-" in finding["message"]
        for finding in result["findings"]
    )


def test_cookie_lookup_is_case_insensitive():
    result = analyze(
        {
            "headers": {
                "set-cookie": "session=abc; Secure; HttpOnly; SameSite=Lax",
            }
        }
    )

    assert len(result["cookies"]) == 1
    assert result["findings"] == []
