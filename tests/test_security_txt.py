from datetime import timezone

import requests

from styxscan import security_txt


class FakeResponse:
    def __init__(self, status_code=200, text="", url="https://example.com"):
        self.status_code = status_code
        self.text = text
        self.url = url


def test_parse_preserves_repeated_contacts_and_ignores_comments():
    fields = security_txt.parse(
        """
        # Comment
        Contact: mailto:security@example.com
        Contact: https://example.com/report
        Expires: 2027-01-01T00:00:00Z
        Policy: https://example.com/policy
        Unknown: ignored
        """
    )

    assert fields["contact"] == [
        "mailto:security@example.com",
        "https://example.com/report",
    ]
    assert fields["expires"] == ["2027-01-01T00:00:00Z"]
    assert fields["policy"] == ["https://example.com/policy"]
    assert "unknown" not in fields


def test_discover_prefers_well_known(monkeypatch):
    calls = []

    def fake_get(url, **kwargs):
        calls.append(url)
        return FakeResponse(
            text=(
                "Contact: mailto:security@example.com\n"
                "Expires: 2027-01-01T00:00:00Z\n"
            ),
            url=url,
        )

    monkeypatch.setattr(security_txt.requests, "get", fake_get)

    result = security_txt.discover("https://example.com/path?q=1")

    assert calls == [
        "https://example.com/.well-known/security.txt"
    ]
    assert result["found"] is True
    assert result["valid"] is True
    assert result["expired"] is False
    assert result["contacts"] == ["mailto:security@example.com"]
    assert result["findings"] == []


def test_discover_falls_back_to_root_security_txt(monkeypatch):
    calls = []

    def fake_get(url, **kwargs):
        calls.append(url)
        if "well-known" in url:
            return FakeResponse(status_code=404, url=url)
        return FakeResponse(
            text=(
                "Contact: mailto:security@example.com\n"
                "Expires: 2027-01-01T00:00:00Z\n"
            ),
            url=url,
        )

    monkeypatch.setattr(security_txt.requests, "get", fake_get)

    result = security_txt.discover("https://example.com")

    assert calls == [
        "https://example.com/.well-known/security.txt",
        "https://example.com/security.txt",
    ]
    assert result["found"] is True
    assert result["valid"] is True


def test_discover_reports_missing_file(monkeypatch):
    monkeypatch.setattr(
        security_txt.requests,
        "get",
        lambda url, **kwargs: FakeResponse(status_code=404, url=url),
    )

    result = security_txt.discover("https://example.com")

    assert result["found"] is False
    assert result["status"] == 404
    assert result["valid"] is False
    assert result["findings"][0]["severity"] == "LOW"
    assert "missing" in result["findings"][0]["message"]


def test_discover_flags_missing_contact(monkeypatch):
    monkeypatch.setattr(
        security_txt.requests,
        "get",
        lambda url, **kwargs: FakeResponse(
            text="Expires: 2027-01-01T00:00:00Z\n",
            url=url,
        ),
    )

    result = security_txt.discover("https://example.com")

    assert result["found"] is True
    assert result["valid"] is False
    assert any(
        finding["severity"] == "MEDIUM"
        and "Contact" in finding["message"]
        for finding in result["findings"]
    )


def test_discover_flags_expired_file(monkeypatch):
    monkeypatch.setattr(
        security_txt.requests,
        "get",
        lambda url, **kwargs: FakeResponse(
            text=(
                "Contact: mailto:security@example.com\n"
                "Expires: 2020-01-01T00:00:00Z\n"
            ),
            url=url,
        ),
    )

    result = security_txt.discover("https://example.com")

    assert result["expired"] is True
    assert result["valid"] is False
    assert any(
        finding["severity"] == "MEDIUM"
        and "expired" in finding["message"]
        for finding in result["findings"]
    )


def test_discover_flags_invalid_expires(monkeypatch):
    monkeypatch.setattr(
        security_txt.requests,
        "get",
        lambda url, **kwargs: FakeResponse(
            text=(
                "Contact: mailto:security@example.com\n"
                "Expires: next year\n"
            ),
            url=url,
        ),
    )

    result = security_txt.discover("https://example.com")

    assert result["expires_at"] is None
    assert any(
        "ISO 8601" in finding["message"]
        for finding in result["findings"]
    )


def test_discover_reports_network_failures(monkeypatch):
    def fake_get(url, **kwargs):
        raise requests.RequestException("connection failed")

    monkeypatch.setattr(security_txt.requests, "get", fake_get)

    result = security_txt.discover("https://example.com")

    assert result["found"] is False
    assert len(result["warnings"]) == 2
    assert "connection failed" in result["warnings"][0]
    assert result["findings"] == []


def test_parse_expires_handles_naive_and_invalid_values():
    parsed = security_txt._parse_expires("2027-01-01T00:00:00")
    assert parsed is not None
    assert parsed.tzinfo == timezone.utc
    assert security_txt._parse_expires("not a date") is None


def test_parse_expires_accepts_lowercase_z():
    parsed = security_txt._parse_expires("2027-01-01T00:00:00z")
    assert parsed is not None
    assert parsed.tzinfo == timezone.utc


def test_discover_rejects_invalid_url():
    result = security_txt.discover("not a url")
    assert result["found"] is False
    assert "invalid target" in result["error"]
