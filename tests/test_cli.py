import json

import pytest

from styxscan import __version__, cli


def make_http(**overrides):
    result = {
        "status": 200,
        "url": "https://example.com/",
        "headers": {},
        "content": "<html></html>",
        "content_type": "text/html",
        "content_truncated": False,
        "set_cookie": [],
        "server": "test-server",
        "powered_by": None,
        "history": [],
        "scheme_downgrade": False,
    }
    result.update(overrides)
    return result


def make_dns_security(**overrides):
    result = {
        "spf": {"present": True, "records": ["v=spf1 -all"]},
        "dmarc": {
            "present": True,
            "policy": "reject",
            "records": ["v=DMARC1; p=reject"],
        },
        "dnssec": {"present": True},
        "findings": [],
        "warnings": [],
    }
    result.update(overrides)
    return result


def make_security_txt(**overrides):
    result = {
        "found": True,
        "url": "https://example.com/.well-known/security.txt",
        "status": 200,
        "fields": {"contact": ["mailto:security@example.com"]},
        "contacts": ["mailto:security@example.com"],
        "expires": "2027-01-01T00:00:00+00:00",
        "expires_at": "2027-01-01T00:00:00+00:00",
        "expired": False,
        "valid": True,
        "findings": [],
        "warnings": [],
    }
    result.update(overrides)
    return result


def patch_scan(monkeypatch, http=None, security_txt=None):
    monkeypatch.setattr(cli, "fetch", lambda target, timeout=10: http or make_http())
    monkeypatch.setattr(
        cli,
        "resolve_with_warnings",
        lambda domain, timeout=5: (
            {
                "A": ["192.0.2.1"],
                "AAAA": [],
                "MX": [],
                "NS": [],
                "TXT": ["v=spf1 -all"],
            },
            [],
        ),
    )
    monkeypatch.setattr(
        cli,
        "analyze_security",
        lambda domain, records, timeout=5: make_dns_security(),
    )
    monkeypatch.setattr(
        cli,
        "inspect",
        lambda target, timeout=10: {
            "connected": True,
            "verified": True,
            "verification_error": None,
            "version": "TLSv1.3",
            "cipher": "TEST-CIPHER",
            "subject": "example.com",
            "issuer": "Test CA",
            "serial": "01AB",
            "issued_at": None,
            "expires_at": None,
            "days_left": 100,
            "expired": False,
            "san": [],
        },
    )
    monkeypatch.setattr(
        cli,
        "discover_security_txt",
        lambda target, timeout=10: security_txt or make_security_txt(),
    )
    monkeypatch.setattr(cli, "show", lambda result: None)


def test_normalize_url():
    assert cli.normalize_url("example.com") == "https://example.com"
    assert (
        cli.normalize_url("https://example.com")
        == "https://example.com"
    )
    assert cli.normalize_url("http://example.com") == "http://example.com"


def test_normalize_url_preserves_path_and_case_folds_scheme():
    assert (
        cli.normalize_url("HTTP://Example.COM/path?q=1")
        == "http://example.com/path?q=1"
    )


def test_normalize_url_converts_idn():
    assert (
        cli.normalize_url("https://bücher.example")
        == "https://xn--bcher-kva.example"
    )


def test_normalize_url_accepts_ipv4_ipv6_and_ports():
    assert cli.normalize_url("127.0.0.1") == "https://127.0.0.1"
    assert (
        cli.normalize_url("https://[::1]:8443/x")
        == "https://[::1]:8443/x"
    )
    assert (
        cli.normalize_url("example.com:8443")
        == "https://example.com:8443"
    )


@pytest.mark.parametrize(
    "target",
    [
        "",
        "   ",
        "ftp://example.com",
        "https://",
        "https://exa mple.com",
        "https://example.com:abc",
        "https://user:pass@example.com",
        "example.com\\@evil.com",
        "https://example..com",
        "https://-bad.com",
        "https://bad-.com",
        "https://example.com:0",
        "https://example.com\x1b[31m",
    ],
)
def test_normalize_url_rejects_invalid_targets(target):
    with pytest.raises(ValueError):
        cli.normalize_url(target)


def test_domain_from_url_uses_ascii_hostname():
    assert cli.domain_from_url("https://example.com./x") == "example.com"
    assert (
        cli.domain_from_url("https://bücher.example")
        == "xn--bcher-kva.example"
    )


def test_main_json_output(monkeypatch, capsys):
    patch_scan(monkeypatch)

    assert cli.main(["example.com", "--json"]) == 0

    result = json.loads(capsys.readouterr().out)

    assert result["tool"] == "styxscan"
    assert result["version"] == __version__
    assert result["target"] == "https://example.com"
    assert result["http"]["status"] == 200
    assert result["headers"] is not None
    assert result["dns"]["A"] == ["192.0.2.1"]
    assert result["tls"]["version"] == "TLSv1.3"
    assert result["security_txt"]["valid"] is True
    assert "findings" in result
    assert result["security_summary"]["total"] == len(result["findings"])


def test_main_http_error_returns_one(monkeypatch, capsys):
    monkeypatch.setattr(
        cli,
        "fetch",
        lambda target, timeout=10: {"error": "connection failed"},
    )

    assert cli.main(["example.com"]) == 1

    output = capsys.readouterr().out
    assert "HTTP error" in output
    assert "connection failed" in output


def test_main_http_error_json_has_envelope(monkeypatch, capsys):
    monkeypatch.setattr(
        cli,
        "fetch",
        lambda target, timeout=10: {"error": "connection failed"},
    )

    assert cli.main(["example.com", "--json"]) == 1

    result = json.loads(capsys.readouterr().out)
    assert result["tool"] == "styxscan"
    assert result["version"] == __version__
    assert result["target"] == "https://example.com"
    assert result["error"] == "connection failed"


def test_invalid_target_returns_exit_code_two(capsys):
    assert cli.main(["bad target"]) == 2
    assert "whitespace" in capsys.readouterr().err


def test_main_no_dns(monkeypatch):
    patch_scan(monkeypatch)
    monkeypatch.setattr(
        cli,
        "resolve_with_warnings",
        lambda *args, **kwargs: pytest.fail("DNS should not run"),
    )

    assert cli.main(["example.com", "--no-dns", "--json"]) == 0


def test_main_no_tls(monkeypatch):
    patch_scan(monkeypatch)
    monkeypatch.setattr(
        cli,
        "inspect",
        lambda *args, **kwargs: pytest.fail("TLS should not run"),
    )

    assert cli.main(["example.com", "--no-tls", "--json"]) == 0


def test_main_no_security_txt(monkeypatch):
    patch_scan(monkeypatch)
    monkeypatch.setattr(
        cli,
        "discover_security_txt",
        lambda *args, **kwargs: pytest.fail(
            "security.txt discovery should not run"
        ),
    )

    assert cli.main(["example.com", "--no-security-txt", "--json"]) == 0


def test_http_target_skips_tls(monkeypatch, capsys):
    patch_scan(monkeypatch)
    monkeypatch.setattr(
        cli,
        "inspect",
        lambda *args, **kwargs: pytest.fail("TLS should not run for HTTP"),
    )

    assert cli.main(["http://example.com", "--json"]) == 0

    result = json.loads(capsys.readouterr().out)
    assert result["tls"]["skipped"] is True
    assert "not HTTPS" in result["tls"]["reason"]


def test_timeout_is_passed_to_fetch_and_tls(monkeypatch):
    captured = {}

    monkeypatch.setattr(
        cli,
        "fetch",
        lambda target, timeout=10: (
            captured.update(target=target, timeout=timeout) or make_http()
        ),
    )
    monkeypatch.setattr(
        cli,
        "resolve_with_warnings",
        lambda domain, timeout=5: ({}, []),
    )
    monkeypatch.setattr(
        cli,
        "analyze_security",
        lambda domain, records, timeout=5: make_dns_security(),
    )
    monkeypatch.setattr(
        cli,
        "inspect",
        lambda target, timeout=10: (
            captured.update(tls_timeout=timeout)
            or {
                "connected": True,
                "verified": True,
                "version": "TLSv1.3",
                "cipher": "TEST",
                "days_left": 10,
                "expired": False,
            }
        ),
    )
    monkeypatch.setattr(
        cli,
        "discover_security_txt",
        lambda target, timeout=10: make_security_txt(),
    )
    monkeypatch.setattr(cli, "show", lambda result: None)

    assert cli.main(["example.com", "--timeout", "5"]) == 0

    assert captured["target"] == "https://example.com"
    assert captured["timeout"] == 5
    assert captured["tls_timeout"] == 5


def test_html_report_is_written(monkeypatch, tmp_path):
    patch_scan(monkeypatch)
    report = tmp_path / "report.html"

    assert cli.main(["example.com", "--html", str(report)]) == 0

    html = report.read_text(encoding="utf-8")
    assert "STYXSCAN" in html
    assert "https://example.com" in html
    assert "security.txt" in html


def test_json_and_html_together(monkeypatch, tmp_path, capsys):
    patch_scan(monkeypatch)
    report = tmp_path / "report.html"

    assert (
        cli.main(["example.com", "--json", "--html", str(report)])
        == 0
    )

    result = json.loads(capsys.readouterr().out)
    assert result["tool"] == "styxscan"
    assert report.exists()


def test_html_save_failure_returns_one(monkeypatch, tmp_path, capsys):
    patch_scan(monkeypatch)
    monkeypatch.setattr(
        cli,
        "generate",
        lambda result, output: (_ for _ in ()).throw(OSError("denied")),
    )

    assert (
        cli.main(
            ["example.com", "--json", "--html", str(tmp_path / "x.html")]
        )
        == 1
    )
    assert "Could not save HTML report" in capsys.readouterr().err


@pytest.mark.parametrize("value", ["0", "-1", "61", "nope"])
def test_invalid_timeout_is_rejected(value):
    with pytest.raises(SystemExit) as excinfo:
        cli.main(["example.com", "--timeout", value])
    assert excinfo.value.code == 2


def test_version_flag(capsys):
    with pytest.raises(SystemExit) as excinfo:
        cli.main(["--version"])
    assert excinfo.value.code == 0
    assert __version__ in capsys.readouterr().out
