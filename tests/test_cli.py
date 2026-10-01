import json

from styxscan import cli


def test_normalize_url():
    assert (
        cli.normalize_url("example.com")
        == "https://example.com"
    )

    assert (
        cli.normalize_url("https://example.com")
        == "https://example.com"
    )

    assert (
        cli.normalize_url("http://example.com")
        == "http://example.com"
    )


def test_main_json_output(monkeypatch, capsys):
    fake_http = {
        "status": 200,
        "url": "https://example.com/",
        "headers": {},
        "server": "test-server",
        "powered_by": None,
        "history": [],
    }

    monkeypatch.setattr(
        cli,
        "fetch",
        lambda target, timeout=10: fake_http,
    )

    monkeypatch.setattr(
        cli,
        "resolve",
        lambda domain: {
            "A": ["192.0.2.1"],
            "AAAA": [],
            "MX": [],
            "NS": [],
            "TXT": [],
        },
    )

    monkeypatch.setattr(
        cli,
        "analyze_security",
        lambda domain, records: {
            "spf": {
                "present": True,
                "records": [],
            },
            "dmarc": {
                "present": True,
                "records": [],
            },
            "dnssec": {
                "present": True,
            },
            "findings": [],
        },
    )

    monkeypatch.setattr(
        cli,
        "inspect",
        lambda target: {
            "version": "TLSv1.3",
            "cipher": "TEST-CIPHER",
            "subject": "example.com",
            "issuer": "Test CA",
            "issued_at": None,
            "expires_at": None,
            "days_left": 100,
        },
    )

    monkeypatch.setattr(
        cli,
        "show",
        lambda result: None,
    )

    monkeypatch.setattr(
        "sys.argv",
        [
            "styxscan",
            "example.com",
            "--json",
        ],
    )

    assert cli.main() == 0 

    output = capsys.readouterr().out

    result = json.loads(output)

    assert (
        result["target"]
        == "https://example.com"
    )

    assert (
        result["http"]["status"]
        == 200
    )

    assert "headers" in result
    assert "dns" in result
    assert "tls" in result
    assert "findings" in result


def test_main_http_error(monkeypatch, capsys):
    monkeypatch.setattr(
        cli,
        "fetch",
        lambda target, timeout=10: {
            "error": "connection failed"
        },
    )

    monkeypatch.setattr(
        "sys.argv",
        [
            "styxscan",
            "example.com",
        ],
    )

    cli.main()

    output = capsys.readouterr().out

    assert "HTTP error" in output
    assert "connection failed" in output


def test_main_no_dns(monkeypatch):
    fake_http = {
        "status": 200,
        "url": "https://example.com/",
        "headers": {},
        "server": "test-server",
        "powered_by": None,
        "history": [],
    }

    monkeypatch.setattr(
        cli,
        "fetch",
        lambda target, timeout=10: fake_http,
    )

    def fail_resolve(domain):
        raise AssertionError(
            "DNS should not run"
        )

    monkeypatch.setattr(
        cli,
        "resolve",
        fail_resolve,
    )

    monkeypatch.setattr(
        cli,
        "inspect",
        lambda target: {
            "version": "TLSv1.3",
            "cipher": "TEST-CIPHER",
            "subject": "example.com",
            "issuer": "Test CA",
            "issued_at": None,
            "expires_at": None,
            "days_left": 100,
        },
    )

    monkeypatch.setattr(
        cli,
        "show",
        lambda result: None,
    )

    monkeypatch.setattr(
        "sys.argv",
        [
            "styxscan",
            "example.com",
            "--no-dns",
        ],
    )

    cli.main()


def test_main_no_tls(monkeypatch):
    fake_http = {
        "status": 200,
        "url": "https://example.com/",
        "headers": {},
        "server": "test-server",
        "powered_by": None,
        "history": [],
    }

    monkeypatch.setattr(
        cli,
        "fetch",
        lambda target, timeout=10: fake_http,
    )

    monkeypatch.setattr(
        cli,
        "resolve",
        lambda domain: {
            "A": ["192.0.2.1"],
            "AAAA": [],
            "MX": [],
            "NS": [],
            "TXT": [],
        },
    )

    monkeypatch.setattr(
        cli,
        "analyze_security",
        lambda domain, records: {
            "spf": {
                "present": True,
                "records": [],
            },
            "dmarc": {
                "present": True,
                "records": [],
            },
            "dnssec": {
                "present": True,
            },
            "findings": [],
        },
    )

    def fail_tls(target):
        raise AssertionError(
            "TLS should not run"
        )

    monkeypatch.setattr(
        cli,
        "inspect",
        fail_tls,
    )

    monkeypatch.setattr(
        cli,
        "show",
        lambda result: None,
    )

    monkeypatch.setattr(
        "sys.argv",
        [
            "styxscan",
            "example.com",
            "--no-tls",
        ],
    )

    cli.main()


def test_timeout_is_passed_to_fetch(monkeypatch):
    captured = {}

    fake_http = {
        "status": 200,
        "url": "https://example.com/",
        "headers": {},
        "server": "test-server",
        "powered_by": None,
        "history": [],
    }

    def fake_fetch(
        target,
        timeout=10,
    ):
        captured["target"] = target
        captured["timeout"] = timeout

        return fake_http

    monkeypatch.setattr(
        cli,
        "fetch",
        fake_fetch,
    )

    monkeypatch.setattr(
        cli,
        "resolve",
        lambda domain: {
            "A": [],
            "AAAA": [],
            "MX": [],
            "NS": [],
            "TXT": [],
        },
    )

    monkeypatch.setattr(
        cli,
        "analyze_security",
        lambda domain, records: {
            "spf": {
                "present": True,
                "records": [],
            },
            "dmarc": {
                "present": True,
                "records": [],
            },
            "dnssec": {
                "present": True,
            },
            "findings": [],
        },
    )

    monkeypatch.setattr(
        cli,
        "inspect",
        lambda target: {
            "version": "TLSv1.3",
            "cipher": "TEST-CIPHER",
            "subject": "example.com",
            "issuer": "Test CA",
            "issued_at": None,
            "expires_at": None,
            "days_left": 100,
        },
    )

    monkeypatch.setattr(
        cli,
        "show",
        lambda result: None,
    )

    monkeypatch.setattr(
        "sys.argv",
        [
            "styxscan",
            "example.com",
            "--timeout",
            "5",
        ],
    )

    cli.main()

    assert (
        captured["target"]
        == "https://example.com"
    )

    assert captured["timeout"] == 5


def test_invalid_timeout(monkeypatch):
    monkeypatch.setattr(
        "sys.argv",
        [
            "styxscan",
            "example.com",
            "--timeout",
            "0",
        ],
    )

    try:
        cli.main()
    except SystemExit as error:
        assert error.code == 2
    else:
        raise AssertionError(
            "Expected SystemExit"
        )
