import dns.resolver

from styxscan.dns import analyze_security


def test_spf_present():
    records = {
        "TXT": [
            "v=spf1 -all"
        ]
    }

    result = analyze_security(
        "example.com",
        records,
    )

    assert result["spf"]["present"] is True


def test_spf_missing():
    records = {
        "TXT": []
    }

    result = analyze_security(
        "example.com",
        records,
    )

    assert result["spf"]["present"] is False

    findings = result["findings"]

    assert any(
        finding["name"] == "SPF"
        for finding in findings
    )


def test_dmarc_missing(monkeypatch):
    records = {
        "TXT": [
            "v=spf1 -all"
        ]
    }

    def fake_resolve(domain, record_type):
        raise dns.resolver.NXDOMAIN

    monkeypatch.setattr(
        dns.resolver,
        "resolve",
        fake_resolve,
    )

    result = analyze_security(
        "example.com",
        records,
    )

    findings = result["findings"]

    assert any(
        finding["name"] == "DMARC"
        for finding in findings
    )


def test_dnssec_missing(monkeypatch):
    records = {
        "TXT": [
            "v=spf1 -all"
        ]
    }

    def fake_resolve(domain, record_type):
        raise dns.resolver.NXDOMAIN

    monkeypatch.setattr(
        dns.resolver,
        "resolve",
        fake_resolve,
    )

    result = analyze_security(
        "example.com",
        records,
    )

    findings = result["findings"]

    assert any(
        finding["name"] == "DNSSEC"
        for finding in findings
    )
