import dns.exception
import dns.resolver
import pytest

from styxscan import dns as dns_module
from styxscan.dns import (
    RECORD_TYPES,
    analyze_security,
    resolve,
    resolve_with_warnings,
)


class FakeAnswer:
    def __init__(self, values):
        self._values = list(values or [])
        self.rrset = object() if values else None

    def __iter__(self):
        return iter(self._values)


@pytest.fixture(autouse=True)
def no_live_dns(monkeypatch):
    def fake_query(name, record_type, timeout):
        raise dns.resolver.NXDOMAIN

    monkeypatch.setattr(dns_module, "_query", fake_query)


def spf_records(*records):
    return {"TXT": list(records)}


def test_spf_present():
    result = analyze_security("example.com", spf_records("v=spf1 -all"))

    assert result["spf"]["present"] is True
    assert result["findings"] == [
        finding
        for finding in result["findings"]
        if finding["name"] != "SPF"
    ]


def test_spf_missing():
    result = analyze_security("example.com", {"TXT": []})

    assert result["spf"]["present"] is False
    assert any(
        finding["name"] == "SPF" for finding in result["findings"]
    )


def test_multiple_spf_records_are_flagged():
    result = analyze_security(
        "example.com",
        spf_records("v=spf1 -all", "v=spf1 include:example.net -all"),
    )

    assert any(
        finding["name"] == "SPF"
        and "Multiple" in finding["message"]
        for finding in result["findings"]
    )


def test_spf_plus_all_is_high_severity():
    result = analyze_security(
        "example.com",
        spf_records("v=spf1 +all"),
    )

    assert any(
        finding["name"] == "SPF"
        and finding["severity"] == "HIGH"
        for finding in result["findings"]
    )


def test_dmarc_missing():
    result = analyze_security(
        "example.com",
        spf_records("v=spf1 -all"),
    )

    assert any(
        finding["name"] == "DMARC" for finding in result["findings"]
    )


def test_dmarc_policy_none_is_flagged(monkeypatch):
    def fake_query(name, record_type, timeout):
        if name == "_dmarc.example.com":
            return FakeAnswer(["v=DMARC1; p=none"])
        raise dns.resolver.NXDOMAIN

    monkeypatch.setattr(dns_module, "_query", fake_query)

    result = analyze_security("example.com", spf_records("v=spf1 -all"))

    assert result["dmarc"]["present"] is True
    assert result["dmarc"]["policy"] == "none"
    assert any(
        finding["name"] == "DMARC"
        and "p=none" in finding["message"]
        for finding in result["findings"]
    )


def test_dnssec_missing():
    result = analyze_security(
        "example.com",
        spf_records("v=spf1 -all"),
    )

    assert result["dnssec"]["present"] is False
    assert any(
        finding["name"] == "DNSSEC" for finding in result["findings"]
    )


def test_dnssec_checks_parent_zone_for_subdomain(monkeypatch):
    calls = []

    def fake_query(name, record_type, timeout):
        calls.append((name, record_type))
        if name == "example.com" and record_type == "DNSKEY":
            return FakeAnswer(["257 3 13 TESTKEY"])
        raise dns.resolver.NXDOMAIN

    monkeypatch.setattr(dns_module, "_query", fake_query)

    result = analyze_security(
        "www.example.com",
        spf_records("v=spf1 -all"),
    )

    assert result["dnssec"]["present"] is True
    assert not any(
        finding["name"] == "DNSSEC" for finding in result["findings"]
    )
    assert ("www.example.com", "DNSKEY") in calls
    assert ("example.com", "DNSKEY") in calls


def test_dnssec_does_not_treat_tld_as_target(monkeypatch):
    def fake_query(name, record_type, timeout):
        if name == "com":
            return FakeAnswer(["257 3 13 TLDKEY"])
        raise dns.resolver.NXDOMAIN

    monkeypatch.setattr(dns_module, "_query", fake_query)

    result = analyze_security(
        "example.com",
        spf_records("v=spf1 -all"),
    )

    assert result["dnssec"]["present"] is False


def test_resolve_with_warnings_collects_sorted_unique_values(monkeypatch):
    calls = []

    def fake_query(name, record_type, timeout):
        calls.append((name, record_type, timeout))
        return FakeAnswer(["z", "a", "a"])

    monkeypatch.setattr(dns_module, "_query", fake_query)

    records, warnings = resolve_with_warnings("example.com", timeout=3.5)

    assert warnings == []
    assert list(records) == list(RECORD_TYPES)
    for record_type in RECORD_TYPES:
        assert records[record_type] == ["a", "z"]
    assert calls[0] == ("example.com", "A", 3.5)
    assert len(calls) == len(RECORD_TYPES)


def test_resolve_with_warnings_stops_on_nxdomain(monkeypatch):
    calls = []

    def fake_query(name, record_type, timeout):
        calls.append(record_type)
        raise dns.resolver.NXDOMAIN

    monkeypatch.setattr(dns_module, "_query", fake_query)

    records, warnings = resolve_with_warnings("missing.example")

    assert calls == ["A"]
    assert records["A"] == []
    assert "does not exist" in warnings[0]


def test_resolve_with_warnings_stops_on_timeout(monkeypatch):
    monkeypatch.setattr(
        dns_module,
        "_query",
        lambda name, record_type, timeout: (_ for _ in ()).throw(
            dns.exception.Timeout()
        ),
    )

    records, warnings = resolve_with_warnings("example.com")

    assert warnings == ["A lookup timed out"]
    assert all(values == [] for values in records.values())


def test_resolve_with_warnings_continues_after_single_failure(monkeypatch):
    def fake_query(name, record_type, timeout):
        if record_type == "AAAA":
            raise dns.exception.DNSException("boom")
        return FakeAnswer([record_type])

    monkeypatch.setattr(dns_module, "_query", fake_query)

    records, warnings = resolve_with_warnings("example.com")

    assert records["A"] == ["A"]
    assert records["AAAA"] == []
    assert records["MX"] == ["MX"]
    assert any("AAAA" in warning for warning in warnings)


def test_resolve_with_warnings_does_not_crash_on_unexpected_error(
    monkeypatch,
):
    monkeypatch.setattr(
        dns_module,
        "_query",
        lambda name, record_type, timeout: (_ for _ in ()).throw(
            RuntimeError("bad")
        ),
    )

    records, warnings = resolve_with_warnings("example.com")

    assert all("RuntimeError: bad" in warning for warning in warnings)
    assert all(values == [] for values in records.values())


def test_resolve_wrapper_returns_records_only(monkeypatch):
    monkeypatch.setattr(
        dns_module,
        "_query",
        lambda name, record_type, timeout: FakeAnswer([record_type]),
    )

    records = resolve("example.com")

    assert records["A"] == ["A"]


def test_resolve_rejects_invalid_timeout():
    with pytest.raises(ValueError, match="timeout"):
        resolve_with_warnings("example.com", timeout=0)
