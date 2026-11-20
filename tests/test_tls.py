import ssl
from datetime import datetime, timezone

from styxscan import tls


CERT = {
    "notBefore": "Jan  1 00:00:00 2026 GMT",
    "notAfter": "Jan  1 00:00:00 2027 GMT",
    "subject": ((("commonName", "example.com"),),),
    "issuer": ((("commonName", "Test CA"),),),
    "serialNumber": "01AB",
    "subjectAltName": (
        ("DNS", "example.com"),
        ("DNS", "www.example.com"),
    ),
}


def test_tls_inspect_success(monkeypatch):
    class FakeTLS:
        def version(self):
            return "TLSv1.3"

        def cipher(self):
            return ("TLS_AES_256_GCM_SHA384", "TLSv1.3", 256)

        def getpeercert(self):
            return {
                "notBefore": "Jan  1 00:00:00 2026 GMT",
                "notAfter": "Jan  1 00:00:00 2027 GMT",
                "subject": (
                    (
                        ("commonName", "example.com"),
                    ),
                ),
                "issuer": (
                    (
                        ("commonName", "Test CA"),
                    ),
                ),
            }

        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, traceback):
            pass

    class FakeSocket:
        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, traceback):
            pass

    class FakeContext:
        def wrap_socket(self, sock, server_hostname):
            return FakeTLS()

    monkeypatch.setattr(
        tls.socket,
        "create_connection",
        lambda address, timeout: FakeSocket(),
    )
    monkeypatch.setattr(
        tls.ssl,
        "create_default_context",
        lambda: FakeContext(),
    )

    result = tls.inspect("https://example.com")

    assert result["version"] == "TLSv1.3"
    assert result["cipher"] == "TLS_AES_256_GCM_SHA384"
    assert result["verified"] is True
    assert result["connected"] is True
    assert result["expires_at"] is not None
    assert result["issued_at"] is not None
    assert result["days_left"] is not None


def test_tls_inspect_error(monkeypatch):
    def fake_connection(address, timeout):
        raise OSError("connection failed")

    monkeypatch.setattr(
        tls.socket,
        "create_connection",
        fake_connection,
    )

    result = tls.inspect("https://example.com")

    assert result["connected"] is False
    assert "connection failed" in result["error"]


def test_tls_inspect_falls_back_to_unverified_details(monkeypatch):
    calls = []

    def fake_handshake(hostname, port, timeout, verify):
        calls.append(verify)
        if verify:
            raise ssl.SSLCertVerificationError("certificate has expired")
        return CERT, "TLSv1.2", "ECDHE-RSA-AES256-GCM-SHA384"

    monkeypatch.setattr(tls, "_handshake", fake_handshake)

    result = tls.inspect("https://example.com", timeout=3)

    assert calls == [True, False]
    assert result["connected"] is True
    assert result["verified"] is False
    assert "certificate has expired" in result["verification_error"]
    assert result["subject"] == "example.com"
    assert result["issuer"] == "Test CA"
    assert result["serial"] == "01AB"
    assert result["san"] == ["DNS:example.com", "DNS:www.example.com"]


def test_tls_inspect_reports_fallback_connection_failure(monkeypatch):
    def fake_handshake(hostname, port, timeout, verify):
        if verify:
            raise ssl.SSLCertVerificationError("expired")
        raise OSError("connection reset")

    monkeypatch.setattr(tls, "_handshake", fake_handshake)

    result = tls.inspect("https://example.com")

    assert result["connected"] is False
    assert "connection reset" in result["error"]


def test_tls_inspect_rejects_invalid_port():
    result = tls.inspect("https://example.com:notaport")
    assert result["connected"] is False
    assert "error" in result


def test_tls_inspect_rejects_invalid_timeout():
    result = tls.inspect("https://example.com", timeout=0)
    assert result["connected"] is False
    assert "timeout" in result["error"]


def test_tls_inspect_converts_idn_hostname(monkeypatch):
    captured = {}

    def fake_handshake(hostname, port, timeout, verify):
        captured["hostname"] = hostname
        return CERT, "TLSv1.3", "CIPHER"

    monkeypatch.setattr(tls, "_handshake", fake_handshake)

    tls.inspect("https://bücher.example")

    assert captured["hostname"] == "xn--bcher-kva.example"


def test_decode_der_certificate_returns_empty_without_der():
    assert tls._decode_der_certificate(None) == {}
    assert tls._decode_der_certificate(b"") == {}


def test_certificate_time_handles_invalid_values():
    assert tls._certificate_time("not a date") is None
    parsed = tls._certificate_time("Jan  1 00:00:00 2026 GMT")
    assert parsed == datetime(2026, 1, 1, tzinfo=timezone.utc)
