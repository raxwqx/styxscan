from datetime import datetime, timezone

from styxscan import tls


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

    class FakeContext:
        def wrap_socket(
            self,
            sock,
            server_hostname,
        ):
            return FakeTLS()

    result = tls.inspect(
        "https://example.com"
    )

    assert result["version"] == "TLSv1.3"
    assert result["cipher"] == "TLS_AES_256_GCM_SHA384"
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

    result = tls.inspect(
        "https://example.com"
    )

    assert "error" in result
    assert "connection failed" in result["error"]
