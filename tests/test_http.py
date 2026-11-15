import requests

from styxscan.http import fetch
from styxscan.http import MAX_RESPONSE_BYTES


def test_fetch_success(monkeypatch):
    class FakeResponse:
        status_code = 200
        url = "https://example.com/"
        headers = {
            "Server": "test-server",
            "X-Powered-By": "test-runtime",
        }
        history = []
        text = "<html><body>StyxScan test</body></html>"

    def fake_get(*args, **kwargs):
        return FakeResponse()

    monkeypatch.setattr(
        requests,
        "get",
        fake_get,
    )

    result = fetch(
        "https://example.com"
    )

    assert result["status"] == 200
    assert result["url"] == "https://example.com/"
    assert result["headers"]["Server"] == "test-server"
    assert result["headers"]["X-Powered-By"] == "test-runtime"
    assert result["content"] == (
        "<html><body>StyxScan test</body></html>"
    )


def test_fetch_redirect_history(monkeypatch):
    class FakeHistory:
        status_code = 301
        url = "http://example.com"

    class FakeResponse:
        status_code = 200
        url = "https://example.com/"
        headers = {
            "Server": "nginx"
        }
        history = []
        text = "<html><body>Redirected</body></html>"

    def fake_get(*args, **kwargs):
        response = FakeResponse()

        response.history = [
            FakeHistory()
        ]

        return response

    monkeypatch.setattr(
        requests,
        "get",
        fake_get,
    )

    result = fetch(
        "http://example.com"
    )

    assert result["status"] == 200
    assert result["url"] == "https://example.com/"
    assert result["content"] == (
        "<html><body>Redirected</body></html>"
    )

    assert result["history"] == [
        {
            "status": 301,
            "url": "http://example.com",
        }
    ]


def test_fetch_request_exception(monkeypatch):
    def fake_get(*args, **kwargs):
        raise requests.RequestException(
            "Connection failed"
        )

    monkeypatch.setattr(
        requests,
        "get",
        fake_get,
    )

    result = fetch(
        "https://example.com"
    )

    assert "error" in result
    assert result["error"] == "Connection failed"


def test_fetch_timeout(monkeypatch):
    captured = {}

    class FakeResponse:
        status_code = 200
        url = "https://example.com/"
        headers = {}
        history = []
        text = "<html></html>"

    def fake_get(*args, **kwargs):
        captured.update(kwargs)
        return FakeResponse()

    monkeypatch.setattr(
        requests,
        "get",
        fake_get,
    )

    fetch(
        "https://example.com",
        timeout=25,
    )

    assert captured["timeout"] == 25


def test_fetch_caps_streamed_body_and_closes_response(monkeypatch):
    class FakeResponse:
        status_code = 200
        url = "https://example.com/"
        headers = {}
        history = []
        encoding = "utf-8"
        closed = False

        def iter_content(self, chunk_size):
            assert chunk_size > 0
            yield b"x" * (MAX_RESPONSE_BYTES + 17)

        def close(self):
            self.closed = True

    response = FakeResponse()
    monkeypatch.setattr(requests, "get", lambda *args, **kwargs: response)

    result = fetch("https://example.com")

    assert result["content_bytes"] == MAX_RESPONSE_BYTES
    assert len(result["content"].encode("utf-8")) == MAX_RESPONSE_BYTES
    assert result["content_truncated"] is True
    assert response.closed is True


def test_fetch_multiple_set_cookie_headers(
    monkeypatch
):
    class FakeRawHeaders:
        def getlist(self, name):
            if name == "Set-Cookie":
                return [
                    "session=abc; Secure; HttpOnly",
                    "csrf=xyz; Secure; HttpOnly",
                ]

            return []

    class FakeRaw:
        headers = FakeRawHeaders()

    class FakeResponse:
        status_code = 200

        url = "https://example.com/"

        headers = {
            "Server": "test-server"
        }

        history = []

        raw = FakeRaw()

        text = "<html><body>Cookies</body></html>"

    def fake_get(*args, **kwargs):
        return FakeResponse()

    monkeypatch.setattr(
        requests,
        "get",
        fake_get,
    )

    result = fetch(
        "https://example.com"
    )

    assert result["set_cookie"] == [
        "session=abc; Secure; HttpOnly",
        "csrf=xyz; Secure; HttpOnly",
    ]

    assert result["content"] == (
        "<html><body>Cookies</body></html>"
    )
def test_fetch_redirect_history_multiple(monkeypatch):
    class FakeHistoryOne:
        status_code = 301
        url = "http://example.com"

    class FakeHistoryTwo:
        status_code = 302
        url = "http://www.example.com"

    class FakeResponse:
        status_code = 200
        url = "https://example.com/"
        headers = {
            "Server": "cloudflare"
        }
        history = [
            FakeHistoryOne(),
            FakeHistoryTwo(),
        ]
        text = "<html></html>"

    def fake_get(*args, **kwargs):
        return FakeResponse()

    monkeypatch.setattr(
        requests,
        "get",
        fake_get,
    )

    result = fetch(
        "http://example.com"
    )

    assert result["history"] == [
        {
            "status": 301,
            "url": "http://example.com",
        },
        {
            "status": 302,
            "url": "http://www.example.com",
        },
    ]

    assert result["status"] == 200
    assert result["url"] == "https://example.com/"
