"""HTTP fetching with bounded response handling."""

from __future__ import annotations

from urllib.parse import urlsplit

import requests

from . import USER_AGENT

DEFAULT_MAX_BODY = 512 * 1024


def _read_body(response, max_bytes: int) -> tuple[str, bool]:
    """Read at most *max_bytes* of the response body.

    ``requests`` responses are streamed so a very large page cannot exhaust
    memory. Test doubles and unusual response objects that do not expose
    ``iter_content`` fall back to ``response.text``.
    """

    iter_content = getattr(response, "iter_content", None)
    if callable(iter_content):
        chunks: list[bytes] = []
        total = 0
        truncated = False

        for chunk in iter_content(chunk_size=8192):
            if not chunk:
                continue

            remaining = max_bytes - total
            if remaining <= 0:
                truncated = True
                break

            if len(chunk) > remaining:
                chunks.append(chunk[:remaining])
                total += remaining
                truncated = True
                break

            chunks.append(chunk)
            total += len(chunk)

        raw = b"".join(chunks)
        encoding = getattr(response, "encoding", None) or "utf-8"
        try:
            text = raw.decode(encoding, errors="replace")
        except LookupError:
            text = raw.decode("utf-8", errors="replace")
        return text, truncated

    text = getattr(response, "text", "") or ""
    if len(text) > max_bytes:
        return text[:max_bytes], True
    return text, False


def _header(headers, name: str):
    if headers is None:
        return None

    getter = getattr(headers, "get", None)
    if getter is not None:
        value = getter(name)
        if value is not None:
            return value

    for key, value in headers.items():
        if key.lower() == name.lower():
            return value
    return None


def _set_cookie_headers(response, headers) -> list[str]:
    raw = getattr(response, "raw", None)
    raw_headers = getattr(raw, "headers", None)
    getlist = getattr(raw_headers, "getlist", None)

    if getlist:
        values = getlist("Set-Cookie")
        if values:
            return list(values)

    value = _header(headers, "Set-Cookie")
    return [value] if value else []


def fetch(
    url: str,
    timeout: float = 10,
    max_body: int = DEFAULT_MAX_BODY,
) -> dict:
    """Fetch *url* and return a normalized result dictionary.

    Redirects are followed, the body is bounded to *max_body* bytes, and
    request failures are returned as ``{"error": ...}`` instead of raising.
    """

    try:
        response = requests.get(
            url,
            timeout=timeout,
            allow_redirects=True,
            stream=True,
            headers={"User-Agent": USER_AGENT},
        )
    except requests.RequestException as error:
        return {"error": str(error)}
    except ValueError as error:
        return {"error": str(error)}

    try:
        headers = dict(response.headers)
        content, content_truncated = _read_body(response, max_body)
        history = [
            {
                "status": item.status_code,
                "url": item.url,
            }
            for item in response.history
        ]
        final_url = response.url

        scheme_downgrade = False
        initial_scheme = urlsplit(url).scheme.lower()
        if initial_scheme == "https":
            for item in history:
                if urlsplit(item["url"]).scheme.lower() == "http":
                    scheme_downgrade = True
            if urlsplit(final_url).scheme.lower() == "http":
                scheme_downgrade = True

        return {
            "status": response.status_code,
            "url": final_url,
            "headers": headers,
            "content": content,
            "content_truncated": content_truncated,
            "content_type": _header(headers, "Content-Type"),
            "set_cookie": _set_cookie_headers(response, headers),
            "server": _header(headers, "Server"),
            "powered_by": _header(headers, "X-Powered-By"),
            "history": history,
            "scheme_downgrade": scheme_downgrade,
        }
    except requests.RequestException as error:
        return {"error": str(error)}
    finally:
        close = getattr(response, "close", None)
        if callable(close):
            close()
