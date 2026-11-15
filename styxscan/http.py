import requests

MAX_RESPONSE_BYTES = 1024 * 1024
_CHUNK_SIZE = 64 * 1024


def fetch(url, timeout=10):
    response = None
    try:
        response = requests.get(
            url,
            timeout=timeout,
            allow_redirects=True,
            stream=True,
            headers={"User-Agent": "StyxScan/5.0.0"},
        )
        headers = dict(response.headers)
        set_cookie_headers = []
        raw_headers = getattr(getattr(response, "raw", None), "headers", None)
        getlist = getattr(raw_headers, "getlist", None)
        if getlist:
            set_cookie_headers = getlist("Set-Cookie")
        if not set_cookie_headers and headers.get("Set-Cookie"):
            set_cookie_headers = [headers["Set-Cookie"]]

        encoding = getattr(response, "encoding", None) or "utf-8"
        iterator = getattr(response, "iter_content", None)
        if callable(iterator):
            body = bytearray()
            truncated = False
            for chunk in iterator(chunk_size=_CHUNK_SIZE):
                if not chunk:
                    continue
                available = MAX_RESPONSE_BYTES - len(body)
                if len(chunk) > available:
                    body.extend(chunk[:available])
                    truncated = True
                    break
                body.extend(chunk)
            content = bytes(body).decode(encoding, errors="replace")
        else:
            # Keep lightweight response doubles and compatible adapters usable.
            raw_body = str(getattr(response, "text", "")).encode(encoding, errors="replace")
            truncated = len(raw_body) > MAX_RESPONSE_BYTES
            content = raw_body[:MAX_RESPONSE_BYTES].decode(encoding, errors="replace")
            body = raw_body[:MAX_RESPONSE_BYTES]

        return {
            "status": response.status_code,
            "url": response.url,
            "headers": headers,
            "content": content,
            "content_bytes": len(body),
            "content_truncated": truncated,
            "set_cookie": set_cookie_headers,
            "server": headers.get("Server"),
            "powered_by": headers.get("X-Powered-By"),
            "history": [
                {"status": item.status_code, "url": item.url}
                for item in response.history
            ],
        }
    except requests.RequestException as error:
        return {"error": str(error)}
    finally:
        close = getattr(response, "close", None)
        if callable(close):
            close()
