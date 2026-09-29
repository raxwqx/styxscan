import requests


def fetch(url, timeout=10):
    try:
        response = requests.get(
            url,
            timeout=timeout,
            allow_redirects=True,
            headers={
                "User-Agent": "StyxScan/0.1"
            },
        )

        headers = dict(response.headers)

        set_cookie_headers = []

        raw = getattr(
            response,
            "raw",
            None,
        )

        raw_headers = getattr(
            raw,
            "headers",
            None,
        )

        if raw_headers is not None:
            getlist = getattr(
                raw_headers,
                "getlist",
                None,
            )

            if getlist:
                set_cookie_headers = (
                    getlist("Set-Cookie")
                )

        if not set_cookie_headers:
            set_cookie = headers.get(
                "Set-Cookie"
            )

            if set_cookie:
                set_cookie_headers = [
                    set_cookie
                ]

        return {
            "status": response.status_code,
            "url": response.url,
            "headers": headers,
            "content": response.text,
            "set_cookie": set_cookie_headers,
            "server": response.headers.get(
                "Server"
            ),
            "powered_by": response.headers.get(
                "X-Powered-By"
            ),
            "history": [
                {
                    "status": item.status_code,
                    "url": item.url,
                }
                for item in response.history
            ],
        }

    except requests.RequestException as error:
        return {
            "error": str(error)
        }
