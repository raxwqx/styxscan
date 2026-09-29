#!/usr/bin/env python3

import sys
import requests


SECURITY_HEADERS = [
    "Strict-Transport-Security",
    "Content-Security-Policy",
    "X-Content-Type-Options",
    "X-Frame-Options",
    "Referrer-Policy",
]


def scan(url):
    print()
    print("================================")
    print("        STYXSCAN v0.1")
    print("================================")
    print()
    print(f"Target: {url}")
    print()

    try:
        response = requests.get(
            url,
            timeout=10,
            allow_redirects=True,
        )
    except requests.RequestException as error:
        print(f"[!] Connection error: {error}")
        return

    print(f"[+] Status: {response.status_code}")
    print(f"[+] Final URL: {response.url}")
    print()

    print("Security Headers")
    print("----------------")

    for header in SECURITY_HEADERS:
        if header in response.headers:
            print(f"[+] {header}")
        else:
            print(f"[-] {header} missing")

    print()


def main():
    if len(sys.argv) != 2:
        print("Usage: python3 styxscan.py <URL>")
        sys.exit(1)

    url = sys.argv[1]

    if not url.startswith(("http://", "https://")):
        url = "https://" + url

    scan(url)


if __name__ == "__main__":
    main()
