import argparse
import json
from urllib.parse import urlparse

from styxscan.http import fetch
from styxscan.headers import analyze
from styxscan.dns import resolve, analyze_security
from styxscan.tls import inspect
from styxscan.findings import (
    analyze_headers,
    summarize,
)
from styxscan.cookies import analyze as analyze_cookies
from styxscan.cors import analyze as analyze_cors
from styxscan.technology import analyze as analyze_technology
from styxscan.html_reporter import generate
from styxscan.reporter import show


def normalize_url(target):
    if not target.startswith(
        ("http://", "https://")
    ):
        target = "https://" + target

    return target


def main():
    parser = argparse.ArgumentParser(
        description="StyxScan - Security Research Toolkit"
    )

    parser.add_argument(
        "target",
        help="Target URL or domain",
    )

    parser.add_argument(
        "--json",
        action="store_true",
        help="Output results as JSON",
    )

    parser.add_argument(
        "--html",
        metavar="FILE",
        help="Save results as an HTML report",
    )

    parser.add_argument(
        "--timeout",
        type=int,
        default=10,
        help="HTTP request timeout in seconds",
    )

    parser.add_argument(
        "--no-dns",
        action="store_true",
        help="Disable DNS analysis",
    )

    parser.add_argument(
        "--no-tls",
        action="store_true",
        help="Disable TLS analysis",
    )

    args = parser.parse_args()

    if args.timeout <= 0:
        parser.error(
            "--timeout must be greater than 0"
        )

    target = normalize_url(args.target)

    parsed = urlparse(target)
    domain = parsed.hostname

    if not args.json:
        print(
            f"[+] Scanning {target}..."
        )

    http_result = fetch(
        target,
        timeout=args.timeout,
    )

    if "error" in http_result:
        if args.json:
            print(
                json.dumps(
                    {
                        "target": target,
                        "error": http_result["error"],
                    },
                    indent=2,
                )
            )
        else:
            print(
                f"[!] HTTP error: "
                f"{http_result['error']}"
            )

        return

    header_result = analyze(
        http_result.get(
            "headers",
            {},
        )
    )

    if args.no_dns:
        dns_result = {}

        dns_security_result = {
            "spf": {
                "present": None,
                "records": [],
            },
            "dmarc": {
                "present": None,
                "records": [],
            },
            "dnssec": {
                "present": None,
            },
            "findings": [],
            "skipped": True,
        }

    else:
        dns_result = resolve(
            domain
        )

        dns_security_result = analyze_security(
            domain,
            dns_result,
        )

    if args.no_tls:
        tls_result = {
            "skipped": True,
        }

    else:
        tls_result = inspect(
            target
        )

    findings = analyze_headers(
        header_result
    )

    cookie_result = analyze_cookies(
        http_result
    )

    findings.extend(
        cookie_result.get(
            "findings",
            [],
        )
    )

    cors_result = analyze_cors(
        http_result.get(
            "headers",
            {},
        )
    )

    findings.extend(
        cors_result.get(
            "findings",
            [],
        )
    )

    findings.extend(
        dns_security_result.get(
            "findings",
            [],
        )
    )

    technology_result = analyze_technology(
        http_result
    )

    findings.extend(
        technology_result.get(
            "findings",
            [],
        )
    )

    security_summary = summarize(
        findings
    )

    result = {
        "target": target,
        "http": http_result,
        "headers": header_result,
        "dns": dns_result,
        "dns_security": dns_security_result,
        "tls": tls_result,
        "cookies": cookie_result,
        "cors": cors_result,
        "technology": technology_result,
        "findings": findings,
        "security_summary": security_summary,
    }

    if args.json:
        print(
            json.dumps(
                result,
                indent=2,
            )
        )
        return

    if args.html:
        try:
            generate(
                result,
                args.html,
            )

            print(
                f"[+] HTML report saved: "
                f"{args.html}"
            )

        except OSError as error:
            print(
                f"[!] Could not save HTML report: "
                f"{error}"
            )

    show(result)


if __name__ == "__main__":
    main()
