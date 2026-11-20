"""Command-line interface for StyxScan."""

from __future__ import annotations

import argparse
import ipaddress
import json
import re
import sys
from urllib.parse import urlsplit, urlunsplit

from . import __version__
from .cookies import analyze as analyze_cookies
from .cors import analyze as analyze_cors
from .dns import analyze_security, resolve_with_warnings
from .findings import analyze_headers, analyze_tls, summarize
from .headers import analyze
from .html_reporter import generate
from .http import fetch
from .reporter import show
from .sanitize import sanitize
from .security_txt import discover as discover_security_txt
from .technology import analyze as analyze_technology
from .tls import inspect

MAX_TIMEOUT = 60.0
_HOST_LABEL_RE = re.compile(r"^[a-z0-9_-]+$")


def _validate_host(host: str) -> str:
    if not host:
        raise ValueError("target URL must include a hostname")

    try:
        ipaddress.ip_address(host)
        return host
    except ValueError:
        pass

    if not host.isascii():
        try:
            host = host.encode("idna").decode("ascii")
        except UnicodeError as error:
            raise ValueError(
                "target hostname contains an invalid internationalized name"
            ) from error

    host = host.rstrip(".").lower()
    if not host:
        raise ValueError("target URL must include a hostname")
    if len(host) > 253:
        raise ValueError("target hostname must be 253 characters or fewer")

    labels = host.split(".")
    if any(not label for label in labels):
        raise ValueError("target hostname contains an empty label")

    for label in labels:
        if len(label) > 63:
            raise ValueError(
                "target hostname contains a label longer than 63 characters"
            )
        if label.startswith("-") or label.endswith("-"):
            raise ValueError(
                "target hostname labels must not start or end with a hyphen"
            )
        if not _HOST_LABEL_RE.fullmatch(label):
            raise ValueError(
                "target hostname contains invalid characters"
            )

    return host


def normalize_url(target: str) -> str:
    """Validate a target and return a normalized HTTP(S) URL.

    Bare hosts and host/path values get an ``https://`` prefix. URLs with
    credentials, control characters, whitespace, non-HTTP schemes, invalid
    ports, or malformed hostnames are rejected.
    """

    if not isinstance(target, str):
        raise ValueError("target must be a URL or domain name")

    target = target.strip()
    if not target:
        raise ValueError("target URL or domain is required")

    if any(ord(character) < 32 or ord(character) == 127 for character in target):
        raise ValueError("target contains control characters")
    if any(character.isspace() for character in target):
        raise ValueError("target contains whitespace")
    if "\\" in target:
        raise ValueError("target contains an invalid backslash")

    if "://" not in target:
        target = "https://" + target

    parsed = urlsplit(target)
    scheme = parsed.scheme.lower()

    if scheme not in ("http", "https"):
        raise ValueError("target scheme must be http or https")
    if parsed.username or parsed.password:
        raise ValueError("target must not include credentials")

    try:
        port = parsed.port
    except ValueError as error:
        raise ValueError("target contains an invalid port") from error

    if port is not None and not 1 <= port <= 65535:
        raise ValueError("target port must be between 1 and 65535")

    host = _validate_host(parsed.hostname or "")

    if ":" in host:
        netloc = f"[{host}]"
    else:
        netloc = host

    if port is not None:
        netloc = f"{netloc}:{port}"

    return urlunsplit(
        (
            scheme,
            netloc,
            parsed.path,
            parsed.query,
            parsed.fragment,
        )
    )


def domain_from_url(url: str) -> str:
    """Return the ASCII hostname of *url* for DNS queries."""

    parsed = urlsplit(url)
    host = parsed.hostname
    if not host:
        raise ValueError("target URL must include a hostname")

    try:
        ipaddress.ip_address(host)
        return host
    except ValueError:
        pass

    if not host.isascii():
        try:
            host = host.encode("idna").decode("ascii")
        except UnicodeError as error:
            raise ValueError(
                "target hostname contains an invalid internationalized name"
            ) from error

    return host.rstrip(".").lower()


def _timeout(value: str) -> float:
    try:
        timeout = float(value)
    except ValueError as error:
        raise argparse.ArgumentTypeError("timeout must be a number") from error

    if not 0 < timeout <= MAX_TIMEOUT:
        raise argparse.ArgumentTypeError(
            f"timeout must be between 0 and {MAX_TIMEOUT:g} seconds"
        )
    return timeout


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="styxscan",
        description="StyxScan - Security Research Toolkit",
    )

    parser.add_argument("target", help="Target URL or domain")
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
        type=_timeout,
        default=10.0,
        help="HTTP, DNS, TLS, and security.txt timeout in seconds (default: 10)",
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
    parser.add_argument(
        "--no-security-txt",
        action="store_true",
        help="Disable security.txt discovery",
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"StyxScan {__version__}",
    )
    return parser


def _print_error(message: object) -> None:
    print(f"[!] {sanitize(message)}", file=sys.stderr)


def _http_error_result(target: str, error: object) -> dict:
    return {
        "tool": "styxscan",
        "version": __version__,
        "target": target,
        "error": sanitize(error),
    }


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    try:
        target = normalize_url(args.target)
        domain = domain_from_url(target)
    except ValueError as error:
        _print_error(error)
        return 2

    if not args.json:
        print(f"[+] Scanning {target}...")

    http_result = fetch(target, timeout=args.timeout)

    if "error" in http_result:
        if args.json:
            print(
                json.dumps(
                    _http_error_result(target, http_result["error"]),
                    indent=2,
                )
            )
        else:
            print(f"[!] HTTP error: {sanitize(http_result['error'])}")
        return 1

    header_result = analyze(http_result.get("headers", {}))

    if args.no_dns:
        dns_result = {}
        dns_security_result = {
            "spf": {"present": None, "records": []},
            "dmarc": {
                "present": None,
                "policy": None,
                "records": [],
            },
            "dnssec": {"present": None},
            "findings": [],
            "warnings": [],
            "skipped": True,
        }
    else:
        dns_result, dns_warnings = resolve_with_warnings(
            domain,
            timeout=args.timeout,
        )
        dns_security_result = analyze_security(
            domain,
            dns_result,
            timeout=args.timeout,
        )
        dns_security_result["warnings"] = (
            list(dns_security_result.get("warnings", []))
            + dns_warnings
        )

    scheme = urlsplit(target).scheme.lower()

    if args.no_tls:
        tls_result = {"skipped": True, "reason": "disabled"}
    elif scheme != "https":
        tls_result = {
            "skipped": True,
            "reason": "target scheme is not HTTPS",
        }
    else:
        tls_result = inspect(target, timeout=args.timeout)

    if args.no_security_txt:
        security_txt_result = {"skipped": True, "reason": "disabled"}
    else:
        security_txt_result = discover_security_txt(
            target,
            timeout=args.timeout,
        )

    findings = analyze_headers(header_result)

    cookie_result = analyze_cookies(http_result)
    findings.extend(cookie_result.get("findings", []))

    cors_result = analyze_cors(http_result.get("headers", {}))
    findings.extend(cors_result.get("findings", []))

    findings.extend(dns_security_result.get("findings", []))
    findings.extend(analyze_tls(tls_result))
    findings.extend(security_txt_result.get("findings", []))

    technology_result = analyze_technology(http_result)
    findings.extend(technology_result.get("findings", []))

    if http_result.get("scheme_downgrade"):
        findings.append(
            {
                "type": "http",
                "name": "HTTPS",
                "severity": "HIGH",
                "message": "The redirect chain downgrades from HTTPS to HTTP",
            }
        )

    security_summary = summarize(findings)

    result = {
        "tool": "styxscan",
        "version": __version__,
        "target": target,
        "http": http_result,
        "headers": header_result,
        "dns": dns_result,
        "dns_security": dns_security_result,
        "tls": tls_result,
        "cookies": cookie_result,
        "cors": cors_result,
        "security_txt": security_txt_result,
        "technology": technology_result,
        "findings": findings,
        "security_summary": security_summary,
    }

    exit_code = 0

    if args.html:
        try:
            generate(result, args.html)
            if args.json:
                print(f"[+] HTML report saved: {args.html}", file=sys.stderr)
            else:
                print(f"[+] HTML report saved: {args.html}")
        except OSError as error:
            _print_error(f"Could not save HTML report: {error}")
            exit_code = 1

    if args.json:
        print(json.dumps(result, indent=2))
    else:
        show(result)

    return exit_code


if __name__ == "__main__":
    raise SystemExit(main())
