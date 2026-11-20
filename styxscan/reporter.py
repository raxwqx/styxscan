"""Rich terminal rendering."""

from __future__ import annotations

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from . import __version__
from .sanitize import sanitize

console = Console()

SEVERITY_STYLES = {
    "CRITICAL": "[bold red]CRITICAL[/bold red]",
    "HIGH": "[red]HIGH[/red]",
    "MEDIUM": "[yellow]MEDIUM[/yellow]",
    "LOW": "[cyan]LOW[/cyan]",
    "INFO": "[dim]INFO[/dim]",
}


def _value(value: object, style: str | None = None) -> Text:
    return Text(sanitize(value), style=style)


def _present(value: object) -> str:
    return "yes" if bool(value) else "no"


def _tls_state(tls: dict) -> tuple[str, str]:
    if tls.get("skipped"):
        return "[dim]SKIP[/dim]", tls.get("reason") or "Disabled"

    if "error" in tls:
        return "[red]ERROR[/red]", tls.get("error", "")

    days_left = tls.get("days_left")
    if isinstance(days_left, (int, float)) and not isinstance(days_left, bool):
        if days_left < 0:
            return "[red]EXPIRED[/red]", "Certificate expired"
        if days_left <= 30:
            return "[yellow]EXPIRING[/yellow]", f"{days_left} day(s) left"

    if tls.get("verified") is False:
        return "[yellow]UNVERIFIED[/yellow]", "Certificate not verified"

    return "[green]VALID[/green]", tls.get("version") or "Available"


def _security_txt_state(security_txt: dict) -> tuple[str, str]:
    if security_txt.get("skipped"):
        return "[dim]SKIP[/dim]", security_txt.get("reason") or "Disabled"

    if not security_txt.get("found"):
        return "[yellow]MISSING[/yellow]", "No security.txt found"

    if security_txt.get("expired"):
        return "[red]EXPIRED[/red]", "security.txt has expired"
    if security_txt.get("valid"):
        return "[green]VALID[/green]", "Contact and expiry present"
    return "[yellow]REVIEW[/yellow]", "Incomplete security.txt"


def _redirect_table(http: dict) -> Table:
    table = Table(title="Redirect History")
    table.add_column("Step", justify="right")
    table.add_column("Status")
    table.add_column("URL")

    history = http.get("history", []) or []
    if not history:
        table.add_row("-", "[green]NONE[/green]", "No redirects detected")
        return table

    for index, redirect in enumerate(history, start=1):
        status = redirect.get("status", "N/A")
        if status in (301, 308):
            status_display = f"[yellow]{status}[/yellow]"
        elif status in (302, 303, 307):
            status_display = f"[cyan]{status}[/cyan]"
        else:
            status_display = str(status)

        table.add_row(
            str(index),
            status_display,
            _value(redirect.get("url", "N/A")),
        )

    return table


def show(result: dict) -> None:
    target = result.get("target", "")
    http = result.get("http", {}) or {}
    headers = result.get("headers", []) or []
    tls = result.get("tls", {}) or {}
    dns = result.get("dns", {}) or {}
    dns_security = result.get("dns_security", {}) or {}
    security_txt = result.get("security_txt", {}) or {}
    cookies = result.get("cookies", {}) or {}
    cors = result.get("cors", {}) or {}
    technology = result.get("technology", {}) or {}
    findings = result.get("findings", []) or []
    security_summary = result.get("security_summary", {}) or {}

    console.print()
    console.print(
        Panel(
            f"[bold cyan]STYXSCAN v{__version__}[/bold cyan]\n"
            "[dim]Security Research Toolkit[/dim]",
            title="[bold cyan]STYXSCAN[/bold cyan]",
            border_style="cyan",
        )
    )

    target_table = Table(show_header=False, box=None, padding=(0, 2))
    target_table.add_row("[bold]Target[/bold]", _value(target))
    target_table.add_row(
        "[bold]Status[/bold]",
        _value(http.get("status", "N/A")),
    )
    target_table.add_row(
        "[bold]Final URL[/bold]",
        _value(http.get("url", "N/A")),
    )
    target_table.add_row(
        "[bold]Server[/bold]",
        _value(http.get("server") or "Not detected"),
    )
    if http.get("powered_by"):
        target_table.add_row(
            "[bold]Powered By[/bold]",
            _value(http.get("powered_by")),
        )
    if http.get("content_truncated"):
        target_table.add_row(
            "[bold]Body[/bold]",
            _value("truncated at the configured limit"),
        )

    console.print(
        Panel(
            target_table,
            title="[bold]Target Information[/bold]",
            border_style="blue",
        )
    )

    present_count = sum(
        1 for header in headers if header.get("present")
    )
    header_missing = len(headers) - present_count
    header_status = (
        "[green]OK[/green]"
        if header_missing == 0
        else "[yellow]REVIEW[/yellow]"
    )

    dns_enabled = not dns_security.get("skipped", False)
    tls_enabled = not tls.get("skipped", False)
    dns_count = sum(1 for values in dns.values() if values)
    dns_findings = dns_security.get("findings", []) or []
    cookie_list = cookies.get("cookies", []) or []
    cookie_findings = cookies.get("findings", []) or []
    cors_findings = cors.get("findings", []) or []

    overview = Table(title="Security Overview")
    overview.add_column("Check")
    overview.add_column("Result")
    overview.add_column("Details")

    overview.add_row(
        "Security Headers",
        header_status,
        f"{present_count}/{len(headers)} present",
    )

    tls_status, tls_detail = _tls_state(tls)
    overview.add_row("TLS", tls_status, _value(tls_detail))

    if not dns_enabled:
        overview.add_row("DNS Records", "[dim]SKIP[/dim]", "Disabled")
        overview.add_row("DNS Security", "[dim]SKIP[/dim]", "Disabled")
    else:
        overview.add_row(
            "DNS Records",
            "[green]OK[/green]",
            f"{dns_count}/{len(dns)} types found",
        )
        overview.add_row(
            "DNS Security",
            "[yellow]REVIEW[/yellow]"
            if dns_findings
            else "[green]OK[/green]",
            f"{len(dns_findings)} finding(s)",
        )

    security_txt_status, security_txt_detail = _security_txt_state(
        security_txt
    )
    overview.add_row(
        "security.txt",
        security_txt_status,
        _value(security_txt_detail),
    )

    overview.add_row(
        "Cookies",
        "[yellow]REVIEW[/yellow]"
        if cookie_findings
        else "[green]OK[/green]",
        f"{len(cookie_list)} detected, {len(cookie_findings)} finding(s)",
    )

    overview.add_row(
        "CORS",
        "[yellow]REVIEW[/yellow]"
        if cors_findings
        else "[green]OK[/green]",
        f"{len(cors_findings)} finding(s)",
    )

    console.print()
    console.print(overview)

    summary_table = Table(title="Security Summary")
    summary_table.add_column("Severity")
    summary_table.add_column("Count", justify="right")

    for severity in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"):
        summary_table.add_row(
            SEVERITY_STYLES[severity],
            str(security_summary.get(severity, 0)),
        )

    summary_table.add_row(
        "[bold]TOTAL[/bold]",
        f"[bold]{security_summary.get('total', 0)}[/bold]",
    )

    console.print()
    console.print(summary_table)

    http_table = Table(title="HTTP Information")
    http_table.add_column("Property")
    http_table.add_column("Value")
    http_table.add_row("Status", _value(http.get("status", "N/A")))
    http_table.add_row("Final URL", _value(http.get("url", "N/A")))
    http_table.add_row(
        "Server",
        _value(http.get("server") or "Not detected"),
    )
    http_table.add_row(
        "Powered By",
        _value(http.get("powered_by") or "Not detected"),
    )
    http_table.add_row(
        "Content Type",
        _value(http.get("content_type") or "Not provided"),
    )
    http_table.add_row(
        "Redirects",
        str(len(http.get("history", []) or [])),
    )
    http_table.add_row(
        "Response Headers",
        str(len(http.get("headers", {}) or {})),
    )
    http_table.add_row(
        "HTTPS Downgrade",
        _value(
            "yes" if http.get("scheme_downgrade") else "no",
            style="red" if http.get("scheme_downgrade") else None,
        ),
    )

    console.print()
    console.print(http_table)

    console.print()
    console.print(_redirect_table(http))

    headers_table = Table(title="Security Headers")
    headers_table.add_column("Header")
    headers_table.add_column("Status")
    headers_table.add_column("Value")

    for header in headers:
        if header.get("present"):
            status = Text("present", style="green")
            value = _value(header.get("value", ""))
        else:
            status = Text("missing", style="yellow")
            value = _value("Not sent")

        headers_table.add_row(
            _value(header.get("header", header.get("name", ""))),
            status,
            value,
        )

    console.print()
    console.print(headers_table)

    if tls_enabled:
        tls_table = Table(title="TLS Details")
        tls_table.add_column("Property")
        tls_table.add_column("Value")

        if "error" in tls:
            tls_table.add_row("Status", Text("connection failed", style="red"))
            tls_table.add_row("Error", _value(tls.get("error", "")))
        else:
            tls_table.add_row(
                "Verified",
                Text("yes", style="green")
                if tls.get("verified")
                else Text("no", style="yellow"),
            )
            tls_table.add_row("Version", _value(tls.get("version") or "N/A"))
            tls_table.add_row("Cipher", _value(tls.get("cipher") or "N/A"))
            tls_table.add_row("Subject", _value(tls.get("subject") or "N/A"))
            tls_table.add_row("Issuer", _value(tls.get("issuer") or "N/A"))
            tls_table.add_row("Serial", _value(tls.get("serial") or "N/A"))
            tls_table.add_row("Issued", _value(tls.get("issued_at") or "N/A"))
            tls_table.add_row("Expires", _value(tls.get("expires_at") or "N/A"))

            days_left = tls.get("days_left")
            tls_table.add_row(
                "Days Left",
                _value("N/A" if days_left is None else days_left),
            )
            expired = tls.get("expired")
            tls_table.add_row(
                "Expired",
                _value("N/A" if expired is None else _present(expired)),
            )

            san = tls.get("san") or []
            tls_table.add_row(
                "SAN",
                _value(", ".join(san) if san else "N/A"),
            )

            if tls.get("verification_error"):
                tls_table.add_row(
                    "Verification",
                    _value(tls["verification_error"], style="yellow"),
                )

        console.print()
        console.print(tls_table)

    if dns_enabled:
        dns_table = Table(title="DNS Records")
        dns_table.add_column("Type")
        dns_table.add_column("Records")

        for record_type, values in dns.items():
            if values:
                for index, value in enumerate(values):
                    dns_table.add_row(
                        record_type if index == 0 else "",
                        _value(value),
                    )
            else:
                dns_table.add_row(record_type, Text("-", style="dim"))

        console.print()
        console.print(dns_table)

        dns_security_table = Table(title="DNS Security")
        dns_security_table.add_column("Check")
        dns_security_table.add_column("Status")
        dns_security_table.add_column("Details")

        spf = dns_security.get("spf", {}) or {}
        dmarc = dns_security.get("dmarc", {}) or {}
        dnssec = dns_security.get("dnssec", {}) or {}

        dns_security_table.add_row(
            "SPF",
            Text("present", style="green")
            if spf.get("present")
            else Text("missing", style="yellow"),
            _value(
                "; ".join(spf.get("records", []) or [])
                if spf.get("records")
                else "No SPF record"
            ),
        )

        dmarc_detail = "No DMARC record"
        if dmarc.get("present"):
            dmarc_detail = f"policy={dmarc.get('policy') or 'not set'}"
        dns_security_table.add_row(
            "DMARC",
            Text("present", style="green")
            if dmarc.get("present")
            else Text("missing", style="yellow"),
            _value(dmarc_detail),
        )

        dns_security_table.add_row(
            "DNSSEC",
            Text("present", style="green")
            if dnssec.get("present")
            else Text("not detected", style="yellow"),
            _value(
                "DNSKEY record found"
                if dnssec.get("present")
                else "No DNSKEY record found"
            ),
        )

        console.print()
        console.print(dns_security_table)

        warnings = dns_security.get("warnings", []) or []
        if warnings:
            console.print()
            console.print(
                Panel(
                    Text(
                        "\n".join(
                            f"! {sanitize(item)}" for item in warnings
                        )
                    ),
                    title="DNS Warnings",
                    border_style="yellow",
                )
            )

    if not security_txt.get("skipped"):
        security_txt_table = Table(title="security.txt")
        security_txt_table.add_column("Property")
        security_txt_table.add_column("Value")

        security_txt_table.add_row(
            "Found",
            Text("yes", style="green")
            if security_txt.get("found")
            else Text("no", style="yellow"),
        )
        security_txt_table.add_row(
            "URL",
            _value(security_txt.get("url") or "N/A"),
        )
        security_txt_table.add_row(
            "Status",
            _value(
                security_txt.get("status")
                if security_txt.get("status") is not None
                else "N/A"
            ),
        )
        security_txt_table.add_row(
            "Valid",
            _value(_present(security_txt.get("valid"))),
        )
        security_txt_table.add_row(
            "Expires",
            _value(security_txt.get("expires_at") or "N/A"),
        )

        contacts = security_txt.get("contacts", []) or []
        security_txt_table.add_row(
            "Contacts",
            _value(", ".join(contacts) if contacts else "N/A"),
        )

        fields = security_txt.get("fields", {}) or {}
        for field in ("policy", "canonical", "preferred-languages"):
            values = fields.get(field, []) or []
            if values:
                security_txt_table.add_row(
                    field.replace("-", " ").title(),
                    _value(", ".join(values)),
                )

        if security_txt.get("error"):
            security_txt_table.add_row(
                "Error",
                _value(security_txt["error"], style="yellow"),
            )

        console.print()
        console.print(security_txt_table)

        warnings = security_txt.get("warnings", []) or []
        if warnings:
            console.print()
            console.print(
                Panel(
                    Text(
                        "\n".join(
                            f"! {sanitize(item)}" for item in warnings
                        )
                    ),
                    title="security.txt Warnings",
                    border_style="yellow",
                )
            )

    cookies_table = Table(title="Cookies")
    cookies_table.add_column("Name")
    cookies_table.add_column("Secure")
    cookies_table.add_column("HttpOnly")
    cookies_table.add_column("SameSite")

    if cookie_list:
        for cookie in cookie_list:
            cookies_table.add_row(
                _value(cookie.get("name", "")),
                _value(_present(cookie.get("secure"))),
                _value(_present(cookie.get("httponly"))),
                _value(cookie.get("samesite") or "not set"),
            )
    else:
        cookies_table.add_row(
            Text("No cookies detected", style="dim"),
            "-",
            "-",
            "-",
        )

    console.print()
    console.print(cookies_table)

    cors_table = Table(title="CORS")
    cors_table.add_column("Header")
    cors_table.add_column("Value")

    cors_headers = cors.get("headers", {}) or {}
    if any(value is not None for value in cors_headers.values()):
        for field, value in cors_headers.items():
            cors_table.add_row(
                _value(field),
                _value(value if value is not None else "Not sent"),
            )
    else:
        cors_table.add_row(
            Text("No CORS headers detected", style="dim"),
            "-",
        )

    console.print()
    console.print(cors_table)

    technologies = technology.get("technologies", []) or []
    tech_table = Table(title="Technology Detection")
    tech_table.add_column("Technology")
    tech_table.add_column("Category")
    tech_table.add_column("Confidence")
    tech_table.add_column("Evidence")

    if technologies:
        for tech in technologies:
            confidence = str(
                tech.get("confidence", "unknown")
            ).upper()

            if confidence == "HIGH":
                confidence_display = Text("HIGH", style="green")
            elif confidence == "MEDIUM":
                confidence_display = Text("MEDIUM", style="yellow")
            else:
                confidence_display = Text("LOW", style="dim")

            tech_table.add_row(
                _value(tech.get("name", "Unknown")),
                _value(tech.get("category", "Unknown")),
                confidence_display,
                _value(tech.get("evidence", "")),
            )
    else:
        tech_table.add_row(
            Text("None detected", style="dim"),
            "-",
            "-",
            "-",
        )

    console.print()
    console.print(tech_table)

    findings_table = Table(title="Security Findings")
    findings_table.add_column("Severity")
    findings_table.add_column("Finding")

    if findings:
        severity_order = {
            "CRITICAL": 0,
            "HIGH": 1,
            "MEDIUM": 2,
            "LOW": 3,
            "INFO": 4,
        }
        sorted_findings = sorted(
            findings,
            key=lambda finding: severity_order.get(
                finding.get("severity", "INFO"),
                99,
            ),
        )

        for finding in sorted_findings:
            severity = finding.get("severity", "INFO")
            severity_display = SEVERITY_STYLES.get(
                severity,
                "[dim]INFO[/dim]",
            )
            findings_table.add_row(
                severity_display,
                _value(finding.get("message", "")),
            )
    else:
        findings_table.add_row(
            Text("OK", style="green"),
            "No security findings",
        )

    console.print()
    console.print(findings_table)

    console.print()
    console.print(
        Panel(
            "[dim]StyxScan performs passive security analysis "
            "of publicly accessible information.[/dim]",
            border_style="dim",
        )
    )
