from rich.console import Console
from rich.panel import Panel
from rich.table import Table


console = Console()


def show(result):
    target = result.get("target", "")
    http = result.get("http", {})
    headers = result.get("headers", [])
    tls = result.get("tls", {})
    dns = result.get("dns", {})
    dns_security = result.get("dns_security", {})
    cookies = result.get("cookies", {})
    cors = result.get("cors", {})
    technology = result.get("technology", {})
    findings = result.get("findings", [])
    security_summary = result.get(
        "security_summary",
        {},
    )

    # ============================================================
    # HEADER
    # ============================================================

    console.print()

    console.print(
        Panel(
            "[bold cyan]STYXSCAN v0.1[/bold cyan]\n"
            "[dim]Security Research Toolkit[/dim]",
            title="[bold cyan]STYXSCAN[/bold cyan]",
            border_style="cyan",
        )
    )

    # ============================================================
    # TARGET INFORMATION
    # ============================================================

    target_table = Table(
        show_header=False,
        box=None,
        padding=(0, 2),
    )

    target_table.add_row(
        "[bold]Target[/bold]",
        target,
    )

    target_table.add_row(
        "[bold]Status[/bold]",
        str(http.get("status", "N/A")),
    )

    target_table.add_row(
        "[bold]Final URL[/bold]",
        http.get("url", "N/A"),
    )

    target_table.add_row(
        "[bold]Server[/bold]",
        http.get(
            "server"
        ) or "[dim]Not detected[/dim]",
    )

    if http.get("powered_by"):
        target_table.add_row(
            "[bold]Powered By[/bold]",
            http.get("powered_by"),
        )

    console.print(
        Panel(
            target_table,
            title="[bold]Target Information[/bold]",
            border_style="blue",
        )
    )

    # ============================================================
    # SECURITY OVERVIEW
    # ============================================================

    present_count = sum(
        1
        for header in headers
        if header.get("present")
    )

    dns_enabled = not dns_security.get(
        "skipped",
        False,
    )

    tls_enabled = not tls.get(
        "skipped",
        False,
    )

    dns_count = sum(
        1
        for values in dns.values()
        if values
    )

    dns_findings = dns_security.get(
        "findings",
        [],
    )

    cookie_list = cookies.get(
        "cookies",
        [],
    )

    cors_findings = cors.get(
        "findings",
        [],
    )

    overview = Table(
        title="Security Overview",
    )

    overview.add_column("Check")
    overview.add_column("Result")
    overview.add_column("Details")

    # ============================================================
    # SECURITY HEADERS
    # ============================================================

    header_missing = (
        len(headers) - present_count
    )

    if header_missing == 0:
        header_status = "[green]OK[/green]"
    else:
        header_status = "[yellow]REVIEW[/yellow]"

    overview.add_row(
        "Security Headers",
        header_status,
        f"{present_count}/{len(headers)} present",
    )

    # ============================================================
    # TLS
    # ============================================================

    if not tls_enabled:
        tls_status = "[dim]SKIP[/dim]"
        tls_detail = "Disabled"

    elif "error" in tls:
        tls_status = "[red]ERROR[/red]"
        tls_detail = tls.get(
            "error",
            "",
        )

    else:
        days_left = tls.get(
            "days_left"
        )

        if days_left is not None and days_left < 0:
            tls_status = "[red]EXPIRED[/red]"

        elif (
            days_left is not None
            and days_left <= 30
        ):
            tls_status = "[yellow]EXPIRING[/yellow]"

        else:
            tls_status = "[green]VALID[/green]"

        tls_detail = tls.get(
            "version",
            "Available",
        )

    overview.add_row(
        "TLS",
        tls_status,
        tls_detail,
    )

    # ============================================================
    # DNS RECORDS
    # ============================================================

    if not dns_enabled:
        overview.add_row(
            "DNS Records",
            "[dim]SKIP[/dim]",
            "Disabled",
        )

    else:
        overview.add_row(
            "DNS Records",
            "[green]OK[/green]",
            f"{dns_count}/{len(dns)} types found",
        )

    # ============================================================
    # DNS SECURITY
    # ============================================================

    if not dns_enabled:
        overview.add_row(
            "DNS Security",
            "[dim]SKIP[/dim]",
            "Disabled",
        )

    else:
        if dns_findings:
            dns_security_status = (
                "[yellow]REVIEW[/yellow]"
            )
        else:
            dns_security_status = (
                "[green]OK[/green]"
            )

        overview.add_row(
            "DNS Security",
            dns_security_status,
            f"{len(dns_findings)} finding(s)",
        )

    # ============================================================
    # COOKIES
    # ============================================================

    overview.add_row(
        "Cookies",
        "[green]OK[/green]",
        f"{len(cookie_list)} detected",
    )

    # ============================================================
    # CORS
    # ============================================================

    if cors_findings:
        cors_status = "[yellow]REVIEW[/yellow]"
    else:
        cors_status = "[green]OK[/green]"

    overview.add_row(
        "CORS",
        cors_status,
        f"{len(cors_findings)} finding(s)",
    )

    console.print()
    console.print(overview)

    # ============================================================
    # SECURITY SUMMARY
    # ============================================================

    summary_table = Table(
        title="Security Summary",
    )

    summary_table.add_column("Severity")
    summary_table.add_column(
        "Count",
        justify="right",
    )

    summary_styles = {
        "CRITICAL": "[bold red]CRITICAL[/bold red]",
        "HIGH": "[red]HIGH[/red]",
        "MEDIUM": "[yellow]MEDIUM[/yellow]",
        "LOW": "[cyan]LOW[/cyan]",
        "INFO": "[dim]INFO[/dim]",
    }

    for severity in [
        "CRITICAL",
        "HIGH",
        "MEDIUM",
        "LOW",
        "INFO",
    ]:
        summary_table.add_row(
            summary_styles[severity],
            str(
                security_summary.get(
                    severity,
                    0,
                )
            ),
        )

    summary_table.add_row(
        "[bold]TOTAL[/bold]",
        f"[bold]{security_summary.get('total', 0)}[/bold]",
    )

    console.print()
    console.print(summary_table)

    # ============================================================
    # HTTP INFORMATION
    # ============================================================

    response_headers = http.get(
        "headers",
        {},
    )

    redirect_history = http.get(
        "history",
        [],
    )

    http_table = Table(
        title="HTTP Information",
    )

    http_table.add_column("Property")
    http_table.add_column("Value")

    http_table.add_row(
        "Status",
        str(
            http.get(
                "status",
                "N/A",
            )
        ),
    )

    http_table.add_row(
        "Final URL",
        http.get(
            "url",
            "N/A",
        ),
    )

    http_table.add_row(
        "Server",
        http.get(
            "server"
        ) or "[dim]Not detected[/dim]",
    )

    http_table.add_row(
        "Powered By",
        http.get(
            "powered_by"
        ) or "[dim]Not detected[/dim]",
    )

    http_table.add_row(
        "Redirects",
        str(
            len(redirect_history)
        ),
    )

    http_table.add_row(
        "Response Headers",
        str(
            len(response_headers)
        ),
    )

    console.print()
    console.print(http_table)

    # ============================================================
    # REDIRECT HISTORY
    # ============================================================

    redirect_history = http.get(
        "history",
        [],
    )

    redirect_table = Table(
        title="Redirect History",
    )

    redirect_table.add_column("Step", justify="right")
    redirect_table.add_column("Status")
    redirect_table.add_column("URL")

    if redirect_history:
        for index, redirect in enumerate(
            redirect_history,
            start=1,
        ):
            status = redirect.get(
                "status",
                "N/A",
            )

            if status in (301, 308):
                status_display = (
                    f"[yellow]{status}[/yellow]"
                )

            elif status in (302, 303, 307):
                status_display = (
                    f"[cyan]{status}[/cyan]"
                )

            else:
                status_display = str(status)

            redirect_table.add_row(
                str(index),
                status_display,
                redirect.get(
                    "url",
                    "N/A",
                ),
            )
    else:
        redirect_table.add_row(
            "-",
            "[green]NONE[/green]",
            "No redirects detected",
        )

    console.print()
    console.print(redirect_table)

    # ============================================================
    # TECHNOLOGY DETECTION
    # ============================================================

    technologies = technology.get(
        "technologies",
        [],
    )

    tech_table = Table(
        title="Technology Detection",
    )

    tech_table.add_column("Technology")
    tech_table.add_column("Category")
    tech_table.add_column("Confidence")
    tech_table.add_column("Evidence")

    if technologies:
        for tech in technologies:
            confidence = tech.get(
                "confidence",
                "unknown",
            ).upper()

            if confidence == "HIGH":
                confidence_display = (
                    "[green]HIGH[/green]"
                )

            elif confidence == "MEDIUM":
                confidence_display = (
                    "[yellow]MEDIUM[/yellow]"
                )

            else:
                confidence_display = (
                    "[dim]LOW[/dim]"
                )

            tech_table.add_row(
                tech.get(
                    "name",
                    "Unknown",
                ),
                tech.get(
                    "category",
                    "Unknown",
                ),
                confidence_display,
                tech.get(
                    "evidence",
                    "",
                ),
            )

    else:
        tech_table.add_row(
            "[dim]None detected[/dim]",
            "-",
            "-",
            "-",
        )

    console.print()
    console.print(tech_table)

    # ============================================================
    # TLS DETAILS
    # ============================================================

    if tls_enabled and "error" not in tls:
        tls_table = Table(
            title="TLS Details",
        )

        tls_table.add_column("Property")
        tls_table.add_column("Value")

        tls_table.add_row(
            "Version",
            str(
                tls.get("version")
            ),
        )

        tls_table.add_row(
            "Cipher",
            str(
                tls.get("cipher")
            ),
        )

        tls_table.add_row(
            "Subject",
            str(
                tls.get("subject")
            ),
        )

        tls_table.add_row(
            "Issuer",
            str(
                tls.get("issuer")
            ),
        )

        tls_table.add_row(
            "Issued",
            str(
                tls.get("issued_at")
            ),
        )

        tls_table.add_row(
            "Expires",
            str(
                tls.get("expires_at")
            ),
        )

        days_left = tls.get(
            "days_left"
        )

        if days_left is not None:
            tls_table.add_row(
                "Days Left",
                str(days_left),
            )

        console.print()
        console.print(tls_table)

    # ============================================================
    # DNS RECORDS
    # ============================================================

    if dns_enabled:
        dns_table = Table(
            title="DNS Records",
        )

        dns_table.add_column("Type")
        dns_table.add_column("Records")

        for record_type, values in dns.items():
            if values:
                first = True

                for value in values:
                    dns_table.add_row(
                        record_type if first else "",
                        value,
                    )

                    first = False

        console.print()
        console.print(dns_table)

    # ============================================================
    # SECURITY FINDINGS
    # ============================================================

    findings_table = Table(
        title="Security Findings",
    )

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
                finding.get(
                    "severity",
                    "INFO",
                ),
                99,
            ),
        )

        for finding in sorted_findings:
            severity = finding.get(
                "severity",
                "INFO",
            )

            if severity == "CRITICAL":
                severity_display = (
                    "[bold red]CRITICAL[/bold red]"
                )

            elif severity == "HIGH":
                severity_display = (
                    "[red]HIGH[/red]"
                )

            elif severity == "MEDIUM":
                severity_display = (
                    "[yellow]MEDIUM[/yellow]"
                )

            elif severity == "LOW":
                severity_display = (
                    "[cyan]LOW[/cyan]"
                )

            else:
                severity_display = (
                    "[dim]INFO[/dim]"
                )

            findings_table.add_row(
                severity_display,
                finding.get(
                    "message",
                    "",
                ),
            )

    else:
        findings_table.add_row(
            "[green]OK[/green]",
            "No security findings",
        )

    console.print()
    console.print(findings_table)

    # ============================================================
    # FOOTER
    # ============================================================

    console.print()

    console.print(
        Panel(
            "[dim]"
            "StyxScan performs passive security analysis "
            "of publicly accessible information."
            "[/dim]",
            border_style="dim",
        )
    )

