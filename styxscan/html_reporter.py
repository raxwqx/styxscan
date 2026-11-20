"""HTML report generation."""

from __future__ import annotations

from html import escape

from . import __version__
from .sanitize import sanitize

SEVERITIES = ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO")


def _e(value: object) -> str:
    return escape(sanitize(value))


def _yes_no(value: object) -> str:
    return "yes" if bool(value) else "no"


def _table(headers: list[str], rows: list[list[str]]) -> str:
    header_html = "".join(f"<th>{_e(header)}</th>" for header in headers)
    body_html = "".join(
        "<tr>" + "".join(f"<td>{cell}</td>" for cell in row) + "</tr>"
        for row in rows
    )
    return (
        "<table><thead><tr>"
        f"{header_html}"
        "</tr></thead><tbody>"
        f"{body_html}"
        "</tbody></table>"
    )


def _tls_status(tls: dict) -> str:
    if tls.get("skipped"):
        return "SKIPPED"
    if "error" in tls:
        return "ERROR"
    days_left = tls.get("days_left")
    if isinstance(days_left, (int, float)) and not isinstance(days_left, bool):
        if days_left < 0:
            return "EXPIRED"
    if tls.get("verified") is False:
        return "UNVERIFIED"
    if isinstance(days_left, (int, float)) and not isinstance(days_left, bool):
        if days_left <= 30:
            return "EXPIRING SOON"
    return "VALID"


def _security_txt_status(security_txt: dict) -> str:
    if security_txt.get("skipped"):
        return "SKIPPED"
    if not security_txt.get("found"):
        return "MISSING"
    if security_txt.get("expired"):
        return "EXPIRED"
    if security_txt.get("valid"):
        return "VALID"
    return "REVIEW"


def generate(result: dict, output_file: str) -> None:
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

    present_headers = sum(
        1 for header in headers if header.get("present")
    )

    finding_rows = []
    for finding in findings:
        severity = str(finding.get("severity", "INFO")).upper()
        severity_class = (
            severity.lower() if severity in SEVERITIES else "info"
        )
        finding_rows.append(
            [
                f'<span class="severity {severity_class}">{_e(severity)}</span>',
                _e(finding.get("message", "")),
            ]
        )

    if not finding_rows:
        finding_rows = [['<span class="ok">OK</span>', "No security findings"]]

    technology_rows = [
        [
            _e(tech.get("name", "")),
            _e(tech.get("category", "")),
            _e(str(tech.get("confidence", "")).upper()),
            _e(tech.get("evidence", "")),
        ]
        for tech in technology.get("technologies", []) or []
    ]
    if not technology_rows:
        technology_rows = [["No technologies detected", "-", "-", "-"]]

    header_rows = [
        [
            _e(header.get("header", header.get("name", ""))),
            (
                '<span class="ok">present</span>'
                if header.get("present")
                else '<span class="medium">missing</span>'
            ),
            _e(header.get("value") if header.get("value") is not None else "Not sent"),
        ]
        for header in headers
    ]
    if not header_rows:
        header_rows = [["No headers captured", "-", "-"]]

    dns_rows = []
    for record_type, values in dns.items():
        if values:
            for value in values:
                dns_rows.append([_e(record_type), _e(value)])
        else:
            dns_rows.append([_e(record_type), "-"])
    if not dns_rows:
        dns_rows = [["-", "DNS analysis disabled"]]

    cookie_rows = [
        [
            _e(cookie.get("name", "")),
            _e(_yes_no(cookie.get("secure"))),
            _e(_yes_no(cookie.get("httponly"))),
            _e(cookie.get("samesite") or "not set"),
        ]
        for cookie in cookies.get("cookies", []) or []
    ]
    if not cookie_rows:
        cookie_rows = [["No cookies detected", "-", "-", "-"]]

    cors_headers = cors.get("headers", {}) or {}
    cors_rows = [
        [_e(field), _e(value if value is not None else "Not sent")]
        for field, value in cors_headers.items()
    ]
    if not cors_rows:
        cors_rows = [["No CORS headers detected", "-"]]

    redirect_rows = [
        [
            str(index),
            _e(item.get("status", "N/A")),
            _e(item.get("url", "N/A")),
        ]
        for index, item in enumerate(http.get("history", []) or [], start=1)
    ]
    if not redirect_rows:
        redirect_rows = [["-", "NONE", "No redirects detected"]]

    spf = dns_security.get("spf", {}) or {}
    dmarc = dns_security.get("dmarc", {}) or {}
    dnssec = dns_security.get("dnssec", {}) or {}

    dns_security_rows = [
        [
            "SPF",
            _e("present" if spf.get("present") else "missing"),
            _e(
                "; ".join(spf.get("records", []) or [])
                if spf.get("records")
                else "No SPF record"
            ),
        ],
        [
            "DMARC",
            _e("present" if dmarc.get("present") else "missing"),
            _e(
                f"policy={dmarc.get('policy') or 'not set'}"
                if dmarc.get("present")
                else "No DMARC record"
            ),
        ],
        [
            "DNSSEC",
            _e("present" if dnssec.get("present") else "not detected"),
            _e(
                "DNSKEY record found"
                if dnssec.get("present")
                else "No DNSKEY record found"
            ),
        ],
    ]

    tls_rows = []
    if tls.get("skipped"):
        tls_rows = [["Status", "SKIPPED"], ["Reason", _e(tls.get("reason") or "Disabled")]]
    elif "error" in tls:
        tls_rows = [
            ["Status", "ERROR"],
            ["Error", _e(tls.get("error", ""))],
        ]
    else:
        tls_rows = [
            ["Verified", _e(_yes_no(tls.get("verified")))],
            ["Version", _e(tls.get("version") or "N/A")],
            ["Cipher", _e(tls.get("cipher") or "N/A")],
            ["Subject", _e(tls.get("subject") or "N/A")],
            ["Issuer", _e(tls.get("issuer") or "N/A")],
            ["Serial", _e(tls.get("serial") or "N/A")],
            ["Issued", _e(tls.get("issued_at") or "N/A")],
            ["Expires", _e(tls.get("expires_at") or "N/A")],
            [
                "Days Left",
                _e(
                    "N/A"
                    if tls.get("days_left") is None
                    else tls.get("days_left")
                ),
            ],
            [
                "Expired",
                _e(
                    "N/A"
                    if tls.get("expired") is None
                    else _yes_no(tls.get("expired"))
                ),
            ],
            [
                "SAN",
                _e(", ".join(tls.get("san", []) or []) or "N/A"),
            ],
        ]
        if tls.get("verification_error"):
            tls_rows.append(
                ["Verification", _e(tls["verification_error"])]
            )

    if security_txt.get("skipped"):
        security_txt_rows = [
            ["Status", "SKIPPED"],
            ["Reason", _e(security_txt.get("reason") or "Disabled")],
        ]
    else:
        security_txt_rows = [
            ["Found", _e(_yes_no(security_txt.get("found")))],
            ["URL", _e(security_txt.get("url") or "N/A")],
            [
                "Status",
                _e(
                    security_txt.get("status")
                    if security_txt.get("status") is not None
                    else "N/A"
                ),
            ],
            ["Valid", _e(_yes_no(security_txt.get("valid")))],
            ["Expires", _e(security_txt.get("expires_at") or "N/A")],
            [
                "Contacts",
                _e(
                    ", ".join(security_txt.get("contacts", []) or [])
                    or "N/A"
                ),
            ],
        ]
        fields = security_txt.get("fields", {}) or {}
        for field in ("policy", "canonical", "preferred-languages"):
            values = fields.get(field, []) or []
            if values:
                security_txt_rows.append(
                    [field.replace("-", " ").title(), _e(", ".join(values))]
                )
        if security_txt.get("error"):
            security_txt_rows.append(["Error", _e(security_txt["error"])])

    http_rows = [
        ["Status", _e(http.get("status", "N/A"))],
        ["Final URL", _e(http.get("url", "N/A"))],
        ["Server", _e(http.get("server") or "Not detected")],
        ["Powered By", _e(http.get("powered_by") or "Not detected")],
        ["Content Type", _e(http.get("content_type") or "Not provided")],
        [
            "Redirects",
            _e(len(http.get("history", []) or [])),
        ],
        [
            "Response Headers",
            _e(len(http.get("headers", {}) or {})),
        ],
        [
            "HTTPS Downgrade",
            _e("yes" if http.get("scheme_downgrade") else "no"),
        ],
    ]

    summary_rows = [
        [
            f'<span class="severity {severity.lower()}">{severity}</span>',
            _e(security_summary.get(severity, 0)),
        ]
        for severity in SEVERITIES
    ]
    summary_rows.append(
        ["<strong>TOTAL</strong>", _e(security_summary.get("total", 0))]
    )

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>StyxScan Report - {_e(target)}</title>
<style>
    * {{ box-sizing: border-box; }}
    body {{
        margin: 0;
        background: #0b0f14;
        color: #e6edf3;
        font-family: Inter, system-ui, -apple-system, BlinkMacSystemFont,
            "Segoe UI", sans-serif;
    }}
    .container {{ max-width: 1100px; margin: 40px auto; padding: 0 20px; }}
    .header {{
        background: #111821;
        border: 1px solid #263241;
        border-radius: 14px;
        padding: 28px;
        margin-bottom: 24px;
    }}
    .header h1 {{ margin: 0; color: #22d3ee; font-size: 30px; }}
    .header p {{ color: #8b98a8; margin-bottom: 0; }}
    .grid {{
        display: grid;
        grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
        gap: 14px;
        margin-bottom: 24px;
    }}
    .card {{
        background: #111821;
        border: 1px solid #263241;
        border-radius: 12px;
        padding: 20px;
    }}
    .card .label {{ color: #8b98a8; font-size: 13px; }}
    .card .value {{ font-size: 24px; font-weight: 700; margin-top: 8px; }}
    .section {{
        background: #111821;
        border: 1px solid #263241;
        border-radius: 14px;
        padding: 24px;
        margin-bottom: 24px;
        overflow-x: auto;
    }}
    h2 {{ margin-top: 0; color: #22d3ee; }}
    table {{ width: 100%; border-collapse: collapse; }}
    th, td {{
        padding: 12px;
        text-align: left;
        border-bottom: 1px solid #263241;
        vertical-align: top;
    }}
    th {{ color: #8b98a8; font-size: 13px; text-transform: uppercase; }}
    .severity {{ font-weight: 700; }}
    .critical {{ color: #ff3b3b; }}
    .high {{ color: #ff5c5c; }}
    .medium {{ color: #f6c453; }}
    .low {{ color: #55d6be; }}
    .info {{ color: #8b98a8; }}
    .ok {{ color: #55d6be; font-weight: 700; }}
    .footer {{
        color: #667383;
        text-align: center;
        padding: 20px;
        font-size: 13px;
    }}
</style>
</head>
<body>
<div class="container">

    <div class="header">
        <h1>STYXSCAN</h1>
        <p>Security Research Toolkit v{_e(__version__)}</p>
        <p>Target: <strong>{_e(target)}</strong></p>
    </div>

    <div class="grid">
        <div class="card">
            <div class="label">HTTP STATUS</div>
            <div class="value">{_e(http.get("status", "N/A"))}</div>
        </div>
        <div class="card">
            <div class="label">SECURITY HEADERS</div>
            <div class="value">{present_headers}/{len(headers)}</div>
        </div>
        <div class="card">
            <div class="label">TLS</div>
            <div class="value">{_e(_tls_status(tls))}</div>
        </div>
        <div class="card">
            <div class="label">SECURITY.TXT</div>
            <div class="value">{_e(_security_txt_status(security_txt))}</div>
        </div>
        <div class="card">
            <div class="label">FINDINGS</div>
            <div class="value">{len(findings)}</div>
        </div>
    </div>

    <div class="section">
        <h2>HTTP Information</h2>
        {_table(["Property", "Value"], http_rows)}
    </div>

    <div class="section">
        <h2>Redirect History</h2>
        {_table(["Step", "Status", "URL"], redirect_rows)}
    </div>

    <div class="section">
        <h2>Security Headers</h2>
        {_table(["Header", "Status", "Value"], header_rows)}
    </div>

    <div class="section">
        <h2>TLS</h2>
        {_table(["Property", "Value"], tls_rows)}
    </div>

    <div class="section">
        <h2>DNS Records</h2>
        {_table(["Type", "Value"], dns_rows)}
    </div>

    <div class="section">
        <h2>DNS Security</h2>
        {_table(["Check", "Status", "Details"], dns_security_rows)}
    </div>

    <div class="section">
        <h2>security.txt</h2>
        {_table(["Property", "Value"], security_txt_rows)}
    </div>

    <div class="section">
        <h2>Cookies</h2>
        {_table(["Name", "Secure", "HttpOnly", "SameSite"], cookie_rows)}
    </div>

    <div class="section">
        <h2>CORS</h2>
        {_table(["Header", "Value"], cors_rows)}
    </div>

    <div class="section">
        <h2>Technology Detection</h2>
        {_table(["Technology", "Category", "Confidence", "Evidence"], technology_rows)}
    </div>

    <div class="section">
        <h2>Security Summary</h2>
        {_table(["Severity", "Count"], summary_rows)}
    </div>

    <div class="section">
        <h2>Security Findings</h2>
        {_table(["Severity", "Finding"], finding_rows)}
    </div>

    <div class="footer">
        StyxScan performs passive security analysis of publicly accessible information.
    </div>

</div>
</body>
</html>
"""

    with open(output_file, "w", encoding="utf-8") as file:
        file.write(html)
