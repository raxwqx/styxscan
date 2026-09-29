from html import escape


def generate(result, output_file):
    target = escape(result.get("target", ""))

    http = result.get("http", {})
    headers = result.get("headers", [])
    tls = result.get("tls", {})
    technology = result.get("technology", {})
    findings = result.get("findings", [])

    present_headers = sum(
        1
        for header in headers
        if header.get("present")
    )

    technologies = technology.get(
        "technologies",
        [],
    )

    finding_rows = ""

    for finding in findings:
        severity = escape(
            finding.get("severity", "INFO")
        )

        message = escape(
            finding.get("message", "")
        )

        finding_rows += f"""
        <tr>
            <td class="severity {severity.lower()}">
                {severity}
            </td>
            <td>{message}</td>
        </tr>
        """

    if not finding_rows:
        finding_rows = """
        <tr>
            <td class="ok" colspan="2">
                No findings detected
            </td>
        </tr>
        """

    technology_rows = ""

    for tech in technologies:
        technology_rows += f"""
        <tr>
            <td>{escape(str(tech.get("name", "")))}</td>
            <td>{escape(str(tech.get("category", "")))}</td>
            <td>{escape(str(tech.get("confidence", "")).upper())}</td>
            <td>{escape(str(tech.get("evidence", "")))}</td>
        </tr>
        """

    if not technology_rows:
        technology_rows = """
        <tr>
            <td colspan="4">
                No technologies detected
            </td>
        </tr>
        """

    tls_version = escape(
        str(tls.get("version", "N/A"))
    )

    tls_status = "ERROR"

    if "error" not in tls:
        days_left = tls.get("days_left")

        if days_left is not None and days_left < 0:
            tls_status = "EXPIRED"
        elif days_left is not None and days_left <= 30:
            tls_status = "EXPIRING SOON"
        else:
            tls_status = "VALID"

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport"
      content="width=device-width, initial-scale=1.0">

<title>StyxScan Report</title>

<style>
    * {{
        box-sizing: border-box;
    }}

    body {{
        margin: 0;
        background: #0b0f14;
        color: #e6edf3;
        font-family:
            Inter,
            system-ui,
            -apple-system,
            BlinkMacSystemFont,
            "Segoe UI",
            sans-serif;
    }}

    .container {{
        max-width: 1100px;
        margin: 40px auto;
        padding: 0 20px;
    }}

    .header {{
        background: #111821;
        border: 1px solid #263241;
        border-radius: 14px;
        padding: 28px;
        margin-bottom: 24px;
    }}

    .header h1 {{
        margin: 0;
        color: #22d3ee;
        font-size: 30px;
    }}

    .header p {{
        color: #8b98a8;
        margin-bottom: 0;
    }}

    .grid {{
        display: grid;
        grid-template-columns:
            repeat(auto-fit, minmax(180px, 1fr));
        gap: 14px;
        margin-bottom: 24px;
    }}

    .card {{
        background: #111821;
        border: 1px solid #263241;
        border-radius: 12px;
        padding: 20px;
    }}

    .card .label {{
        color: #8b98a8;
        font-size: 13px;
    }}

    .card .value {{
        font-size: 24px;
        font-weight: 700;
        margin-top: 8px;
    }}

    .section {{
        background: #111821;
        border: 1px solid #263241;
        border-radius: 14px;
        padding: 24px;
        margin-bottom: 24px;
        overflow-x: auto;
    }}

    h2 {{
        margin-top: 0;
        color: #22d3ee;
    }}

    table {{
        width: 100%;
        border-collapse: collapse;
    }}

    th,
    td {{
        padding: 12px;
        text-align: left;
        border-bottom: 1px solid #263241;
    }}

    th {{
        color: #8b98a8;
        font-size: 13px;
        text-transform: uppercase;
    }}

    .severity {{
        font-weight: 700;
    }}

    .high {{
        color: #ff5c5c;
    }}

    .medium {{
        color: #f6c453;
    }}

    .low {{
        color: #55d6be;
    }}

    .info {{
        color: #8b98a8;
    }}

    .ok {{
        color: #55d6be;
        font-weight: 700;
    }}

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
        <p>Security Research Toolkit</p>
        <p>
            Target:
            <strong>{target}</strong>
        </p>
    </div>

    <div class="grid">

        <div class="card">
            <div class="label">HTTP STATUS</div>
            <div class="value">
                {http.get("status", "N/A")}
            </div>
        </div>

        <div class="card">
            <div class="label">SECURITY HEADERS</div>
            <div class="value">
                {present_headers}/{len(headers)}
            </div>
        </div>

        <div class="card">
            <div class="label">TLS</div>
            <div class="value">
                {escape(tls_status)}
            </div>
        </div>

        <div class="card">
            <div class="label">FINDINGS</div>
            <div class="value">
                {len(findings)}
            </div>
        </div>

    </div>

    <div class="section">
        <h2>Technology Detection</h2>

        <table>
            <thead>
                <tr>
                    <th>Technology</th>
                    <th>Category</th>
                    <th>Confidence</th>
                    <th>Evidence</th>
                </tr>
            </thead>

            <tbody>
                {technology_rows}
            </tbody>
        </table>
    </div>

    <div class="section">
        <h2>Security Findings</h2>

        <table>
            <thead>
                <tr>
                    <th>Severity</th>
                    <th>Finding</th>
                </tr>
            </thead>

            <tbody>
                {finding_rows}
            </tbody>
        </table>
    </div>

    <div class="section">
        <h2>TLS</h2>

        <table>
            <tr>
                <th>Version</th>
                <td>{tls_version}</td>
            </tr>

            <tr>
                <th>Status</th>
                <td>{escape(tls_status)}</td>
            </tr>

            <tr>
                <th>Days Left</th>
                <td>{tls.get("days_left", "N/A")}</td>
            </tr>
        </table>
    </div>

    <div class="footer">
        StyxScan performs passive security analysis
        of publicly accessible information.
    </div>

</div>

</body>
</html>
"""

    with open(
        output_file,
        "w",
        encoding="utf-8",
    ) as file:
        file.write(html)
