HEADER_SEVERITY = {
    "HSTS": "MEDIUM",
    "CSP": "MEDIUM",
    "X-Content-Type-Options": "LOW",
    "X-Frame-Options": "LOW",
    "Referrer-Policy": "LOW",
    "Permissions-Policy": "LOW",
}


SEVERITY_ORDER = [
    "CRITICAL",
    "HIGH",
    "MEDIUM",
    "LOW",
    "INFO",
]


def analyze_headers(headers):
    findings = []

    for header in headers:
        if not header["present"]:
            name = header["name"]

            findings.append({
                "type": "security-header",
                "name": name,
                "severity": HEADER_SEVERITY.get(
                    name,
                    "INFO",
                ),
                "message": f"{name} is missing",
            })

    return findings


def summarize(findings):
    summary = {
        severity: 0
        for severity in SEVERITY_ORDER
    }

    for finding in findings:
        severity = finding.get(
            "severity",
            "INFO",
        )

        if severity not in summary:
            severity = "INFO"

        summary[severity] += 1

    summary["total"] = len(findings)

    return summary
