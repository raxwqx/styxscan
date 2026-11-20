from styxscan.html_reporter import generate


def make_result():
    return {
        "target": "https://example.com/<script>alert(1)</script>",
        "http": {
            "status": 200,
            "url": "https://example.com/",
            "headers": {"Server": "<script>server</script>"},
            "server": "<script>server</script>",
            "powered_by": "<b>runtime</b>",
            "content_type": "text/html",
            "history": [],
            "scheme_downgrade": False,
        },
        "headers": [
            {
                "name": "HSTS",
                "header": "Strict-Transport-Security",
                "present": True,
                "value": "max-age=31536000<script>",
            }
        ],
        "dns": {"A": ["192.0.2.1"]},
        "dns_security": {
            "spf": {"present": True, "records": ["v=spf1 -all"]},
            "dmarc": {
                "present": True,
                "policy": "reject",
                "records": [],
            },
            "dnssec": {"present": True},
            "findings": [],
            "warnings": [],
        },
        "tls": {
            "verified": True,
            "version": "TLSv1.3",
            "cipher": "TEST",
            "subject": "example.com",
            "issuer": "Test CA",
            "serial": "01AB",
            "issued_at": None,
            "expires_at": None,
            "days_left": "<script>days</script>",
            "expired": False,
            "san": [],
        },
        "security_txt": {
            "found": True,
            "url": "https://example.com/.well-known/security.txt",
            "status": 200,
            "fields": {"contact": ["mailto:security@example.com"]},
            "contacts": ["mailto:security@example.com"],
            "expires_at": "2027-01-01T00:00:00+00:00",
            "expired": False,
            "valid": True,
            "findings": [],
            "warnings": [],
        },
        "cookies": {
            "cookies": [
                {
                    "name": "session",
                    "secure": True,
                    "httponly": True,
                    "samesite": "Lax",
                }
            ],
            "findings": [],
        },
        "cors": {"headers": {}, "findings": []},
        "technology": {"technologies": [], "findings": []},
        "findings": [
            {
                "severity": "MEDIUM",
                "message": "<img src=x onerror=alert(1)>",
            }
        ],
        "security_summary": {
            "CRITICAL": 0,
            "HIGH": 0,
            "MEDIUM": 1,
            "LOW": 0,
            "INFO": 0,
            "total": 1,
        },
    }


def test_html_report_escapes_untrusted_values(tmp_path):
    report = tmp_path / "report.html"

    generate(make_result(), str(report))

    html = report.read_text(encoding="utf-8")

    assert "<script>alert(1)</script>" not in html
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in html
    assert "<img src=x onerror=alert(1)>" not in html
    assert "&lt;img src=x onerror=alert(1)&gt;" in html
    assert "&lt;b&gt;runtime&lt;/b&gt;" in html
    assert "&lt;script&gt;days&lt;/script&gt;" in html


def test_html_report_contains_all_sections(tmp_path):
    report = tmp_path / "report.html"

    generate(make_result(), str(report))

    html = report.read_text(encoding="utf-8")

    for heading in (
        "HTTP Information",
        "Redirect History",
        "Security Headers",
        "TLS",
        "DNS Records",
        "DNS Security",
        "security.txt",
        "Cookies",
        "CORS",
        "Technology Detection",
        "Security Summary",
        "Security Findings",
    ):
        assert heading in html
