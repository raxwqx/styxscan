from styxscan.findings import summarize


def test_summarize_findings():
    findings = [
        {
            "severity": "CRITICAL",
            "name": "Test Critical",
        },
        {
            "severity": "HIGH",
            "name": "Test High",
        },
        {
            "severity": "MEDIUM",
            "name": "Test Medium",
        },
        {
            "severity": "MEDIUM",
            "name": "Test Medium 2",
        },
        {
            "severity": "LOW",
            "name": "Test Low",
        },
        {
            "severity": "INFO",
            "name": "Test Info",
        },
    ]

    result = summarize(findings)

    assert result["CRITICAL"] == 1
    assert result["HIGH"] == 1
    assert result["MEDIUM"] == 2
    assert result["LOW"] == 1
    assert result["INFO"] == 1
    assert result["total"] == 6


def test_summarize_empty_findings():
    result = summarize([])

    assert result["CRITICAL"] == 0
    assert result["HIGH"] == 0
    assert result["MEDIUM"] == 0
    assert result["LOW"] == 0
    assert result["INFO"] == 0
    assert result["total"] == 0


def test_summarize_unknown_severity():
    findings = [
        {
            "severity": "WEIRD",
            "name": "Unknown severity",
        }
    ]

    result = summarize(findings)

    assert result["INFO"] == 1
    assert result["total"] == 1
