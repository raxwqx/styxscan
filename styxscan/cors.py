def analyze(headers):
    cors_headers = {
        "Access-Control-Allow-Origin": headers.get(
            "Access-Control-Allow-Origin"
        ),
        "Access-Control-Allow-Credentials": headers.get(
            "Access-Control-Allow-Credentials"
        ),
        "Access-Control-Allow-Methods": headers.get(
            "Access-Control-Allow-Methods"
        ),
        "Access-Control-Allow-Headers": headers.get(
            "Access-Control-Allow-Headers"
        ),
    }

    findings = []

    origin = cors_headers["Access-Control-Allow-Origin"]
    credentials = cors_headers[
        "Access-Control-Allow-Credentials"
    ]

    if origin == "*":
        findings.append({
            "type": "cors",
            "severity": "INFO",
            "message": "CORS allows all origins (*)",
        })

        if credentials and credentials.lower() == "true":
            findings.append({
                "type": "cors",
                "severity": "MEDIUM",
                "message": (
                    "CORS allows all origins with credentials"
                ),
            })

    return {
        "headers": cors_headers,
        "findings": findings,
    }
