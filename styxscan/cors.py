"""CORS header analysis."""

from __future__ import annotations

from .headers import get_header

CORS_FIELDS = (
    "Access-Control-Allow-Origin",
    "Access-Control-Allow-Credentials",
    "Access-Control-Allow-Methods",
    "Access-Control-Allow-Headers",
)


def analyze(headers: dict) -> dict:
    """Review CORS response headers for common misconfigurations."""

    cors_headers = {
        field: get_header(headers, field) for field in CORS_FIELDS
    }
    vary = get_header(headers, "Vary") or ""

    findings = []

    origin = cors_headers["Access-Control-Allow-Origin"]
    credentials = cors_headers["Access-Control-Allow-Credentials"]
    credentials_enabled = (
        bool(credentials) and str(credentials).strip().lower() == "true"
    )

    if origin == "*":
        findings.append(
            {
                "type": "cors",
                "severity": "INFO",
                "message": "CORS allows all origins (*)",
            }
        )

        if credentials_enabled:
            findings.append(
                {
                    "type": "cors",
                    "severity": "MEDIUM",
                    "message": "CORS allows all origins with credentials",
                }
            )
    elif origin is not None:
        stripped = str(origin).strip()

        if stripped.lower() == "null":
            findings.append(
                {
                    "type": "cors",
                    "severity": "MEDIUM",
                    "message": (
                        "CORS allows the null origin, which can be reached "
                        "from sandboxed or data: documents"
                    ),
                }
            )
        elif stripped and "://" not in stripped:
            findings.append(
                {
                    "type": "cors",
                    "severity": "LOW",
                    "message": (
                        "CORS Access-Control-Allow-Origin is not a valid "
                        "origin or wildcard"
                    ),
                }
            )
        elif credentials_enabled:
            vary_lower = str(vary).lower()
            if "origin" not in vary_lower:
                findings.append(
                    {
                        "type": "cors",
                        "severity": "LOW",
                        "message": (
                            "CORS allows a specific origin with credentials "
                            "but Vary does not include Origin"
                        ),
                    }
                )

    if credentials is not None:
        value = str(credentials).strip().lower()
        if value not in ("true", "false"):
            findings.append(
                {
                    "type": "cors",
                    "severity": "LOW",
                    "message": (
                        "CORS Access-Control-Allow-Credentials has an "
                        "unexpected value"
                    ),
                }
            )

    return {
        "headers": cors_headers,
        "findings": findings,
    }
