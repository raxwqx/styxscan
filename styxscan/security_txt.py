"""RFC 9116 ``security.txt`` discovery."""

from __future__ import annotations

from datetime import datetime, timezone
from urllib.parse import urlsplit

import requests

from . import USER_AGENT

SECURITY_TXT_PATHS = (
    "/.well-known/security.txt",
    "/security.txt",
)

KNOWN_FIELDS = {
    "contact",
    "expires",
    "encryption",
    "acknowledgments",
    "preferred-languages",
    "canonical",
    "policy",
    "hiring",
    "csaf",
}

MAX_BODY = 64 * 1024


def _read_text(response) -> str:
    """Read at most ``MAX_BODY`` bytes from a security.txt response."""

    iter_content = getattr(response, "iter_content", None)
    if callable(iter_content):
        chunks = []
        total = 0
        for chunk in iter_content(chunk_size=4096):
            if not chunk:
                continue
            remaining = MAX_BODY - total
            if remaining <= 0:
                break
            if len(chunk) > remaining:
                chunks.append(chunk[:remaining])
                break
            chunks.append(chunk)
            total += len(chunk)

        raw = b"".join(chunks)
        encoding = getattr(response, "encoding", None) or "utf-8"
        try:
            return raw.decode(encoding, errors="replace")
        except LookupError:
            return raw.decode("utf-8", errors="replace")

    return (getattr(response, "text", "") or "")[:MAX_BODY]


def parse(text: str) -> dict[str, list[str]]:
    """Parse security.txt field lines into a case-insensitive mapping.

    Comment lines (``#``) and malformed lines are ignored. Repeated fields
    are preserved because ``Contact`` and ``Acknowledgments`` may appear
    more than once.
    """

    fields: dict[str, list[str]] = {}

    for raw_line in (text or "").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or ":" not in line:
            continue

        name, value = line.split(":", 1)
        name = name.strip().lower()
        value = value.strip()

        if name not in KNOWN_FIELDS or not value:
            continue

        fields.setdefault(name, []).append(value)

    return fields


def _parse_expires(value: str | None) -> datetime | None:
    if not value:
        return None

    try:
        value = value.strip()
        if value.endswith(("Z", "z")):
            value = value[:-1] + "+00:00"
        parsed = datetime.fromisoformat(value)
    except (ValueError, TypeError):
        return None

    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)

    return parsed


def _findings(
    found: bool,
    contacts: list[str],
    expires: str | None,
    expires_at: datetime | None,
    expired: bool | None,
) -> list[dict]:
    if not found:
        return [
            {
                "type": "security-txt",
                "name": "security.txt",
                "severity": "LOW",
                "message": "security.txt is missing",
            }
        ]

    findings = []

    if not contacts:
        findings.append(
            {
                "type": "security-txt",
                "name": "security.txt",
                "severity": "MEDIUM",
                "message": "security.txt has no Contact field",
            }
        )

    if not expires:
        findings.append(
            {
                "type": "security-txt",
                "name": "security.txt",
                "severity": "LOW",
                "message": "security.txt has no Expires field",
            }
        )
    elif expires_at is None:
        findings.append(
            {
                "type": "security-txt",
                "name": "security.txt",
                "severity": "LOW",
                "message": "security.txt Expires value is not valid ISO 8601",
            }
        )
    elif expired:
        findings.append(
            {
                "type": "security-txt",
                "name": "security.txt",
                "severity": "MEDIUM",
                "message": "security.txt has expired",
            }
        )

    return findings


def discover(base_url: str, timeout: float = 10) -> dict:
    """Fetch and validate ``security.txt`` for the target origin.

    ``/.well-known/security.txt`` is preferred and ``/security.txt`` is used
    as a fallback. Network failures are reported separately from a missing
    file so an outage is not presented as a security finding.
    """

    parsed = urlsplit(base_url)
    if parsed.scheme not in ("http", "https") or not parsed.netloc:
        return {
            "found": False,
            "error": "invalid target URL",
            "findings": [],
            "warnings": [],
            "fields": {},
            "contacts": [],
            "expires": None,
            "expires_at": None,
            "expired": None,
            "valid": False,
            "url": None,
            "status": None,
        }

    origin = f"{parsed.scheme}://{parsed.netloc}"
    warnings = []
    last_status = None

    for path in SECURITY_TXT_PATHS:
        url = origin + path

        try:
            response = requests.get(
                url,
                timeout=timeout,
                allow_redirects=True,
                stream=True,
                headers={"User-Agent": USER_AGENT},
            )
        except requests.RequestException as error:
            warnings.append(f"{path} request failed: {error}")
            continue
        except ValueError as error:
            warnings.append(f"{path} request failed: {error}")
            continue

        try:
            last_status = response.status_code

            if response.status_code != 200:
                continue

            text = _read_text(response)
            fields = parse(text)
            contacts = fields.get("contact", [])
            expires = fields.get("expires", [None])[0]
            expires_at = _parse_expires(expires)
            now = datetime.now(timezone.utc)
            expired = (
                expires_at is not None and expires_at <= now
            )
            valid = bool(contacts) and expires_at is not None and not expired

            return {
                "found": True,
                "url": getattr(response, "url", url) or url,
                "status": response.status_code,
                "fields": fields,
                "contacts": contacts,
                "expires": expires,
                "expires_at": (
                    expires_at.isoformat() if expires_at else None
                ),
                "expired": expired if expires_at is not None else None,
                "valid": valid,
                "findings": _findings(
                    True,
                    contacts,
                    expires,
                    expires_at,
                    expired if expires_at is not None else None,
                ),
                "warnings": warnings,
            }
        except requests.RequestException as error:
            warnings.append(f"{path} response failed: {error}")
            continue
        finally:
            close = getattr(response, "close", None)
            if callable(close):
                close()

    return {
        "found": False,
        "url": origin + SECURITY_TXT_PATHS[0],
        "status": last_status,
        "fields": {},
        "contacts": [],
        "expires": None,
        "expires_at": None,
        "expired": None,
        "valid": False,
        "findings": (
            []
            if last_status is None and warnings
            else _findings(False, [], None, None, None)
        ),
        "warnings": warnings,
    }
