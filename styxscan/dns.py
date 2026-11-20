"""DNS reconnaissance and email/DNSSEC security analysis."""

from __future__ import annotations

import ipaddress
import re

import dns.exception
import dns.resolver

RECORD_TYPES = ("A", "AAAA", "MX", "NS", "TXT")

REQUESTED_RECORD_TYPES = RECORD_TYPES

_SPF_ALL_RE = re.compile(r"(?:^|\s)\+all(?:\s|$)", re.IGNORECASE)
_SPF_QUESTION_ALL_RE = re.compile(r"(?:^|\s)\?all(?:\s|$)", re.IGNORECASE)
_DMARC_POLICY_RE = re.compile(
    r"(?:^|;)\s*p\s*=\s*(none|quarantine|reject)\b",
    re.IGNORECASE,
)


def _is_ip_address(domain: str) -> bool:
    try:
        ipaddress.ip_address(domain)
        return True
    except ValueError:
        return False


def _clean_record(record: object) -> str:
    return str(record).strip().strip('"')


def _query(name: str, record_type: str, timeout: float):
    return dns.resolver.resolve(
        name,
        record_type,
        lifetime=timeout,
        search=False,
        raise_on_no_answer=False,
    )


def resolve_with_warnings(
    domain: str,
    timeout: float = 5.0,
) -> tuple[dict[str, list[str]], list[str]]:
    """Collect A, AAAA, MX, NS, and TXT records plus resolver diagnostics.

    Resolver failures are no longer indistinguishable from an empty answer
    set: they are returned as warnings. NXDOMAIN, timeouts, and nameserver
    failures stop the remaining lookups because they affect the whole name.
    """

    if timeout <= 0:
        raise ValueError("timeout must be greater than 0")

    records = {record_type: [] for record_type in RECORD_TYPES}
    warnings: list[str] = []

    for record_type in RECORD_TYPES:
        try:
            answers = _query(domain, record_type, timeout)
        except dns.resolver.NXDOMAIN:
            warnings.append(f"{record_type} lookup failed: target does not exist")
            break
        except dns.resolver.NoAnswer:
            records[record_type] = []
            continue
        except dns.resolver.NoNameservers:
            warnings.append(
                f"{record_type} lookup failed: no nameservers available"
            )
            break
        except dns.exception.Timeout:
            warnings.append(f"{record_type} lookup timed out")
            break
        except dns.exception.DNSException as error:
            warnings.append(f"{record_type} lookup failed: {error}")
            continue
        except Exception as error:  # defensive: never crash on resolver bugs
            warnings.append(
                f"{record_type} lookup failed: "
                f"{type(error).__name__}: {error}"
            )
            continue

        if getattr(answers, "rrset", None) is None:
            records[record_type] = []
            continue

        records[record_type] = sorted(
            {
                value
                for value in (_clean_record(answer) for answer in answers)
                if value
            }
        )

    return records, warnings


def resolve(domain: str, timeout: float = 5.0) -> dict[str, list[str]]:
    """Backwards-compatible record resolver that returns only records."""

    records, _ = resolve_with_warnings(domain, timeout=timeout)
    return records


def _dnssec_present(
    domain: str,
    timeout: float,
) -> tuple[bool, list[str]]:
    """Look for DNSKEY records at the name or one of its parent zones.

    A DNSKEY record is published at the zone apex, so checking only the
    scanned hostname misses signed parent zones. The walk stops before the
    top-level label to avoid treating the TLD's own DNSKEY as the target's.
    """

    if _is_ip_address(domain):
        return False, []

    labels = domain.rstrip(".").split(".")
    warnings: list[str] = []

    for index in range(0, len(labels) - 1):
        zone = ".".join(labels[index:])

        try:
            answers = _query(zone, "DNSKEY", timeout)
        except dns.resolver.NXDOMAIN:
            continue
        except dns.resolver.NoAnswer:
            continue
        except dns.resolver.NoNameservers:
            warnings.append(f"DNSSEC lookup failed at {zone}: no nameservers")
            continue
        except dns.exception.Timeout:
            warnings.append(f"DNSSEC lookup timed out at {zone}")
            continue
        except dns.exception.DNSException as error:
            warnings.append(f"DNSSEC lookup failed at {zone}: {error}")
            continue

        if getattr(answers, "rrset", None) is not None:
            return True, warnings

    return False, warnings


def analyze_security(
    domain: str,
    records: dict[str, list[str]],
    timeout: float = 5.0,
) -> dict:
    """Analyze SPF, DMARC, and DNSSEC configuration for *domain*."""

    findings: list[dict] = []
    warnings: list[str] = []
    records = records or {}
    txt_records = records.get("TXT", []) or []
    normalized_txt = [_clean_record(record) for record in txt_records]

    spf_records = [
        record
        for record in normalized_txt
        if "v=spf1" in record.lower()
    ]
    spf_present = bool(spf_records)

    if not spf_present:
        findings.append(
            {
                "type": "dns-security",
                "name": "SPF",
                "severity": "MEDIUM",
                "message": "SPF record is missing",
            }
        )
    else:
        if len(spf_records) > 1:
            findings.append(
                {
                    "type": "dns-security",
                    "name": "SPF",
                    "severity": "MEDIUM",
                    "message": (
                        "Multiple SPF records are published; receivers may "
                        "ignore all of them"
                    ),
                }
            )

        for record in spf_records:
            if _SPF_ALL_RE.search(record):
                findings.append(
                    {
                        "type": "dns-security",
                        "name": "SPF",
                        "severity": "HIGH",
                        "message": "SPF ends with +all and authorizes every sender",
                    }
                )
            elif _SPF_QUESTION_ALL_RE.search(record):
                findings.append(
                    {
                        "type": "dns-security",
                        "name": "SPF",
                        "severity": "LOW",
                        "message": "SPF ends with ?all and makes no sender assertion",
                    }
                )

    dmarc_records: list[str] = []
    dmarc_present = False
    dmarc_policy = None

    try:
        answers = _query(f"_dmarc.{domain}", "TXT", timeout)
        if getattr(answers, "rrset", None) is not None:
            dmarc_records = [
                _clean_record(answer) for answer in answers
            ]
    except dns.resolver.NXDOMAIN:
        warnings.append("DMARC lookup failed: target does not exist")
    except dns.resolver.NoAnswer:
        pass
    except dns.resolver.NoNameservers:
        warnings.append("DMARC lookup failed: no nameservers available")
    except dns.exception.Timeout:
        warnings.append("DMARC lookup timed out")
    except dns.exception.DNSException as error:
        warnings.append(f"DMARC lookup failed: {error}")
    except Exception as error:  # defensive: never crash on resolver bugs
        warnings.append(
            f"DMARC lookup failed: {type(error).__name__}: {error}"
        )

    dmarc_tag_records = [
        record
        for record in dmarc_records
        if "v=dmarc1" in record.lower()
    ]
    dmarc_present = bool(dmarc_tag_records)

    if dmarc_present:
        for record in dmarc_tag_records:
            match = _DMARC_POLICY_RE.search(record)
            if match:
                dmarc_policy = match.group(1).lower()
                break

        if dmarc_policy is None:
            findings.append(
                {
                    "type": "dns-security",
                    "name": "DMARC",
                    "severity": "LOW",
                    "message": "DMARC record has no valid p= policy",
                }
            )
        elif dmarc_policy == "none":
            findings.append(
                {
                    "type": "dns-security",
                    "name": "DMARC",
                    "severity": "LOW",
                    "message": "DMARC policy is p=none and does not block abuse",
                }
            )
    else:
        findings.append(
            {
                "type": "dns-security",
                "name": "DMARC",
                "severity": "MEDIUM",
                "message": "DMARC record is missing",
            }
        )

    dnssec_present, dnssec_warnings = _dnssec_present(domain, timeout)
    warnings.extend(dnssec_warnings)

    if not dnssec_present:
        findings.append(
            {
                "type": "dns-security",
                "name": "DNSSEC",
                "severity": "LOW",
                "message": "DNSSEC DNSKEY record not detected",
            }
        )

    return {
        "spf": {
            "present": spf_present,
            "records": spf_records,
        },
        "dmarc": {
            "present": dmarc_present,
            "policy": dmarc_policy,
            "records": dmarc_records,
        },
        "dnssec": {
            "present": dnssec_present,
        },
        "findings": findings,
        "warnings": warnings,
    }
