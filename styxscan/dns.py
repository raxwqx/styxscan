import dns.resolver


def resolve(domain):
    records = {}

    for record_type in [
        "A",
        "AAAA",
        "MX",
        "NS",
        "TXT",
    ]:
        try:
            answers = dns.resolver.resolve(
                domain,
                record_type,
            )

            records[record_type] = [
                str(answer)
                for answer in answers
            ]

        except Exception:
            records[record_type] = []

    return records


def analyze_security(domain, records):
    findings = []

    # ============================================================
    # SPF
    # ============================================================

    txt_records = records.get(
        "TXT",
        [],
    )

    spf_records = [
        record
        for record in txt_records
        if "v=spf1" in record.lower()
    ]

    spf_present = bool(spf_records)

    if not spf_present:
        findings.append({
            "type": "dns-security",
            "name": "SPF",
            "severity": "MEDIUM",
            "message": "SPF record is missing",
        })

    # ============================================================
    # DMARC
    # ============================================================

    dmarc_present = False
    dmarc_records = []

    try:
        answers = dns.resolver.resolve(
            f"_dmarc.{domain}",
            "TXT",
        )

        dmarc_records = [
            str(answer)
            for answer in answers
        ]

        dmarc_present = any(
            "v=dmarc1" in record.lower()
            for record in dmarc_records
        )

    except Exception:
        dmarc_present = False

    if not dmarc_present:
        findings.append({
            "type": "dns-security",
            "name": "DMARC",
            "severity": "MEDIUM",
            "message": "DMARC record is missing",
        })

    # ============================================================
    # DNSSEC
    # ============================================================

    dnssec_present = False

    try:
        dns.resolver.resolve(
            domain,
            "DNSKEY",
        )

        dnssec_present = True

    except Exception:
        dnssec_present = False

    if not dnssec_present:
        findings.append({
            "type": "dns-security",
            "name": "DNSSEC",
            "severity": "LOW",
            "message": "DNSSEC DNSKEY record not detected",
        })

    return {
        "spf": {
            "present": spf_present,
            "records": spf_records,
        },
        "dmarc": {
            "present": dmarc_present,
            "records": dmarc_records,
        },
        "dnssec": {
            "present": dnssec_present,
        },
        "findings": findings,
    }
