import socket
import ssl
from datetime import datetime, timezone
from urllib.parse import urlparse


def extract_common_name(name_data):
    """Extract a Common Name (CN) from a certificate subject or issuer."""
    for attribute_group in name_data or ():
        for attribute in attribute_group:
            if len(attribute) >= 2 and attribute[0] == "commonName":
                return attribute[1]
    return None


def inspect(url, timeout=10):
    """Inspect a verified HTTPS certificate; plain HTTP targets are skipped."""
    parsed = urlparse(url)
    if parsed.scheme.lower() != "https":
        return {"skipped": True, "reason": "TLS inspection requires an HTTPS URL."}
    try:
        hostname = parsed.hostname
        port = parsed.port or 443
        if not hostname:
            return {"error": "Invalid hostname"}
        context = ssl.create_default_context()
        with socket.create_connection((hostname, port), timeout=timeout) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as tls:
                certificate = tls.getpeercert()
                not_before = certificate.get("notBefore")
                not_after = certificate.get("notAfter")
                issued_at = None
                expires_at = None
                days_left = None
                if not_before:
                    issued_timestamp = ssl.cert_time_to_seconds(not_before)
                    issued_at = datetime.fromtimestamp(
                        issued_timestamp, tz=timezone.utc
                    ).isoformat()
                if not_after:
                    expires_timestamp = ssl.cert_time_to_seconds(not_after)
                    expires_datetime = datetime.fromtimestamp(
                        expires_timestamp, tz=timezone.utc
                    )
                    expires_at = expires_datetime.isoformat()
                    days_left = (expires_datetime - datetime.now(timezone.utc)).days
                cipher_info = tls.cipher()
                return {
                    "version": tls.version(),
                    "cipher": cipher_info[0] if cipher_info else None,
                    "subject": extract_common_name(certificate.get("subject", ())),
                    "issuer": extract_common_name(certificate.get("issuer", ())),
                    "issued_at": issued_at,
                    "expires_at": expires_at,
                    "days_left": days_left,
                }
    except (OSError, ssl.SSLError, ValueError) as error:
        return {"error": str(error)}
