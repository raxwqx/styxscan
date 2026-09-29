import socket
import ssl
from datetime import datetime, timezone
from urllib.parse import urlparse


def extract_common_name(name_data):
    """
    Extract the Common Name (CN) from a certificate
    subject or issuer structure.
    """

    for attribute_group in name_data or ():
        for attribute in attribute_group:
            if attribute[0] == "commonName":
                return attribute[1]

    return None


def inspect(url):
    """
    Inspect the TLS configuration and certificate
    of an HTTPS target.
    """

    parsed = urlparse(url)

    hostname = parsed.hostname
    port = parsed.port or 443

    if not hostname:
        return {
            "error": "Invalid hostname"
        }

    context = ssl.create_default_context()

    try:
        with socket.create_connection(
            (hostname, port),
            timeout=10,
        ) as sock:

            with context.wrap_socket(
                sock,
                server_hostname=hostname,
            ) as tls:

                certificate = tls.getpeercert()

                not_before = certificate.get(
                    "notBefore"
                )

                not_after = certificate.get(
                    "notAfter"
                )

                issued_at = None
                expires_at = None
                days_left = None

                # Certificate issue date
                if not_before:
                    issued_timestamp = (
                        ssl.cert_time_to_seconds(
                            not_before
                        )
                    )

                    issued_at = (
                        datetime.fromtimestamp(
                            issued_timestamp,
                            tz=timezone.utc,
                        ).isoformat()
                    )

                # Certificate expiration date
                if not_after:
                    expires_timestamp = (
                        ssl.cert_time_to_seconds(
                            not_after
                        )
                    )

                    expires_datetime = (
                        datetime.fromtimestamp(
                            expires_timestamp,
                            tz=timezone.utc,
                        )
                    )

                    expires_at = (
                        expires_datetime.isoformat()
                    )

                    now = datetime.now(
                        timezone.utc
                    )

                    days_left = (
                        expires_datetime - now
                    ).days

                subject = extract_common_name(
                    certificate.get(
                        "subject",
                        (),
                    )
                )

                issuer = extract_common_name(
                    certificate.get(
                        "issuer",
                        (),
                    )
                )

                cipher_info = tls.cipher()

                cipher = None

                if cipher_info:
                    cipher = cipher_info[0]

                return {
                    "version": tls.version(),
                    "cipher": cipher,
                    "subject": subject,
                    "issuer": issuer,
                    "issued_at": issued_at,
                    "expires_at": expires_at,
                    "days_left": days_left,
                }

    except Exception as error:
        return {
            "error": str(error)
        }
