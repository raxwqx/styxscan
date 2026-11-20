"""TLS certificate inspection."""

from __future__ import annotations

import os
import socket
import ssl
import tempfile
from datetime import datetime, timezone
from urllib.parse import urlsplit

DEFAULT_TIMEOUT = 10.0
MAX_TIMEOUT = 60.0


def _extract_common_name(name_data) -> str | None:
    for attribute_group in name_data or ():
        for attribute in attribute_group:
            if attribute[0] == "commonName":
                return attribute[1]
    return None


def _decode_der_certificate(der: bytes | None) -> dict:
    """Decode a binary certificate when verification was disabled.

    ``SSLSocket.getpeercert()`` returns an empty dictionary for unverified
    connections. CPython exposes a decoder through ``ssl._ssl`` which is used
    here to keep the fallback report useful without changing the trust mode.
    """

    if not der:
        return {}

    decoder = getattr(ssl._ssl, "_test_decode_cert", None)
    if decoder is None:
        return {}

    path = None
    try:
        pem = ssl.DER_cert_to_PEM_cert(der)
        with tempfile.NamedTemporaryFile(
            mode="w",
            suffix=".pem",
            encoding="ascii",
            delete=False,
        ) as handle:
            handle.write(pem)
            path = handle.name
        return decoder(path)
    except (OSError, ValueError, ssl.SSLError):
        return {}
    finally:
        if path:
            try:
                os.unlink(path)
            except OSError:
                pass


def _unverified_context() -> ssl.SSLContext:
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    return context


def _handshake(hostname: str, port: int, timeout: float, verify: bool):
    context = (
        ssl.create_default_context()
        if verify
        else _unverified_context()
    )

    with socket.create_connection(
        (hostname, port),
        timeout=timeout,
    ) as sock:
        with context.wrap_socket(
            sock,
            server_hostname=hostname,
        ) as tls:
            certificate = tls.getpeercert()
            if not certificate:
                certificate = _decode_der_certificate(
                    tls.getpeercert(binary_form=True)
                )

            cipher_info = tls.cipher()
            cipher = cipher_info[0] if cipher_info else None
            return certificate, tls.version(), cipher


def _certificate_time(value):
    if not value:
        return None
    try:
        return datetime.fromtimestamp(
            ssl.cert_time_to_seconds(value),
            tz=timezone.utc,
        )
    except (ValueError, OverflowError, OSError):
        return None


def _failure(error: object) -> dict:
    return {
        "error": str(error),
        "connected": False,
        "verified": False,
    }


def inspect(url: str, timeout: float = DEFAULT_TIMEOUT) -> dict:
    """Inspect the TLS certificate of an HTTPS target.

    A certificate-verified handshake is attempted first. If verification
    fails (expired, self-signed, hostname mismatch), the handshake is retried
    without verification so the certificate details can still be reported.
    The result then carries ``verified: False`` and ``verification_error``.
    """

    if timeout <= 0 or timeout > MAX_TIMEOUT:
        return _failure(
            f"timeout must be between 0 and {MAX_TIMEOUT:g} seconds"
        )

    try:
        parsed = urlsplit(url)
        hostname = parsed.hostname
        port = parsed.port or 443
    except ValueError as error:
        return _failure(error)

    if not hostname:
        return _failure("Invalid hostname")

    if not hostname.isascii():
        try:
            hostname = hostname.encode("idna").decode("ascii")
        except UnicodeError as error:
            return _failure(f"Invalid hostname: {error}")

    verification_error = None
    try:
        certificate, version, cipher = _handshake(
            hostname,
            port,
            timeout,
            verify=True,
        )
        verified = True
    except ssl.SSLCertVerificationError as error:
        verification_error = str(error)
        try:
            certificate, version, cipher = _handshake(
                hostname,
                port,
                timeout,
                verify=False,
            )
            verified = False
        except (OSError, ssl.SSLError, ValueError) as retry_error:
            return _failure(retry_error)
    except (OSError, ssl.SSLError, ValueError) as error:
        return _failure(error)

    certificate = certificate or {}
    issued_at = _certificate_time(certificate.get("notBefore"))
    expires_at = _certificate_time(certificate.get("notAfter"))

    days_left = None
    expired = None
    if expires_at is not None:
        days_left = (expires_at - datetime.now(timezone.utc)).days
        expired = expires_at <= datetime.now(timezone.utc)

    san = [
        f"{kind}:{value}"
        for kind, value in certificate.get("subjectAltName", ())
    ]

    return {
        "connected": True,
        "verified": verified,
        "verification_error": verification_error,
        "version": version,
        "cipher": cipher,
        "subject": _extract_common_name(certificate.get("subject", ())),
        "issuer": _extract_common_name(certificate.get("issuer", ())),
        "serial": certificate.get("serialNumber"),
        "issued_at": issued_at.isoformat() if issued_at else None,
        "expires_at": expires_at.isoformat() if expires_at else None,
        "days_left": days_left,
        "expired": expired,
        "san": sorted(san),
    }
