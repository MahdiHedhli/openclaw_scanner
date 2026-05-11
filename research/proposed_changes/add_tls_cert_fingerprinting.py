"""
Proposed enhancement: TLS Certificate Fingerprinting for OpenClaw Scanner
=========================================================================
Date: 2026-03-23
Research topic: #2 — TLS certificate fingerprinting

This file contains proposed code additions for extracting and matching
TLS certificate metadata during active probing. It does NOT modify any
existing source files — it is a standalone reference for implementation.

Dependencies:
  - `cryptography` (pip install cryptography) — for cert parsing
  - Python `ssl` + `socket` standard library — for cert retrieval
"""

# ---------------------------------------------------------------------------
# 1. New data model: TLSCertInfo
# ---------------------------------------------------------------------------
# Add this to openclaw_scanner/models.py alongside ProbeObservation

from dataclasses import dataclass, field
from typing import List, Optional


@dataclass
class TLSCertInfo:
    """Metadata extracted from a TLS certificate presented by the target."""

    subject: Optional[str] = None          # RFC 4514 string, e.g. "CN=OpenClaw Gateway,O=OpenClaw Inc"
    issuer: Optional[str] = None           # RFC 4514 string
    serial_number: Optional[str] = None    # Hex string of serial number
    sans: List[str] = field(default_factory=list)  # Subject Alternative Names (DNS and IP)
    not_before: Optional[str] = None       # ISO 8601 UTC
    not_after: Optional[str] = None        # ISO 8601 UTC
    sig_algorithm: Optional[str] = None    # e.g. "sha256WithRSAEncryption"
    pubkey_type: Optional[str] = None      # "RSA" or "EC"
    pubkey_bits: Optional[int] = None      # e.g. 2048, 256
    fingerprint_sha256: Optional[str] = None  # Hex SHA-256 of DER-encoded cert
    self_signed: bool = False              # True if subject == issuer
    error: Optional[str] = None            # Error message if cert extraction failed


# ---------------------------------------------------------------------------
# 2. Certificate extraction function
# ---------------------------------------------------------------------------
# Add this to openclaw_scanner/probe.py (or a new tls_probe.py module)

import hashlib
import socket
import ssl
from typing import Optional as Opt


def extract_tls_cert(
    host: str,
    port: int,
    timeout: float = 5.0,
    server_name: Optional[str] = None,
) -> "TLSCertInfo":
    """
    Connect to host:port, perform a TLS handshake, and extract certificate
    metadata. Uses SNI (Server Name Indication) if server_name is provided.

    Returns a TLSCertInfo dataclass. On failure, the `error` field is set.
    """
    info = TLSCertInfo()

    try:
        # We must not verify the cert — we want to inspect it regardless of validity
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE

        hostname = server_name or host

        with socket.create_connection((host, port), timeout=timeout) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                der_cert = ssock.getpeercert(binary_form=True)

        if not der_cert:
            info.error = "No certificate returned by server"
            return info

        # Parse with the cryptography library
        try:
            from cryptography import x509
            from cryptography.hazmat.primitives import hashes
            from cryptography.hazmat.primitives.asymmetric import rsa, ec
        except ImportError:
            info.error = "cryptography library not installed (pip install cryptography)"
            # Fallback: compute fingerprint from raw DER without parsing
            info.fingerprint_sha256 = hashlib.sha256(der_cert).hexdigest()
            return info

        cert = x509.load_der_x509_certificate(der_cert)

        info.subject = cert.subject.rfc4514_string()
        info.issuer = cert.issuer.rfc4514_string()
        info.serial_number = format(cert.serial_number, "x")
        info.not_before = cert.not_valid_before_utc.isoformat()
        info.not_after = cert.not_valid_after_utc.isoformat()
        info.fingerprint_sha256 = cert.fingerprint(hashes.SHA256()).hex()
        info.self_signed = (cert.subject == cert.issuer)

        # Signature algorithm
        try:
            info.sig_algorithm = cert.signature_algorithm_oid._name
        except Exception:
            info.sig_algorithm = str(cert.signature_algorithm_oid.dotted_string)

        # Public key type and size
        pubkey = cert.public_key()
        if isinstance(pubkey, rsa.RSAPublicKey):
            info.pubkey_type = "RSA"
            info.pubkey_bits = pubkey.key_size
        elif isinstance(pubkey, ec.EllipticCurvePublicKey):
            info.pubkey_type = "EC"
            info.pubkey_bits = pubkey.key_size
        else:
            info.pubkey_type = type(pubkey).__name__
            info.pubkey_bits = getattr(pubkey, "key_size", None)

        # Subject Alternative Names
        try:
            san_ext = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
            info.sans = [
                name.value
                for name in san_ext.value
                if isinstance(name, (x509.DNSName, x509.IPAddress))
            ]
            # Convert IP addresses to strings
            info.sans = [str(s) for s in info.sans]
        except x509.ExtensionNotFound:
            info.sans = []

    except socket.timeout:
        info.error = "Connection timed out"
    except ConnectionRefusedError:
        info.error = "Connection refused"
    except ssl.SSLError as exc:
        info.error = f"SSL error: {exc}"
    except OSError as exc:
        info.error = f"OS error: {exc}"
    except Exception as exc:
        info.error = f"Unexpected error: {exc}"

    return info


# ---------------------------------------------------------------------------
# 3. New condition types for the rules engine
# ---------------------------------------------------------------------------
# Add these cases to _condition_matches() in openclaw_scanner/inference.py
#
# These conditions operate on the TLSCertInfo object rather than on
# per-path ProbeObservation objects.

PROPOSED_CERT_CONDITIONS = """
    # In _condition_matches(), add handling for a `tls_cert` context object
    # passed alongside observations:

    if condition_type == "cert_subject_contains":
        needle = condition["value"].lower()
        return tls_cert is not None and tls_cert.subject and needle in tls_cert.subject.lower()

    if condition_type == "cert_issuer_contains":
        needle = condition["value"].lower()
        return tls_cert is not None and tls_cert.issuer and needle in tls_cert.issuer.lower()

    if condition_type == "cert_fingerprint":
        expected = condition["value"].lower()
        return tls_cert is not None and tls_cert.fingerprint_sha256 == expected

    if condition_type == "cert_self_signed":
        expected = condition.get("value", True)
        return tls_cert is not None and tls_cert.self_signed == expected

    if condition_type == "cert_san_contains":
        needle = condition["value"].lower()
        return tls_cert is not None and any(needle in san.lower() for san in tls_cert.sans)

    if condition_type == "cert_pubkey_type":
        expected = condition["value"].upper()
        return tls_cert is not None and tls_cert.pubkey_type == expected
"""


# ---------------------------------------------------------------------------
# 4. Example fingerprint rules using certificate conditions
# ---------------------------------------------------------------------------

EXAMPLE_CERT_RULES = [
    {
        "id": "openclaw-default-cert",
        "family": "openclaw_default_tls_cert",
        "label": "OpenClaw gateway with default self-signed TLS certificate",
        "confidence": 0.91,
        "notes": "Matches gateways presenting the factory-default self-signed cert. "
                 "Replace placeholder values with actual lab-captured data.",
        "all": [
            {
                "type": "cert_self_signed",
                "value": True,
            },
            {
                "type": "cert_subject_contains",
                "value": "openclaw",  # Replace with actual CN/O value from lab capture
            },
        ],
    },
    {
        "id": "openclaw-cert-fingerprint-v2026.1",
        "family": "openclaw_cert_v2026_1",
        "label": "OpenClaw v2026.1.x default TLS certificate fingerprint",
        "confidence": 0.95,
        "notes": "Exact match on the SHA-256 fingerprint of the default cert shipped with 2026.1.x. "
                 "Replace placeholder hash with actual lab-captured fingerprint.",
        "all": [
            {
                "type": "cert_fingerprint",
                "value": "0000000000000000000000000000000000000000000000000000000000000000",
                # ^^^ PLACEHOLDER — replace with real fingerprint from lab
            },
        ],
    },
    {
        "id": "clawdbot-san-local-mdns",
        "family": "clawdbot_local_cert",
        "label": "Clawdbot gateway with .local mDNS SAN in certificate",
        "confidence": 0.85,
        "notes": "Some Clawdbot deployments include the mDNS hostname in the SAN list.",
        "all": [
            {
                "type": "cert_san_contains",
                "value": "clawdbot",
            },
        ],
    },
]


# ---------------------------------------------------------------------------
# 5. Shodan search queries for passive cert-based discovery
# ---------------------------------------------------------------------------

SHODAN_CERT_QUERIES = [
    # Search for certs with OpenClaw in the subject CN
    'ssl.cert.subject.cn:"OpenClaw" port:18789',
    'ssl.cert.subject.cn:"Clawdbot" port:18789',
    'ssl.cert.subject.cn:"Moltbot" port:18789',
    # Search for certs with OpenClaw in the issuer organization
    'ssl.cert.issuer.o:"OpenClaw"',
    # Search for a specific known cert fingerprint (fill from lab)
    # 'ssl.cert.fingerprint:<hex_fingerprint>',
    # Combined: TLS on OpenClaw default port
    'has_ssl:true port:18789',
]
