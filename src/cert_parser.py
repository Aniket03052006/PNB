"""
Q-ARMOR Phase 1 — X.509 Certificate Parser.

Takes the raw DER-encoded leaf certificate returned by the prober and
extracts human-readable metadata using the ``cryptography`` library.

Extracted fields
----------------
* Subject & Issuer  (e.g. ``CN=example.com, O=Acme Inc``)
* Validity window  (``not_valid_before`` / ``not_valid_after``)
* Public-key algorithm & size  (e.g. RSA-2048, EllipticCurve-256)
* Signature algorithm  (e.g. ``sha256WithRSAEncryption``)
* Subject Alternative Names  (SAN list)
* Expiry status & days remaining
* Self-signed detection
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Optional

from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import (
    dsa,
    ec,
    ed448,
    ed25519,
    rsa,
)
from cryptography.x509.oid import NameOID

from src.models import CertificateMetadata


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _flatten_x509_name(name: x509.Name) -> str:
    """Convert an ``x509.Name`` to a human-readable comma-separated string.

    Example output::

        CN=example.com, O=Acme Inc, L=Mumbai, ST=Maharashtra, C=IN
    """
    parts: list[str] = []
    for attr in name:
        oid_name = attr.oid._name          # e.g. "commonName"
        # Use the short RFC label (CN, O, OU…) when available
        short = _OID_SHORT.get(oid_name, oid_name)
        parts.append(f"{short}={attr.value}")
    return ", ".join(parts)


_OID_SHORT: dict[str, str] = {
    "commonName":             "CN",
    "organizationName":       "O",
    "organizationalUnitName": "OU",
    "countryName":            "C",
    "stateOrProvinceName":    "ST",
    "localityName":           "L",
    "serialNumber":           "SERIALNUMBER",
    "emailAddress":           "EMAIL",
    "domainComponent":        "DC",
}


def _key_algorithm_label(pub_key: object) -> str:
    """Return a human-readable label for the public-key algorithm."""
    if isinstance(pub_key, rsa.RSAPublicKey):
        return "RSA"
    if isinstance(pub_key, ec.EllipticCurvePublicKey):
        return "EllipticCurve"
    if isinstance(pub_key, dsa.DSAPublicKey):
        return "DSA"
    if isinstance(pub_key, ed25519.Ed25519PublicKey):
        return "Ed25519"
    if isinstance(pub_key, ed448.Ed448PublicKey):
        return "Ed448"
    return type(pub_key).__name__


def _key_size(pub_key: object) -> int:
    """Return the key size in bits (0 when not applicable)."""
    if hasattr(pub_key, "key_size"):
        return pub_key.key_size              # RSA, DSA
    if isinstance(pub_key, ec.EllipticCurvePublicKey):
        return pub_key.curve.key_size        # e.g. 256, 384
    if isinstance(pub_key, ed25519.Ed25519PublicKey):
        return 256
    if isinstance(pub_key, ed448.Ed448PublicKey):
        return 448
    return 0


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def parse_certificate(cert_der: bytes) -> CertificateMetadata:
    """Parse a DER-encoded X.509 certificate into a ``CertificateMetadata``.

    Parameters
    ----------
    cert_der : bytes
        Raw DER-encoded certificate (as returned by
        ``ssl_sock.getpeercert(binary_form=True)``).

    Returns
    -------
    CertificateMetadata
        Populated dataclass with all extracted fields.

    Raises
    ------
    ValueError
        If the certificate cannot be decoded.
    """
    try:
        cert = x509.load_der_x509_certificate(cert_der)
    except Exception as exc:
        raise ValueError(f"Failed to parse DER certificate: {exc}") from exc

    meta = CertificateMetadata()

    # ---- Subject / Issuer -------------------------------------------------
    meta.subject = _flatten_x509_name(cert.subject)
    meta.issuer = _flatten_x509_name(cert.issuer)
    meta.serial_number = format(cert.serial_number, "X")  # hex string

    # ---- Self-signed detection -------------------------------------------
    meta.is_self_signed = (cert.subject == cert.issuer)

    # ---- Validity window --------------------------------------------------
    # Use UTC-aware accessors (available since cryptography ≥ 42.x)
    try:
        nb = cert.not_valid_before_utc
        na = cert.not_valid_after_utc
    except AttributeError:
        # Fallback for older cryptography versions
        nb = cert.not_valid_before.replace(tzinfo=timezone.utc)
        na = cert.not_valid_after.replace(tzinfo=timezone.utc)

    meta.not_valid_before = nb.strftime("%Y-%m-%dT%H:%M:%SZ")
    meta.not_valid_after = na.strftime("%Y-%m-%dT%H:%M:%SZ")

    now = datetime.now(timezone.utc)
    delta = na - now
    meta.days_until_expiry = delta.days
    meta.is_expired = delta.total_seconds() < 0

    # ---- Public-key info --------------------------------------------------
    pub_key = cert.public_key()
    meta.public_key_algorithm = _key_algorithm_label(pub_key)
    meta.public_key_size = _key_size(pub_key)

    # ---- Signature algorithm ----------------------------------------------
    sig_oid = cert.signature_algorithm_oid
    meta.signature_algorithm = sig_oid._name if sig_oid else ""

    try:
        sig_hash = cert.signature_hash_algorithm
        meta.signature_hash_algorithm = sig_hash.name if sig_hash else ""
    except Exception:
        meta.signature_hash_algorithm = ""

    # ---- Subject Alternative Names (SANs) ---------------------------------
    try:
        san_ext = cert.extensions.get_extension_for_class(
            x509.SubjectAlternativeName
        )
        meta.subject_alternative_names = sorted(
            {dns.value for dns in san_ext.value.get_values_for_type(x509.DNSName)}
        )
    except x509.ExtensionNotFound:
        meta.subject_alternative_names = []
    except Exception:
        meta.subject_alternative_names = []

    return meta
