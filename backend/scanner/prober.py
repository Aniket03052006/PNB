"""Module 2: Crypto Prober — TLS handshake analysis, certificate inspection, cipher extraction.

Design decisions:
- Uses openssl s_client subprocess for deterministic extraction of the
  negotiated key exchange group (ServerHello), which Python's ssl module
  does not expose.
- Never infers PQC from client offers — only from the Server Temp Key /
  Negotiated TLS1.3 group.
- Returns a partial fingerprint on failure rather than raising, so callers
  can classify the result as UNKNOWN.
- Supports SNI and falls back to IPv6 via socket.getaddrinfo().
"""

from __future__ import annotations

import logging
import ssl
import socket
import asyncio
from datetime import datetime, timezone
from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import rsa, ec, dsa, ed25519, ed448

from backend.models import CryptoFingerprint, TLSInfo, CertificateInfo

logger = logging.getLogger("qarmor.prober")

# Known PQC key exchange algorithms (only from ServerHello negotiated group)
PQC_KEX_ALGORITHMS = {
    "ML-KEM-512", "ML-KEM-768", "ML-KEM-1024",
    "MLKEM512", "MLKEM768", "MLKEM1024",
    "X25519MLKEM768", "X25519KYBER768",
    "KYBER512", "KYBER768", "KYBER1024",
    "KYBER",
}

# PQC signature algorithms (from certificate)
PQC_SIG_ALGORITHMS = {
    "ML-DSA-44", "ML-DSA-65", "ML-DSA-87",
    "SLH-DSA-SHA2-128S", "SLH-DSA-SHAKE-128S",
    "MLDSA44", "MLDSA65", "MLDSA87",
}

# Maps cipher name fragments to key exchange algorithm
CIPHER_KEX_MAP = {
    "ECDHE": "ECDHE", "DHE": "DHE", "RSA": "RSA", "DH": "DH",
    "ECDH": "ECDH", "PSK": "PSK", "SRP": "SRP",
}


def _extract_kex(cipher_name: str) -> str:
    """Extract key exchange from cipher suite name (TLS 1.2 fallback)."""
    for kex, label in CIPHER_KEX_MAP.items():
        if kex in cipher_name.upper():
            return label
    return "UNKNOWN"


def _extract_auth(cipher_name: str) -> str:
    """Extract authentication algorithm from cipher suite name."""
    upper = cipher_name.upper()
    if "ECDSA" in upper:
        return "ECDSA"
    if "RSA" in upper:
        return "RSA"
    if "PSK" in upper:
        return "PSK"
    return "UNKNOWN"


async def _run_openssl_brief(hostname: str, port: int) -> dict:
    """Run openssl s_client -brief to extract the negotiated key exchange group.

    This is the authoritative source for the ServerHello negotiated group,
    which Python's ssl module does not expose.
    """
    info = {"kex": "", "cipher": "", "version": "", "sig": "", "hash": ""}
    try:
        proc = await asyncio.create_subprocess_exec(
            "openssl", "s_client",
            "-connect", f"{hostname}:{port}",
            "-servername", hostname,  # SNI
            "-brief",
            stdin=asyncio.subprocess.DEVNULL,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=8.0)
        output = stdout.decode(errors="ignore") + "\n" + stderr.decode(errors="ignore")

        for line in output.splitlines():
            line = line.strip()
            if not line:
                continue

            if line.startswith("Protocol version:"):
                info["version"] = line.split(":", 1)[1].strip()
            elif line.startswith("Ciphersuite:"):
                info["cipher"] = line.split(":", 1)[1].strip()
            elif line.startswith("Server Temp Key:"):
                # e.g. "Server Temp Key: X25519, 253 bits"
                # or "Server Temp Key: ECDH, P-256, 256 bits"
                raw = line.split(":", 1)[1].strip()
                info["kex"] = raw.split(",")[0].strip()
            elif line.startswith("Negotiated TLS1.3 group:"):
                # Authoritative group for TLS 1.3
                info["kex"] = line.split(":", 1)[1].strip()
            elif line.startswith("Peer signing digest:"):
                info["hash"] = line.split(":", 1)[1].strip()
            elif line.startswith("Peer signature type:") or line.startswith("Signature type:"):
                sig = line.split(":", 1)[1].strip().upper()
                if "ECDSA" in sig:
                    info["sig"] = "ECDSA"
                elif "RSA" in sig:
                    info["sig"] = "RSA"
                elif "ED25519" in sig:
                    info["sig"] = "ED25519"
                else:
                    info["sig"] = sig

        logger.debug("openssl s_client result for %s:%d — %s", hostname, port, info)
    except asyncio.TimeoutError:
        logger.warning("openssl s_client timed out for %s:%d", hostname, port)
    except FileNotFoundError:
        logger.warning("openssl binary not found — key exchange detection limited")
    except Exception as exc:
        logger.debug("openssl s_client failed for %s:%d: %s", hostname, port, exc)
    return info


async def _check_tls_version_supported(hostname: str, port: int, min_ver, max_ver) -> bool:
    """Check if a specific TLS version range is supported by the server."""
    try:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        ctx.minimum_version = min_ver
        ctx.maximum_version = max_ver

        fut = asyncio.open_connection(hostname, port, ssl=ctx, server_hostname=hostname)
        reader, writer = await asyncio.wait_for(fut, timeout=5.0)
        writer.close()
        await writer.wait_closed()
        return True
    except Exception:
        return False


def _flatten_name(name: x509.Name) -> str:
    """Flatten x509 Name object into a comma-separated string."""
    return ", ".join(f"{attr.oid._name}={attr.value}" for attr in name)


def _resolve_host(hostname: str) -> str | None:
    """Resolve hostname to IP, supporting both IPv4 and IPv6."""
    try:
        results = socket.getaddrinfo(hostname, None, socket.AF_UNSPEC, socket.SOCK_STREAM)
        for family, _, _, _, sockaddr in results:
            return sockaddr[0]  # Return first resolved IP
    except socket.gaierror:
        pass
    return None


async def probe_tls(hostname: str, port: int = 443) -> CryptoFingerprint:
    """Perform full TLS handshake and extract cryptographic parameters.

    Returns a CryptoFingerprint with whatever data could be extracted.
    On complete failure, returns a mostly-empty fingerprint — the caller
    (classifier) will mark this as UNKNOWN status.
    """
    fingerprint = CryptoFingerprint()
    tls = TLSInfo()
    cert_info = CertificateInfo()

    # Phase 1: Python SSL — basic connection + certificate extraction
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

        fut = asyncio.open_connection(hostname, port, ssl=ctx, server_hostname=hostname)
        reader, writer = await asyncio.wait_for(fut, timeout=10.0)

        ssl_obj = writer.get_extra_info("ssl_object")
        if ssl_obj:
            tls.version = ssl_obj.version() or ""
            cipher = ssl_obj.cipher()
            if cipher:
                tls.cipher_suite = cipher[0]
                tls.cipher_bits = cipher[2] if len(cipher) > 2 else 0

                for algo in ["AES", "CHACHA20", "3DES", "RC4", "CAMELLIA"]:
                    if algo in cipher[0].upper():
                        tls.cipher_algorithm = algo
                        break

            # Parse certificate
            cert_der = ssl_obj.getpeercert(binary_form=True)
            if cert_der:
                try:
                    parsed = x509.load_der_x509_certificate(cert_der)
                    cert_info.subject = _flatten_name(parsed.subject)
                    cert_info.issuer = _flatten_name(parsed.issuer)
                    cert_info.serial_number = str(parsed.serial_number)
                    cert_info.not_before = parsed.not_valid_before_utc.strftime(
                        "%b %d %H:%M:%S %Y %Z"
                    ).strip()
                    cert_info.not_after = parsed.not_valid_after_utc.strftime(
                        "%b %d %H:%M:%S %Y %Z"
                    ).strip()

                    cert_info.signature_algorithm = parsed.signature_algorithm_oid._name

                    expiry = parsed.not_valid_after_utc
                    cert_info.days_until_expiry = (expiry - datetime.now(timezone.utc)).days
                    cert_info.is_expired = cert_info.days_until_expiry < 0

                    pub = parsed.public_key()
                    cert_info.public_key_type = (
                        type(pub).__name__.replace("PublicKey", "").replace("_", "")
                    )
                    if hasattr(pub, "key_size"):
                        cert_info.public_key_bits = pub.key_size

                    try:
                        ext = parsed.extensions.get_extension_for_class(
                            x509.SubjectAlternativeName
                        )
                        cert_info.san_entries = [name.value for name in ext.value]
                    except x509.ExtensionNotFound:
                        cert_info.san_entries = []
                except Exception as exc:
                    logger.debug("Certificate parse error for %s:%d — %s", hostname, port, exc)

        writer.close()
        await writer.wait_closed()
    except Exception as exc:
        logger.warning("TLS connection failed for %s:%d — %s", hostname, port, exc)

    # Phase 2: openssl s_client — authoritative key exchange group
    openssl_info = await _run_openssl_brief(hostname, port)

    if openssl_info["version"] and not tls.version:
        tls.version = openssl_info["version"]
    if openssl_info["cipher"] and not tls.cipher_suite:
        tls.cipher_suite = openssl_info["cipher"]

    # Key exchange: openssl is authoritative for the ServerHello negotiated group
    if openssl_info.get("kex"):
        tls.key_exchange = openssl_info["kex"]
        tls.authentication = openssl_info.get("sig", "UNKNOWN")
    elif tls.version == "TLSv1.3":
        tls.key_exchange = "UNKNOWN"
        tls.authentication = openssl_info.get("sig", "UNKNOWN")
    else:
        # TLS 1.2 fallback — derive from cipher suite name
        tls.key_exchange = _extract_kex(tls.cipher_suite)
        tls.authentication = _extract_auth(tls.cipher_suite)

    # Cipher algorithm extraction
    if tls.cipher_suite.startswith("TLS_"):
        parts = tls.cipher_suite.split("_")
        if len(parts) > 2:
            tls.cipher_algorithm = "_".join(parts[1:-1])  # e.g. AES_256_GCM
    elif not tls.cipher_algorithm:
        tls.cipher_algorithm = tls.cipher_suite

    # Check TLS version support (using modern API with min/max version)
    try:
        tls12_supported = await _check_tls_version_supported(
            hostname, port, ssl.TLSVersion.TLSv1_2, ssl.TLSVersion.TLSv1_2
        )
        tls.supports_tls_1_2 = "TLSv1.2" in tls.version or tls12_supported
    except Exception:
        tls.supports_tls_1_2 = "TLSv1.2" in tls.version

    tls.supports_tls_1_3 = "TLSv1.3" in tls.version

    # PQC detection — strictly from the negotiated group, not from client offers
    kex_upper = tls.key_exchange.upper().replace("-", "").replace("_", "")
    sig_upper = cert_info.signature_algorithm.upper().replace("-", "").replace("_", "") if cert_info.signature_algorithm else ""

    fingerprint.has_pqc_kex = any(
        pqc.replace("-", "").replace("_", "") in kex_upper for pqc in PQC_KEX_ALGORITHMS
    )
    fingerprint.has_pqc_signature = any(
        pqc.replace("-", "").replace("_", "") in sig_upper for pqc in PQC_SIG_ALGORITHMS
    )
    fingerprint.has_hybrid_mode = (
        "X25519" in tls.key_exchange.upper() and fingerprint.has_pqc_kex
    )
    fingerprint.has_forward_secrecy = any(
        fs in tls.key_exchange.upper()
        for fs in ("DHE", "ECDHE", "X25519", "X448", "MLKEM", "KYBER")
    )

    fingerprint.tls = tls
    fingerprint.certificate = cert_info
    return fingerprint
