"""Module 2: Crypto Prober — TLS handshake analysis, certificate inspection, cipher extraction."""

from __future__ import annotations
import ssl
import socket
import asyncio
import asyncio.subprocess
from datetime import datetime, timezone
from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import rsa, ec, dsa, ed25519, ed448

from backend.models import CryptoFingerprint, TLSInfo, CertificateInfo


# Maps OpenSSL cipher names to human-readable components
CIPHER_KEX_MAP = {
    "ECDHE": "ECDHE", "DHE": "DHE", "RSA": "RSA", "DH": "DH",
    "ECDH": "ECDH", "PSK": "PSK", "SRP": "SRP",
}

PQC_KEX_ALGORITHMS = {"ML-KEM-512", "ML-KEM-768", "ML-KEM-1024", "X25519MLKEM768", "KYBER"}
PQC_SIG_ALGORITHMS = {"ML-DSA-44", "ML-DSA-65", "ML-DSA-87", "SLH-DSA-SHA2-128S", "SLH-DSA-SHAKE-128S"}


def _extract_kex(cipher_name: str) -> str:
    """Extract key exchange algorithm from cipher suite name for TLS 1.2."""
    for kex, label in CIPHER_KEX_MAP.items():
        if kex in cipher_name.upper():
            return label
    return "UNKNOWN"


def _extract_auth(cipher_name: str) -> str:
    """Extract authentication algorithm from cipher suite name."""
    upper = cipher_name.upper()
    if "ECDSA" in upper: return "ECDSA"
    if "RSA" in upper: return "RSA"
    if "PSK" in upper: return "PSK"
    return "UNKNOWN"


async def _run_openssl_brief(hostname: str, port: int) -> dict:
    """Run OpenSSL s_client to extract keys and details not easily available in Python's ssl module."""
    info = {"kex": "", "cipher": "", "version": "", "sig": "", "hash": ""}
    try:
        proc = await asyncio.create_subprocess_exec(
            "openssl", "s_client", "-connect", f"{hostname}:{port}", "-brief",
            stdin=asyncio.subprocess.DEVNULL,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.DEVNULL
        )
        stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=5.0)
        output = stdout.decode(errors="ignore")
        for line in output.splitlines():
            line = line.strip()
            if line.startswith("Protocol version:"):
                info["version"] = line.split(":", 1)[1].strip()
            elif line.startswith("Ciphersuite:"):
                info["cipher"] = line.split(":", 1)[1].strip()
            elif line.startswith("Server Temp Key:"):
                info["kex"] = line.split(":", 1)[1].split(",")[0].strip()
            elif line.startswith("Negotiated TLS1.3 group:"):
                info["kex"] = line.split(":", 1)[1].strip()
            elif line.startswith("Signature type:"):
                sig = line.split(":", 1)[1].strip().upper()
                if "ECDSA" in sig: info["sig"] = "ECDSA"
                elif "RSA" in sig: info["sig"] = "RSA"
                else: info["sig"] = sig
            elif line.startswith("Hash used:"):
                info["hash"] = line.split(":", 1)[1].strip()
    except Exception:
        pass
    return info


async def _check_tls_version(hostname: str, port: int, protocol) -> bool:
    """Check if a specific TLS version is supported."""
    try:
        ctx = ssl.SSLContext(protocol)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        fut = asyncio.open_connection(hostname, port, ssl=ctx, server_hostname=hostname)
        reader, writer = await asyncio.wait_for(fut, timeout=5.0)
        writer.close()
        await writer.wait_closed()
        return True
    except Exception:
        return False


def _flatten_name(name: x509.Name) -> str:
    """Flatten x509 Name object into a comma-separated string."""
    parts = []
    for attr in name:
        parts.append(f"{attr.oid._name}={attr.value}")
    return ", ".join(parts)


async def probe_tls(hostname: str, port: int = 443) -> CryptoFingerprint:
    """Perform full TLS handshake and extract cryptographic parameters."""
    fingerprint = CryptoFingerprint()
    tls = TLSInfo()
    cert_info = CertificateInfo()

    # Phase 1: Python SSL basic connection and Certificate extraction
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
                
                # Extract base algorithm for legacy parsing
                for algo in ["AES", "CHACHA20", "3DES", "RC4", "CAMELLIA"]:
                    if algo in cipher[0].upper():
                        tls.cipher_algorithm = algo
                        break

            # Parse Certificate using cryptography
            cert_der = ssl_obj.getpeercert(binary_form=True)
            if cert_der:
                try:
                    parsed = x509.load_der_x509_certificate(cert_der)
                    cert_info.subject = _flatten_name(parsed.subject)
                    cert_info.issuer = _flatten_name(parsed.issuer)
                    cert_info.serial_number = str(parsed.serial_number)
                    cert_info.not_before = parsed.not_valid_before_utc.strftime("%b %d %H:%M:%S %Y %Z").strip()
                    cert_info.not_after = parsed.not_valid_after_utc.strftime("%b %d %H:%M:%S %Y %Z").strip()
                    
                    cert_info.signature_algorithm = parsed.signature_algorithm_oid._name
                    
                    # Expiry logic
                    expiry = parsed.not_valid_after_utc
                    cert_info.days_until_expiry = (expiry - datetime.now(timezone.utc)).days
                    cert_info.is_expired = cert_info.days_until_expiry < 0

                    # Public key extraction
                    pub = parsed.public_key()
                    cert_info.public_key_type = type(pub).__name__.replace("PublicKey", "").replace("_", "")
                    if hasattr(pub, "key_size"):
                        cert_info.public_key_bits = pub.key_size

                    # Subject Alternative Names (SANs)
                    try:
                        ext = parsed.extensions.get_extension_for_class(x509.SubjectAlternativeName)
                        cert_info.san_entries = [name.value for name in ext.value]
                    except x509.ExtensionNotFound:
                        cert_info.san_entries = []
                except Exception:
                    pass

        writer.close()
        await writer.wait_closed()
    except Exception:
        pass

    # Phase 2: OpenSSL CLI for TLS 1.3 Key Exchange and missing cipher parts
    openssl_info = await _run_openssl_brief(hostname, port)
    
    if openssl_info["version"]:
        tls.version = openssl_info["version"]
    if openssl_info["cipher"]:
        tls.cipher_suite = openssl_info["cipher"]

    # In TLS 1.3 the cipher suite doesn't have the KEX. Use OpenSSL info.
    if tls.version == "TLSv1.3":
        tls.key_exchange = openssl_info.get("kex", "UNKNOWN")
        tls.authentication = openssl_info.get("sig", "UNKNOWN")
    else:
        # TLS 1.2 fallback
        tls.key_exchange = _extract_kex(tls.cipher_suite)
        tls.authentication = _extract_auth(tls.cipher_suite)

    # Clean cipher parsing (Encryption + Hash logic)
    if tls.cipher_suite.startswith("TLS_"):
        parts = tls.cipher_suite.split("_")
        tls.cipher_algorithm = "_".join(parts[1:-1])  # e.g. AES_256_GCM
    elif not tls.cipher_algorithm:
        tls.cipher_algorithm = tls.cipher_suite

    # Check TLS version support independently
    t12_check, t13_check = await asyncio.gather(
        _check_tls_version(hostname, port, ssl.PROTOCOL_TLSv1_2),
        _check_tls_version(hostname, port, ssl.PROTOCOL_TLS)  # We just assume defaults handle TLS 1.3 check natively if needed
    )
    tls.supports_tls_1_2 = "TLSv1.2" in tls.version or t12_check
    tls.supports_tls_1_3 = "TLSv1.3" in tls.version

    # PQC detection
    kex_upper = tls.key_exchange.upper()
    sig_upper = cert_info.signature_algorithm.upper() if cert_info.signature_algorithm else ""
    fingerprint.has_pqc_kex = any(pqc in kex_upper for pqc in PQC_KEX_ALGORITHMS)
    fingerprint.has_pqc_signature = any(pqc in sig_upper for pqc in PQC_SIG_ALGORITHMS)
    fingerprint.has_hybrid_mode = "X25519" in kex_upper and fingerprint.has_pqc_kex
    fingerprint.has_forward_secrecy = "DHE" in kex_upper or kex_upper in ("X25519", "X448")

    fingerprint.tls = tls
    fingerprint.certificate = cert_info
    return fingerprint
