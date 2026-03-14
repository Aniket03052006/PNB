"""Module 2 — Tri-Mode Cryptographic Prober (Phase 6).

Three independent TLS handshakes per asset:
  Probe A: PQC-capable client hello  (ML-KEM-768 + X25519MLKEM768 groups)
  Probe B: TLS 1.3 classical         (X25519 + secp256r1 groups, no PQC)
  Probe C: TLS 1.2 downgrade attempt (max_version = TLS 1.2)

Design:
- asyncio with semaphore cap (default 20 concurrent probes).
- openssl s_client subprocess for authoritative negotiated-group extraction.
- Python `ssl` + cryptography lib for certificate parsing.
- Partial fingerprint on failure -> UNKNOWN.
- SNI everywhere.  IPv4/IPv6 via socket.getaddrinfo().
- Single if/else at entry point: demo mode returns TriModeFingerprints from demo_data.
"""

from __future__ import annotations

import asyncio
import logging
import socket
import ssl
import time
from datetime import datetime, timezone

from cryptography import x509

from backend.models import (
    AssetType,
    CertificateInfo,
    CryptoFingerprint,
    DiscoveredAsset,
    ProbeProfile,
    TLSInfo,
    TriModeFingerprint,
)

logger = logging.getLogger("qarmor.prober")

# ── PQC algorithm sets ──────────────────────────────────────────────────────

PQC_KEX_ALGORITHMS = {
    "ML-KEM-512", "ML-KEM-768", "ML-KEM-1024",
    "MLKEM512", "MLKEM768", "MLKEM1024",
    "X25519MLKEM768", "X25519KYBER768",
    "KYBER512", "KYBER768", "KYBER1024", "KYBER",
}

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

# ── Concurrency ──────────────────────────────────────────────────────────────

_DEFAULT_CONCURRENCY = 20

# ── Low-level helpers ────────────────────────────────────────────────────────


def _extract_kex(cipher_name: str) -> str:
    for kex, label in CIPHER_KEX_MAP.items():
        if kex in cipher_name.upper():
            return label
    return "UNKNOWN"


def _extract_auth(cipher_name: str) -> str:
    upper = cipher_name.upper()
    if "ECDSA" in upper:
        return "ECDSA"
    if "RSA" in upper:
        return "RSA"
    if "PSK" in upper:
        return "PSK"
    return "UNKNOWN"


def _flatten_name(name: x509.Name) -> str:
    return ", ".join(f"{attr.oid._name}={attr.value}" for attr in name)


def _resolve_host(hostname: str) -> str | None:
    """Resolve hostname to IP, supporting IPv4 and IPv6."""
    try:
        results = socket.getaddrinfo(hostname, None, socket.AF_UNSPEC, socket.SOCK_STREAM)
        for _family, _, _, _, sockaddr in results:
            return sockaddr[0]
    except socket.gaierror:
        pass
    return None


# ── openssl s_client wrapper ─────────────────────────────────────────────────


async def _run_openssl(
    hostname: str,
    port: int,
    *,
    connect_host: str | None = None,
    extra_args: list[str] | None = None,
    timeout: float = 8.0,
) -> dict[str, str]:
    """Run ``openssl s_client -brief`` with optional extra args.

    Returns a dict with keys: kex, cipher, version, sig, hash.
    """
    info: dict[str, str] = {"kex": "", "cipher": "", "version": "", "sig": "", "hash": ""}
    target_host = connect_host or hostname
    cmd = [
        "openssl", "s_client",
        "-connect", f"{target_host}:{port}",
        "-servername", hostname,
        "-brief",
    ]
    if extra_args:
        cmd.extend(extra_args)

    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdin=asyncio.subprocess.DEVNULL,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=timeout)
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
                raw = line.split(":", 1)[1].strip()
                info["kex"] = raw.split(",")[0].strip()
            elif line.startswith("Negotiated TLS1.3 group:"):
                info["kex"] = line.split(":", 1)[1].strip()
            elif line.startswith("Peer signing digest:"):
                info["hash"] = line.split(":", 1)[1].strip()
            elif line.startswith(("Peer signature type:", "Signature type:")):
                sig = line.split(":", 1)[1].strip().upper()
                if "ECDSA" in sig:
                    info["sig"] = "ECDSA"
                elif "RSA" in sig:
                    info["sig"] = "RSA"
                elif "ED25519" in sig:
                    info["sig"] = "ED25519"
                else:
                    info["sig"] = sig
    except asyncio.TimeoutError:
        logger.debug("openssl timed out for %s:%d", hostname, port)
    except FileNotFoundError:
        logger.warning("openssl binary not found")
    except Exception as exc:
        logger.debug("openssl failed for %s:%d: %s", hostname, port, exc)
    return info


# ── Certificate extraction ───────────────────────────────────────────────────


async def _extract_certificate(hostname: str, port: int, connect_host: str | None = None) -> CertificateInfo:
    """Connect via Python ssl, pull the DER cert, parse with cryptography."""
    cert_info = CertificateInfo()
    target_host = connect_host or hostname
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

        fut = asyncio.open_connection(target_host, port, ssl=ctx, server_hostname=hostname)
        reader, writer = await asyncio.wait_for(fut, timeout=10.0)

        ssl_obj = writer.get_extra_info("ssl_object")
        if ssl_obj:
            cert_der = ssl_obj.getpeercert(binary_form=True)
            if cert_der:
                parsed = x509.load_der_x509_certificate(cert_der)
                cert_info.subject = _flatten_name(parsed.subject)
                cert_info.issuer = _flatten_name(parsed.issuer)
                cert_info.serial_number = str(parsed.serial_number)
                cert_info.not_before = parsed.not_valid_before_utc.strftime("%b %d %H:%M:%S %Y %Z").strip()
                cert_info.not_after = parsed.not_valid_after_utc.strftime("%b %d %H:%M:%S %Y %Z").strip()
                cert_info.signature_algorithm = parsed.signature_algorithm_oid._name

                expiry = parsed.not_valid_after_utc
                cert_info.days_until_expiry = (expiry - datetime.now(timezone.utc)).days
                cert_info.is_expired = cert_info.days_until_expiry < 0

                pub = parsed.public_key()
                cert_info.public_key_type = type(pub).__name__.replace("PublicKey", "").replace("_", "")
                if hasattr(pub, "key_size"):
                    cert_info.public_key_bits = pub.key_size

                try:
                    ext = parsed.extensions.get_extension_for_class(x509.SubjectAlternativeName)
                    cert_info.san_entries = [name.value for name in ext.value]
                except x509.ExtensionNotFound:
                    cert_info.san_entries = []

        writer.close()
        await writer.wait_closed()
    except Exception as exc:
        logger.debug("Certificate extraction failed for %s:%d — %s", hostname, port, exc)
    return cert_info


# ── Single-probe execution ───────────────────────────────────────────────────


async def _run_single_probe(
    hostname: str,
    port: int,
    mode: str,
    connect_host: str | None = None,
    extra_args: list[str] | None = None,
) -> ProbeProfile:
    """Execute a single TLS probe via openssl s_client.

    mode: "A" | "B" | "C"
    extra_args: additional openssl s_client args for mode-specific behaviour.

    If the probe with extra_args returns no TLS version or cipher (common when
    the installed openssl/LibreSSL does not support flags like ``-groups``),
    the probe is automatically retried without extra_args.
    """
    profile = ProbeProfile(mode=mode)
    try:
        info = await _run_openssl(hostname, port, connect_host=connect_host, extra_args=extra_args)

        # Fallback: if extra_args caused a silent failure, retry without them
        if extra_args and not info.get("version") and not info.get("cipher"):
            logger.debug(
                "Probe %s with extra_args %s returned empty for %s:%d — retrying plain",
                mode, extra_args, hostname, port,
            )
            info = await _run_openssl(hostname, port, connect_host=connect_host)

        profile.tls_version = info.get("version") or None
        profile.cipher_suite = info.get("cipher") or None
        profile.key_exchange = info.get("kex") or None
        profile.key_exchange_group = info.get("kex") or None
        profile.authentication = info.get("sig") or None

        # Cipher bits heuristic
        if profile.cipher_suite:
            cs = profile.cipher_suite.upper()
            if "256" in cs:
                profile.cipher_bits = 256
            elif "128" in cs:
                profile.cipher_bits = 128
            elif "3DES" in cs:
                profile.cipher_bits = 112

        # Fallback KEX from cipher name when openssl didn't report it
        if not profile.key_exchange and profile.cipher_suite:
            profile.key_exchange = _extract_kex(profile.cipher_suite)
        if not profile.authentication and profile.cipher_suite:
            profile.authentication = _extract_auth(profile.cipher_suite)

    except Exception as exc:
        profile.error = str(exc)
        logger.debug("Probe %s failed for %s:%d — %s", mode, hostname, port, exc)

    return profile


# ── Tri-mode probe ───────────────────────────────────────────────────────────


async def probe_trimode(
    hostname: str,
    port: int = 443,
    asset_type: AssetType = AssetType.WEB,
    ip: str | None = None,
) -> TriModeFingerprint:
    """Execute three TLS probes (A/B/C) against a single host:port.

    Probe A: PQC-capable   — offers ML-KEM-768 + X25519MLKEM768 groups
    Probe B: TLS 1.3       — classical groups only (X25519, secp256r1)
    Probe C: TLS 1.2 only  — max_version forced to TLS 1.2
    """
    t0 = time.monotonic()
    connect_host = ip or hostname

    # Run all 3 probes concurrently
    probe_a_task = _run_single_probe(hostname, port, "A", extra_args=[
        "-groups", "ML-KEM-768:X25519MLKEM768:X25519:secp256r1",
    ])
    probe_b_task = _run_single_probe(hostname, port, "B", extra_args=[
        "-groups", "X25519:secp256r1:secp384r1",
    ])
    probe_c_task = _run_single_probe(hostname, port, "C", extra_args=[
        "-tls1_2",
    ])

    probe_a, probe_b, probe_c = await asyncio.gather(
        probe_a_task, probe_b_task, probe_c_task,
        return_exceptions=False,
    )

    # Certificate (one extraction is enough — shared across probes)
    certificate = await _extract_certificate(hostname, port, connect_host=connect_host)

    elapsed = int((time.monotonic() - t0) * 1000)

    # Enrich probes with cert info
    for p in [probe_a, probe_b, probe_c]:
        if certificate.serial_number:
            p.certificate_serial = certificate.serial_number
        if certificate.signature_algorithm and not p.signature_algorithm:
            p.signature_algorithm = certificate.signature_algorithm
        if certificate.public_key_type and not p.public_key_type:
            p.public_key_type = certificate.public_key_type
        if certificate.public_key_bits and not p.public_key_bits:
            p.public_key_bits = certificate.public_key_bits

    # Determine overall error
    all_errors = [p.error for p in [probe_a, probe_b, probe_c] if p.error]
    error = all_errors[0] if len(all_errors) == 3 else None

    return TriModeFingerprint(
        hostname=hostname,
        port=port,
        asset_type=asset_type,
        ip=ip or _resolve_host(hostname),
        probe_a=probe_a,
        probe_b=probe_b,
        probe_c=probe_c,
        certificate=certificate,
        scan_duration_ms=elapsed,
        error=error,
        mode="live",
    )


# ── Batch scanning with concurrency ─────────────────────────────────────────


async def probe_batch(
    assets: list[DiscoveredAsset],
    *,
    concurrency: int = _DEFAULT_CONCURRENCY,
    demo: bool = False,
) -> list[TriModeFingerprint]:
    """Probe a list of assets with tri-mode scanning.

    Single if/else: demo returns static fingerprints; live runs real probes.
    """
    # ── Demo mode ────────────────────────────────────────────────────────
    if demo:
        from backend.demo_data import DEMO_TRIMODE_FINGERPRINTS
        logger.info("[DEMO] Returning %d pre-built TriModeFingerprints", len(DEMO_TRIMODE_FINGERPRINTS))
        return list(DEMO_TRIMODE_FINGERPRINTS)

    # ── Live mode ────────────────────────────────────────────────────────
    sem = asyncio.Semaphore(concurrency)
    results: list[TriModeFingerprint] = []

    async def _scan(asset: DiscoveredAsset) -> TriModeFingerprint:
        async with sem:
            logger.info("Probing %s:%d …", asset.hostname, asset.port)
            return await probe_trimode(
                hostname=asset.hostname,
                port=asset.port,
                asset_type=asset.asset_type,
                ip=asset.ip,
            )

    fps = await asyncio.gather(
        *[_scan(a) for a in assets],
        return_exceptions=True,
    )

    for i, fp in enumerate(fps):
        if isinstance(fp, Exception):
            logger.error("Probe failed for %s:%d — %s", assets[i].hostname, assets[i].port, fp)
            results.append(TriModeFingerprint(
                hostname=assets[i].hostname,
                port=assets[i].port,
                asset_type=assets[i].asset_type,
                ip=assets[i].ip,
                error=str(fp),
                mode="live",
            ))
        else:
            results.append(fp)

    return results


# ── Legacy compatibility: probe_tls ──────────────────────────────────────────


async def probe_tls(hostname: str, port: int = 443, ip: str | None = None) -> CryptoFingerprint:
    """Legacy single-probe entry point (Phase 1-5 compatibility).

    Runs Probe B (TLS 1.3 classical) and converts to CryptoFingerprint.
    """
    fingerprint = CryptoFingerprint()
    tls = TLSInfo()
    cert_info = CertificateInfo()
    connect_host = ip or hostname

    # Phase 1: Python SSL — basic connection + certificate extraction
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

        fut = asyncio.open_connection(connect_host, port, ssl=ctx, server_hostname=hostname)
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

                    expiry = parsed.not_valid_after_utc
                    cert_info.days_until_expiry = (expiry - datetime.now(timezone.utc)).days
                    cert_info.is_expired = cert_info.days_until_expiry < 0

                    pub = parsed.public_key()
                    cert_info.public_key_type = type(pub).__name__.replace("PublicKey", "").replace("_", "")
                    if hasattr(pub, "key_size"):
                        cert_info.public_key_bits = pub.key_size

                    try:
                        ext = parsed.extensions.get_extension_for_class(x509.SubjectAlternativeName)
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
    openssl_info = await _run_openssl(hostname, port)

    if openssl_info["version"] and not tls.version:
        tls.version = openssl_info["version"]
    if openssl_info["cipher"] and not tls.cipher_suite:
        tls.cipher_suite = openssl_info["cipher"]

    if openssl_info.get("kex"):
        tls.key_exchange = openssl_info["kex"]
        tls.authentication = openssl_info.get("sig", "UNKNOWN")
    elif tls.version == "TLSv1.3":
        tls.key_exchange = "UNKNOWN"
        tls.authentication = openssl_info.get("sig", "UNKNOWN")
    else:
        tls.key_exchange = _extract_kex(tls.cipher_suite)
        tls.authentication = _extract_auth(tls.cipher_suite)

    if tls.cipher_suite.startswith("TLS_"):
        parts = tls.cipher_suite.split("_")
        if len(parts) > 2:
            tls.cipher_algorithm = "_".join(parts[1:-1])
    elif not tls.cipher_algorithm:
        tls.cipher_algorithm = tls.cipher_suite

    tls.supports_tls_1_2 = "TLSv1.2" in tls.version
    tls.supports_tls_1_3 = "TLSv1.3" in tls.version

    kex_upper = tls.key_exchange.upper().replace("-", "").replace("_", "")
    sig_upper = (cert_info.signature_algorithm or "").upper().replace("-", "").replace("_", "")

    fingerprint.has_pqc_kex = any(
        pqc.replace("-", "").replace("_", "") in kex_upper for pqc in PQC_KEX_ALGORITHMS
    )
    fingerprint.has_pqc_signature = any(
        pqc.replace("-", "").replace("_", "") in sig_upper for pqc in PQC_SIG_ALGORITHMS
    )
    fingerprint.has_hybrid_mode = "X25519" in tls.key_exchange.upper() and fingerprint.has_pqc_kex
    fingerprint.has_forward_secrecy = any(
        fs in tls.key_exchange.upper()
        for fs in ("DHE", "ECDHE", "X25519", "X448", "MLKEM", "KYBER")
    )

    fingerprint.tls = tls
    fingerprint.certificate = cert_info
    return fingerprint
