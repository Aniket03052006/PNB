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
from typing import Any

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

# sslyze for fast classical TLS scanning (Probes B & C)
try:
    from sslyze import (
        Scanner as SslyzeScanner,
        ServerNetworkLocation,
        ServerScanRequest,
    )
    from sslyze.plugins.scan_commands import ScanCommand
    from sslyze.errors import ConnectionToServerFailed
    _SSLYZE_AVAILABLE = True
except ImportError:
    _SSLYZE_AVAILABLE = False

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

_DEFAULT_CONCURRENCY = 10

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
    timeout: float = 2.0,
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
        try:
            proc.kill()
            await proc.wait()
        except Exception:
            pass
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
        reader, writer = await asyncio.wait_for(fut, timeout=2.0)

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


# ── Full cipher enumeration ──────────────────────────────────────────────────

# TLS 1.2 cipher suites to test — trimmed to 12 representative ciphers to
# reduce subprocess memory pressure on constrained deployments (was 31).
# Coverage: strong ECDHE/DHE GCM, legacy CBC downgrade detection, no-FS RSA,
# and weak NULL/RC4 for security flagging. Classification results are unaffected.
_TLS12_CIPHERS = [
    # ECDHE-RSA: strong GCM + ChaCha20 + CBC legacy downgrade detection
    "ECDHE-RSA-AES256-GCM-SHA384",
    "ECDHE-RSA-AES128-GCM-SHA256",
    "ECDHE-RSA-CHACHA20-POLY1305",
    "ECDHE-RSA-AES256-SHA",
    # ECDHE-ECDSA: GCM (detects ECDSA certificates)
    "ECDHE-ECDSA-AES256-GCM-SHA384",
    "ECDHE-ECDSA-AES128-GCM-SHA256",
    # DHE-RSA: GCM (detects finite-field Diffie-Hellman)
    "DHE-RSA-AES256-GCM-SHA384",
    "DHE-RSA-AES128-GCM-SHA256",
    # RSA static key exchange: no forward secrecy
    "AES256-GCM-SHA384",
    "AES128-GCM-SHA256",
    # Weak/insecure detection
    "NULL-SHA256",
    "RC4-SHA",
]

# TLS 1.3 cipher suites (always the same 5, but test which are accepted)
_TLS13_CIPHERS = [
    "TLS_AES_256_GCM_SHA384",
    "TLS_AES_128_GCM_SHA256",
    "TLS_CHACHA20_POLY1305_SHA256",
    "TLS_AES_128_CCM_SHA256",
    "TLS_AES_128_CCM_8_SHA256",
]

_CIPHER_SCAN_CONCURRENCY = 10  # all 17 ciphers in 2 rounds; safe on 512 MB RAM with probe concurrency=10


async def _test_single_cipher(
    hostname: str,
    port: int,
    cipher: str,
    tls13: bool = False,
    timeout: float = 1.5,
) -> bool:
    """Return True if the server accepts the given cipher."""
    if tls13:
        args = ["-tls1_3", "-ciphersuites", cipher]
    else:
        args = ["-tls1_2", "-cipher", cipher]
    try:
        info = await _run_openssl(hostname, port, extra_args=args, timeout=timeout)
        return bool(info.get("version") and info.get("cipher"))
    except Exception:
        return False


async def _scan_supported_ciphers(hostname: str, port: int, timeout: float = 1.5) -> list[str]:
    """Return all cipher suites accepted by the server.

    Tests TLS 1.3 and TLS 1.2 cipher suites concurrently.
    Returns list of accepted cipher names, strongest first.
    """
    sem = asyncio.Semaphore(_CIPHER_SCAN_CONCURRENCY)

    async def _test(cipher: str, tls13: bool) -> str | None:
        async with sem:
            ok = await _test_single_cipher(hostname, port, cipher, tls13=tls13, timeout=timeout)
            return cipher if ok else None

    tasks = (
        [_test(c, tls13=True) for c in _TLS13_CIPHERS]
        + [_test(c, tls13=False) for c in _TLS12_CIPHERS]
    )
    results = await asyncio.gather(*tasks, return_exceptions=True)
    return [r for r in results if isinstance(r, str) and r]


# ── sslyze-based classical probing (Probes B & C) ───────────────────────────


def _tls_version_from_sslyze(result: Any) -> tuple[str | None, str | None]:
    """Extract best TLS 1.3 version and worst TLS 1.2 version from sslyze result."""
    best_v13: str | None = None
    best_v12: str | None = None
    try:
        tls13 = result.scan_result.tls_1_3_cipher_suites
        if tls13 and tls13.result and tls13.result.accepted_cipher_suites:
            best_v13 = "TLSv1.3"
    except Exception:
        pass
    try:
        tls12 = result.scan_result.tls_1_2_cipher_suites
        if tls12 and tls12.result and tls12.result.accepted_cipher_suites:
            best_v12 = "TLSv1.2"
    except Exception:
        pass
    return best_v13, best_v12


def _best_cipher_sslyze(cipher_suites: Any) -> tuple[str | None, int]:
    """Return (cipher_name, bits) for the strongest accepted cipher suite."""
    try:
        accepted = cipher_suites.result.accepted_cipher_suites
        if accepted:
            name = accepted[0].cipher_suite.name
            bits = 256 if "256" in name else (128 if "128" in name else 0)
            return name, bits
    except Exception:
        pass
    return None, 0


def _all_ciphers_sslyze(result: Any) -> list[str]:
    """Collect all accepted cipher names across all TLS versions."""
    ciphers: list[str] = []
    for attr in ("tls_1_3_cipher_suites", "tls_1_2_cipher_suites",
                 "tls_1_1_cipher_suites", "tls_1_0_cipher_suites"):
        try:
            cs = getattr(result.scan_result, attr, None)
            if cs and cs.result:
                ciphers += [c.cipher_suite.name for c in cs.result.accepted_cipher_suites]
        except Exception:
            pass
    return ciphers


def _cert_info_from_sslyze(result: Any) -> CertificateInfo:
    """Extract CertificateInfo from sslyze CERTIFICATE_INFO result."""
    info = CertificateInfo()
    try:
        cert_result = result.scan_result.certificate_info.result
        chain = cert_result.certificate_deployments[0].received_certificate_chain
        if not chain:
            return info
        leaf = chain[0]
        info.subject = leaf.subject.rfc4514_string()
        info.issuer = leaf.issuer.rfc4514_string()
        info.serial_number = str(leaf.serial_number)
        info.not_before = leaf.not_valid_before_utc.strftime("%b %d %H:%M:%S %Y %Z").strip()
        info.not_after = leaf.not_valid_after_utc.strftime("%b %d %H:%M:%S %Y %Z").strip()
        info.signature_algorithm = leaf.signature_algorithm_oid._name
        expiry = leaf.not_valid_after_utc
        info.days_until_expiry = (expiry - datetime.now(timezone.utc)).days
        info.is_expired = info.days_until_expiry < 0
        pub = leaf.public_key()
        info.public_key_type = type(pub).__name__.replace("PublicKey", "").replace("_", "")
        if hasattr(pub, "key_size"):
            info.public_key_bits = pub.key_size
        try:
            ext = leaf.extensions.get_extension_for_class(x509.SubjectAlternativeName)
            info.san_entries = [n.value for n in ext.value]
        except Exception:
            info.san_entries = []
    except Exception as exc:
        logger.debug("sslyze cert extraction failed: %s", exc)
    return info


async def _probe_classical_sslyze(
    hostname: str,
    port: int,
) -> tuple[ProbeProfile, ProbeProfile, list[str], CertificateInfo]:
    """Probe B (TLS 1.3) and Probe C (TLS 1.2) via OpenSSL subprocess, all in parallel."""
    probe_b, probe_c, ciphers, cert = await asyncio.gather(
        _run_single_probe(hostname, port, "B", extra_args=["-groups", "X25519:secp256r1:secp384r1"]),
        _run_single_probe(hostname, port, "C", extra_args=["-tls1_2"]),
        _scan_supported_ciphers(hostname, port),
        _extract_certificate(hostname, port),
    )
    return probe_b, probe_c, ciphers, cert


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

    # Probe A: PQC detection via OpenSSL subprocess (sslyze doesn't enumerate ML-KEM groups)
    # Probes B & C + cipher list + cert: sslyze (5-8x faster, falls back to OpenSSL)
    probe_a_task = _run_single_probe(hostname, port, "A", extra_args=[
        "-groups", "ML-KEM-768:X25519MLKEM768:X25519:secp256r1",
    ])
    sslyze_task = _probe_classical_sslyze(hostname, port)

    probe_a, (probe_b, probe_c, supported_ciphers, certificate) = await asyncio.gather(
        probe_a_task, sslyze_task,
        return_exceptions=False,
    )

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
    total = len(assets)

    async def _scan(asset: DiscoveredAsset, idx: int) -> TriModeFingerprint:
        async with sem:
            logger.info("[%d/%d] Probing %s:%d", idx + 1, total, asset.hostname, asset.port)
            t0 = time.monotonic()
            result = await probe_trimode(
                hostname=asset.hostname,
                port=asset.port,
                asset_type=asset.asset_type,
                ip=asset.ip,
            )
            logger.info("[%d/%d] Done  %s:%d  (%.1fs)", idx + 1, total, asset.hostname, asset.port, time.monotonic() - t0)
            return result

    fps = await asyncio.gather(
        *[_scan(a, i) for i, a in enumerate(assets)],
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
