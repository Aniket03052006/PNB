"""Demo Data — Realistic simulated bank asset scan for hackathon demonstration."""

from __future__ import annotations
from datetime import datetime, timedelta, timezone
from backend.models import (
    DiscoveredAsset, AssetType, CryptoFingerprint, TLSInfo, CertificateInfo,
    ScanResult, PQCStatus, ScanSummary, RemediationAction, RemediationPriority,
)
from backend.scanner.classifier import classify
from backend.scanner.label_issuer import issue_label


from typing import Any
def _asset(hostname: str, port: int = 443, asset_type: AssetType = AssetType.WEB, ip: str = "203.0.113.") -> DiscoveredAsset:
    """Shorthand builder for demo assets."""
    return DiscoveredAsset(
        hostname=hostname, ip=f"{ip}{hash(hostname) % 254 + 1}",
        port=port, asset_type=asset_type, discovery_method="demo",
    )


def _tls(version: str, cipher: str, bits: int, kex: str, auth: str, algo: str = "AES") -> TLSInfo:
    return TLSInfo(
        version=version, cipher_suite=cipher, cipher_bits=bits,
        cipher_algorithm=algo, key_exchange=kex, authentication=auth,
        supports_tls_1_0="1.0" in version or "1.1" in version,
        supports_tls_1_1="1.1" in version,
        supports_tls_1_2="1.2" in version or "1.3" in version,
        supports_tls_1_3="1.3" in version,
    )


def _cert(subject: str, issuer: str, sig_algo: str, pk_type: str, pk_bits: int, days_until: int = 365) -> CertificateInfo:
    now = datetime.now(timezone.utc)
    return CertificateInfo(
        subject=subject, issuer=issuer,
        serial_number=f"0x{abs(hash(subject)) & 0xFFFFFFFF:08X}",
        not_before=(now - timedelta(days=90)).strftime("%b %d %H:%M:%S %Y GMT"),
        not_after=(now + timedelta(days=days_until)).strftime("%b %d %H:%M:%S %Y GMT"),
        signature_algorithm=sig_algo, public_key_type=pk_type, public_key_bits=pk_bits,
        san_entries=[subject.split("=")[-1].strip()] if "=" in subject else [subject.strip()],
        is_expired=days_until < 0,
        days_until_expiry=days_until,
    )


DEMO_ASSETS: list[dict[str, Any]] = [
    # --- FULLY QUANTUM SAFE (2 assets) ---
    {
        "asset": _asset("pqc-gateway.demobank.com", asset_type=AssetType.API),
        "tls": _tls("TLSv1.3", "TLS_AES_256_GCM_SHA384", 256, "ML-KEM-768", "ML-DSA-65"),
        "cert": _cert("CN=pqc-gateway.demobank.com", "CN=DigiCert PQC Root CA", "ML-DSA-65", "ML-DSA", 2048, 730),
        "pqc_kex": True, "pqc_sig": True, "hybrid": False,
    },
    {
        "asset": _asset("quantum-safe.demobank.com"),
        "tls": _tls("TLSv1.3", "TLS_AES_256_GCM_SHA384", 256, "ML-KEM-1024", "ML-DSA-87"),
        "cert": _cert("CN=quantum-safe.demobank.com", "CN=GlobalSign PQC CA", "ML-DSA-87", "ML-DSA", 4096, 540),
        "pqc_kex": True, "pqc_sig": True, "hybrid": False,
    },

    # --- PQC TRANSITION / HYBRID (3 assets) ---
    {
        "asset": _asset("api.demobank.com", asset_type=AssetType.API),
        "tls": _tls("TLSv1.3", "TLS_AES_256_GCM_SHA384", 256, "X25519MLKEM768", "ECDSA"),
        "cert": _cert("CN=api.demobank.com", "CN=Let's Encrypt R3", "sha256WithRSAEncryption", "EC", 256, 60),
        "pqc_kex": True, "pqc_sig": False, "hybrid": True,
    },
    {
        "asset": _asset("secure.demobank.com"),
        "tls": _tls("TLSv1.3", "TLS_CHACHA20_POLY1305_SHA256", 256, "X25519MLKEM768", "RSA", "CHACHA20"),
        "cert": _cert("CN=secure.demobank.com", "CN=DigiCert SHA2 Extended Validation", "sha256WithRSAEncryption", "RSA", 4096, 220),
        "pqc_kex": True, "pqc_sig": False, "hybrid": True,
    },
    {
        "asset": _asset("corporate.demobank.com"),
        "tls": _tls("TLSv1.3", "TLS_AES_256_GCM_SHA384", 256, "X25519MLKEM768", "ECDSA"),
        "cert": _cert("CN=corporate.demobank.com", "CN=Comodo RSA Organization CA", "sha384WithRSAEncryption", "EC", 384, 180),
        "pqc_kex": True, "pqc_sig": False, "hybrid": True,
    },

    # --- QUANTUM VULNERABLE (7 assets) ---
    {
        "asset": _asset("www.demobank.com"),
        "tls": _tls("TLSv1.3", "TLS_AES_256_GCM_SHA384", 256, "ECDHE", "RSA"),
        "cert": _cert("CN=www.demobank.com", "CN=DigiCert Global Root G2", "sha256WithRSAEncryption", "RSA", 2048, 400),
        "pqc_kex": False, "pqc_sig": False, "hybrid": False,
    },
    {
        "asset": _asset("netbanking.demobank.com"),
        "tls": _tls("TLSv1.2", "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384", 256, "ECDHE", "RSA"),
        "cert": _cert("CN=netbanking.demobank.com", "CN=GeoTrust RSA CA 2018", "sha256WithRSAEncryption", "RSA", 2048, 300),
        "pqc_kex": False, "pqc_sig": False, "hybrid": False,
    },
    {
        "asset": _asset("mobileapi.demobank.com", asset_type=AssetType.API),
        "tls": _tls("TLSv1.2", "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384", 256, "ECDHE", "ECDSA"),
        "cert": _cert("CN=mobileapi.demobank.com", "CN=DigiCert ECC Extended Validation", "ecdsa-with-SHA384", "EC", 384, 250),
        "pqc_kex": False, "pqc_sig": False, "hybrid": False,
    },
    {
        "asset": _asset("portal.demobank.com"),
        "tls": _tls("TLSv1.2", "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256", 128, "ECDHE", "RSA"),
        "cert": _cert("CN=portal.demobank.com", "CN=Let's Encrypt R3", "sha256WithRSAEncryption", "RSA", 2048, 45),
        "pqc_kex": False, "pqc_sig": False, "hybrid": False,
    },
    {
        "asset": _asset("payments.demobank.com", asset_type=AssetType.API),
        "tls": _tls("TLSv1.2", "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384", 256, "ECDHE", "RSA"),
        "cert": _cert("CN=payments.demobank.com", "CN=Entrust Root CA - G2", "sha256WithRSAEncryption", "RSA", 4096, 500),
        "pqc_kex": False, "pqc_sig": False, "hybrid": False,
    },
    {
        "asset": _asset("developer.demobank.com", asset_type=AssetType.API),
        "tls": _tls("TLSv1.2", "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384", 256, "ECDHE", "RSA"),
        "cert": _cert("CN=developer.demobank.com", "CN=Let's Encrypt R3", "sha256WithRSAEncryption", "RSA", 2048, 80),
        "pqc_kex": False, "pqc_sig": False, "hybrid": False,
    },
    {
        "asset": _asset("cdn.demobank.com"),
        "tls": _tls("TLSv1.3", "TLS_AES_128_GCM_SHA256", 128, "ECDHE", "ECDSA"),
        "cert": _cert("CN=cdn.demobank.com", "CN=Cloudflare Inc ECC CA-3", "ecdsa-with-SHA256", "EC", 256, 320),
        "pqc_kex": False, "pqc_sig": False, "hybrid": False,
    },

    # --- CRITICALLY VULNERABLE (3 assets) ---
    {
        "asset": _asset("legacy-vpn.demobank.com", 1194, AssetType.VPN),
        "tls": _tls("TLSv1.1", "TLS_RSA_WITH_AES_128_CBC_SHA", 128, "RSA", "RSA"),
        "cert": _cert("CN=legacy-vpn.demobank.com", "CN=Internal CA", "sha1WithRSAEncryption", "RSA", 1024, 15),
        "pqc_kex": False, "pqc_sig": False, "hybrid": False,
    },
    {
        "asset": _asset("old-staging.demobank.com", 8443),
        "tls": _tls("TLSv1.0", "TLS_RSA_WITH_3DES_EDE_CBC_SHA", 112, "RSA", "RSA", "3DES"),
        "cert": _cert("CN=old-staging.demobank.com", "CN=Internal Self-Signed", "sha1WithRSAEncryption", "RSA", 1024, -30),
        "pqc_kex": False, "pqc_sig": False, "hybrid": False,
    },
    {
        "asset": _asset("test-api.demobank.com", 8080, AssetType.API),
        "tls": _tls("TLSv1.1", "TLS_RSA_WITH_RC4_128_SHA", 128, "RSA", "RSA", "RC4"),
        "cert": _cert("CN=test-api.demobank.com", "CN=Internal CA", "md5WithRSAEncryption", "RSA", 1024, 700),
        "pqc_kex": False, "pqc_sig": False, "hybrid": False,
    },
    # --- REAL-WORLD TEST CASES (badssl.com) ---
    {
        "asset": _asset("rsa2048.badssl.com"),
        "tls": _tls("TLSv1.2", "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384", 256, "ECDHE", "RSA"),
        "cert": _cert("CN=*.badssl.com", "CN=DigiCert SHA2 Secure Server CA", "sha256WithRSAEncryption", "RSA", 2048, 300),
        "pqc_kex": False, "pqc_sig": False, "hybrid": False,
    },
    {
        "asset": _asset("tls-v1-2.badssl.com"),
        "tls": _tls("TLSv1.2", "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384", 256, "ECDHE", "RSA"),
        "cert": _cert("CN=*.badssl.com", "CN=DigiCert SHA2 Secure Server CA", "sha256WithRSAEncryption", "RSA", 2048, 300),
        "pqc_kex": False, "pqc_sig": False, "hybrid": False,
    },
    {
        "asset": _asset("tls-v1-3.badssl.com"),
        "tls": _tls("TLSv1.3", "TLS_AES_256_GCM_SHA384", 256, "X25519", "RSA"),
        "cert": _cert("CN=*.badssl.com", "CN=DigiCert SHA2 Secure Server CA", "sha256WithRSAEncryption", "RSA", 2048, 300),
        "pqc_kex": False, "pqc_sig": False, "hybrid": False,
    },
    {
        "asset": _asset("example.com"),
        "tls": _tls("TLSv1.3", "TLS_AES_256_GCM_SHA384", 256, "X25519", "ECDSA"),
        "cert": _cert("CN=www.example.org", "CN=DigiCert TLS RSA SHA256 2020 CA1", "sha256WithRSAEncryption", "RSA", 2048, 120),
        "pqc_kex": False, "pqc_sig": False, "hybrid": False,
    },
    {
        "asset": _asset("cloudflare.com"),
        "tls": _tls("TLSv1.3", "TLS_AES_256_GCM_SHA384", 256, "X25519MLKEM768", "ECDSA"),
        "cert": _cert("CN=cloudflare.com", "CN=Cloudflare Inc ECC CA-3", "ecdsa-with-SHA256", "EC", 256, 300),
        "pqc_kex": True, "pqc_sig": False, "hybrid": True,
    },
    # --- UNKNOWN (1 asset — simulated scan failure) ---
    {
        "asset": _asset("internal-legacy.demobank.com", 4433),
        "tls": _tls("", "", 0, "", "", ""),
        "cert": _cert("", "", "", "", 0, 0),
        "pqc_kex": False, "pqc_sig": False, "hybrid": False,
        "scan_failure": True,
    },
]


def generate_demo_results() -> ScanSummary:
    """Generate realistic demo scan results for a fictional bank."""
    results: list[ScanResult] = []

    for entry in DEMO_ASSETS:
        tls_info: TLSInfo = entry["tls"]
        fp = CryptoFingerprint(
            tls=tls_info,
            certificate=entry["cert"],
            has_pqc_kex=entry["pqc_kex"],
            has_pqc_signature=entry["pqc_sig"],
            has_hybrid_mode=entry["hybrid"],
            has_forward_secrecy=tls_info.key_exchange in ("ECDHE", "DHE") or "X25519" in tls_info.key_exchange or "KEM" in tls_info.key_exchange,
        )
        q = classify(fp)

        results.append(ScanResult(
            asset=entry["asset"],
            fingerprint=fp,
            q_score=q,
            scan_duration_ms=150 + (len(entry["asset"].hostname) * 17) % 500,
        ))

    # Count statuses
    counts = {s: 0 for s in PQCStatus}
    total_score = 0
    for r in results:
        counts[r.q_score.status] += 1
        total_score += r.q_score.total

    labels = []
    for r in results:
        label = issue_label(r.asset.hostname, r.asset.port, r.q_score)
        if label:
            labels.append(label)

    remediation = _build_remediation_roadmap(results)

    return ScanSummary(
        total_assets=len(results),
        fully_quantum_safe=counts[PQCStatus.FULLY_QUANTUM_SAFE],
        pqc_transition=counts[PQCStatus.PQC_TRANSITION],
        quantum_vulnerable=counts[PQCStatus.QUANTUM_VULNERABLE],
        critically_vulnerable=counts[PQCStatus.CRITICALLY_VULNERABLE],
        unknown=counts.get(PQCStatus.UNKNOWN, 0),
        average_q_score=round(total_score / len(results), 1) if results else 0.0,
        results=results,
        remediation_roadmap=remediation,
        labels=labels,
    )


def _build_remediation_roadmap(results: list[ScanResult]) -> list[RemediationAction]:
    """Build prioritized remediation actions from scan results."""
    critical = [r for r in results if r.q_score.status == PQCStatus.CRITICALLY_VULNERABLE]
    vulnerable = [r for r in results if r.q_score.status == PQCStatus.QUANTUM_VULNERABLE]
    transition = [r for r in results if r.q_score.status == PQCStatus.PQC_TRANSITION]

    actions = []

    if critical:
        actions.append(RemediationAction(
            priority=RemediationPriority.IMMEDIATE,
            timeframe="0-30 days",
            description="Disable deprecated TLS versions and replace weak keys",
            affected_assets=[f"{r.asset.hostname}:{r.asset.port}" for r in critical],
            specific_actions=[
                "Disable TLS 1.0 and TLS 1.1 on all servers",
                "Replace RSA-1024 keys with RSA-2048 minimum",
                "Remove 3DES and RC4 cipher suites",
                "Renew expired certificates immediately",
                "Replace SHA-1 and MD5 certificate signatures",
            ],
        ))

    vulnerable_tls12 = [r for r in vulnerable if r.fingerprint.tls.version == "TLSv1.2"]
    if vulnerable_tls12:
        actions.append(RemediationAction(
            priority=RemediationPriority.SHORT_TERM,
            timeframe="31-90 days",
            description="Migrate to TLS 1.3 with forward secrecy",
            affected_assets=[f"{r.asset.hostname}:{r.asset.port}" for r in vulnerable_tls12],
            specific_actions=[
                "Upgrade server TLS configuration to support TLS 1.3",
                "Enable ECDHE for forward secrecy on remaining TLS 1.2 connections",
                "Prefer AES-256-GCM over AES-128 cipher suites",
                "Configure server to prefer TLS 1.3 in cipher ordering",
            ],
        ))

    vulnerable_tls13 = [r for r in vulnerable if r.fingerprint.tls.version == "TLSv1.3"]
    if vulnerable_tls13:
        actions.append(RemediationAction(
            priority=RemediationPriority.MEDIUM_TERM,
            timeframe="91-180 days",
            description="Enable PQC hybrid key exchange",
            affected_assets=[f"{r.asset.hostname}:{r.asset.port}" for r in vulnerable_tls13],
            specific_actions=[
                "Enable X25519+ML-KEM-768 hybrid key exchange (supported in OpenSSL 3.2+)",
                "Test hybrid handshake compatibility with clients",
                "Request ML-DSA certificate from CA when available",
                "Monitor NIST post-quantum algorithm implementations in your TLS library",
            ],
        ))

    if transition:
        actions.append(RemediationAction(
            priority=RemediationPriority.STRATEGIC,
            timeframe="180-365 days",
            description="Complete PQC migration to full ML-KEM + ML-DSA",
            affected_assets=[f"{r.asset.hostname}:{r.asset.port}" for r in transition],
            specific_actions=[
                "Replace hybrid key exchange with pure ML-KEM-768 or ML-KEM-1024",
                "Deploy ML-DSA certificates for all services",
                "Update JWT signing to use ML-DSA algorithms",
                "Validate end-to-end quantum safety with full PQC stack",
            ],
        ))

    return actions
