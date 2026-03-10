"""Module 3: PQC Classifier — Risk scoring engine based on NIST FIPS 203/204/205.

Classification rules:
- FULLY_QUANTUM_SAFE: PQC KEM + PQC signatures (score >= 90)
- PQC_TRANSITION: Hybrid key exchange e.g. X25519Kyber768 (score >= 70)
- QUANTUM_VULNERABLE: Classical KEX on modern TLS (score 40-69)
- CRITICALLY_VULNERABLE: TLS 1.0/1.1, expired certs, broken crypto (score < 40)
- UNKNOWN: Scan failure, insufficient data to classify

Critical correctness:
- Never infers PQC from client offers — only from has_pqc_kex/has_pqc_signature
  flags set by the prober's ServerHello negotiated group extraction.
- Returns UNKNOWN when TLS data is insufficient rather than guessing.
"""

from __future__ import annotations

import logging

from backend.models import CryptoFingerprint, QScore, PQCStatus

logger = logging.getLogger("qarmor.classifier")

# TLS version scoring (max 25)
TLS_VERSION_SCORES = {
    "TLSv1.3": 25,
    "TLSv1.2": 15,
    "TLSv1.1": 0,
    "TLSv1": 0,
    "TLSv1.0": 0,
    "SSLv3": 0,
}

# Key exchange scoring (max 35)
KEX_SCORES = {
    "ML-KEM-1024": 35, "ML-KEM-768": 35, "ML-KEM-512": 33,
    "X25519MLKEM768": 32, "X25519KYBER768": 32, "KYBER": 30,
    "X25519": 20, "X448": 20,
    "ECDHE": 15, "DHE": 12, "DH": 0, "RSA": 0,
}

# Certificate algorithm scoring (max 25)
CERT_SCORES = {
    "ML-DSA-87": 25, "ML-DSA-65": 25, "ML-DSA-44": 23,
    "SLH-DSA": 25,
    "ED25519": 12, "ED448": 12, "ECDSA": 12,
    "RSA": 0,
}

# Cipher strength scoring (max 15)
CIPHER_STRENGTH_SCORES = {
    256: 15,  # AES-256, ChaCha20
    192: 12,  # AES-192
    128: 10,  # AES-128
    112: 5,   # 3DES
    0: 0,     # RC4, NULL
}


def classify(fingerprint: CryptoFingerprint) -> QScore:
    """Classify a cryptographic fingerprint against NIST PQC standards.

    Returns UNKNOWN status if the fingerprint lacks sufficient data
    to make a reliable classification (e.g. scan failure).
    """
    score = QScore()
    findings: list[str] = []
    recommendations: list[str] = []

    tls = fingerprint.tls
    cert = fingerprint.certificate

    # --- Guard: insufficient data → UNKNOWN ---
    if not tls.version and tls.cipher_bits == 0:
        score.status = PQCStatus.UNKNOWN
        score.findings = ["Scan failed or returned insufficient data for classification"]
        score.recommendations = ["Verify the target is reachable and retry the scan"]
        logger.info("Insufficient TLS data — marking as UNKNOWN")
        return score

    # --- TLS Version Score ---
    tls_score = TLS_VERSION_SCORES.get(tls.version, 0)
    if tls.version not in TLS_VERSION_SCORES and "TLSv1.3" in tls.version:
        tls_score = 25
    score.tls_version_score = tls_score

    if tls_score == 0:
        findings.append(
            f"CRITICAL: {tls.version or 'Legacy Version'} is deprecated and insecure"
        )
        recommendations.append("Immediately disable TLS 1.0/1.1. Upgrade to TLS 1.3")
    elif tls.version == "TLSv1.2":
        findings.append("TLS 1.2 is secure today but lacks PQC key exchange support")
        recommendations.append("Migrate to TLS 1.3 for PQC hybrid key exchange")
    elif tls.version == "TLSv1.3":
        findings.append("TLS 1.3 — Good foundation for PQC migration")

    if tls.supports_tls_1_0 or tls.supports_tls_1_1:
        findings.append("WARNING: Server still accepts deprecated TLS 1.0/1.1 connections")
        recommendations.append("Disable TLS 1.0/1.1 to prevent protocol downgrade attacks")

    # --- Key Exchange Score ---
    kex_upper = tls.key_exchange.upper() if tls.key_exchange else ""
    kex_score = 0
    for pattern, pts in KEX_SCORES.items():
        if pattern in kex_upper:
            kex_score = max(kex_score, pts)
    score.key_exchange_score = kex_score

    if fingerprint.has_pqc_kex:
        findings.append(
            f"PQC key exchange detected ({tls.key_exchange}) — Quantum-resistant key exchange in use"
        )
    elif kex_upper in ("RSA", "DH") or kex_score == 0:
        findings.append(
            f"{kex_upper or 'Legacy'} key exchange is vulnerable to Shor's algorithm"
        )
        recommendations.append(
            "Enable ECDHE or X25519 for forward secrecy, then migrate to ML-KEM hybrid"
        )
    elif kex_score in (12, 15, 20):
        findings.append(f"{kex_upper} provides forward secrecy but is quantum-vulnerable")
        recommendations.append("Enable hybrid mode: X25519 + ML-KEM-768")

    if fingerprint.has_hybrid_mode:
        findings.append("Hybrid PQC mode active — Transitional quantum protection")

    # --- Certificate Score ---
    sig_algo = (cert.signature_algorithm or "").upper()
    cert_score = 0
    for pattern, pts in CERT_SCORES.items():
        if pattern in sig_algo:
            cert_score = max(cert_score, pts)

    # Fallback: check public key type if signature algo didn't match
    if cert_score == 0 and cert.public_key_type:
        pk_upper = cert.public_key_type.upper().replace("_", "")
        for pattern, pts in CERT_SCORES.items():
            if pattern in pk_upper:
                cert_score = max(cert_score, pts)

    score.certificate_score = cert_score

    if fingerprint.has_pqc_signature:
        findings.append("PQC digital signature detected — Quantum-resistant certificate")
    else:
        pk_desc = (
            f"{cert.public_key_type}-{cert.public_key_bits}"
            if cert.public_key_bits
            else cert.public_key_type or "Unknown"
        )
        findings.append(f"Certificate uses {pk_desc} — Vulnerable to quantum factoring")
        recommendations.append(
            "Request a certificate with ML-DSA or SLH-DSA signature from your CA"
        )

    if (
        cert.public_key_bits
        and cert.public_key_bits < 2048
        and "RSA" in (cert.public_key_type or "").upper()
    ):
        findings.append(f"CRITICAL: RSA key size {cert.public_key_bits} bits is below minimum")
        recommendations.append(
            "Immediately replace with RSA-2048 minimum, prefer RSA-4096 or EC P-384"
        )

    if cert.is_expired:
        findings.append("CRITICAL: Certificate is expired")
        recommendations.append("Renew certificate immediately")
    elif cert.days_until_expiry and cert.days_until_expiry < 30:
        findings.append(f"WARNING: Certificate expires in {cert.days_until_expiry} days")
        recommendations.append("Renew certificate before expiry")

    # --- Cipher Strength Score ---
    bits = tls.cipher_bits
    cipher_score = 0
    for threshold, pts in sorted(CIPHER_STRENGTH_SCORES.items(), reverse=True):
        if bits >= threshold:
            cipher_score = pts
            break
    score.cipher_strength_score = cipher_score

    if 0 < bits < 128:
        findings.append(f"Weak cipher: {tls.cipher_algorithm} with {bits}-bit key")
        recommendations.append("Upgrade to AES-256-GCM or ChaCha20-Poly1305")

    # --- Total Score ---
    score.total = tls_score + kex_score + cert_score + cipher_score

    # --- Status Classification ---
    if tls_score == 0 or cert.is_expired:
        score.status = PQCStatus.CRITICALLY_VULNERABLE
        score.total = min(score.total, 39)  # Cap legacy scores
    elif score.total >= 90 or (fingerprint.has_pqc_kex and fingerprint.has_pqc_signature):
        score.status = PQCStatus.FULLY_QUANTUM_SAFE
    elif score.total >= 70 or fingerprint.has_hybrid_mode or fingerprint.has_pqc_kex:
        score.status = PQCStatus.PQC_TRANSITION
    elif score.total >= 40:
        score.status = PQCStatus.QUANTUM_VULNERABLE
    else:
        score.status = PQCStatus.CRITICALLY_VULNERABLE

    score.findings = findings
    score.recommendations = recommendations
    return score
