"""Module 3 — PQC Classifier v7 (Phase 7: Tri-Mode Classification + Agility).

Scoring dimensions (max 100)
────────────────────────────
  TLS Version        … max 20
  Key Exchange       … max 30
  Certificate        … max 20
  Cipher Strength    … max 15
  Crypto Agility     … max 15   ← NEW in Phase 7

Phase 7 additions
─────────────────
  • classify_trimode(TriModeFingerprint) → ClassifiedAsset
      – Computes three Q-Scores from Probes A / B / C
      – Status derived from *worst-case* score
      – Includes one-line plain English summary + recommended action

  • Legacy classify(CryptoFingerprint) → QScore kept for backward compat.

Status thresholds (from negotiated posture)
───────────────────────────────────────────
  FULLY_QUANTUM_SAFE     : TLS 1.3 everywhere + PQC KEX + PQC cert + strong worst-case score
  PQC_TRANSITION         : TLS 1.3 with ML-KEM or hybrid PQC path, but classical cert and/or downgrade exposure remains
  QUANTUM_VULNERABLE     : classical crypto only, but no immediately-broken legacy protocol
  CRITICALLY_VULNERABLE  : weak or legacy transport posture
  UNKNOWN                : probe failure
"""

from __future__ import annotations

import logging
from typing import Any

from backend.models import (
    ClassifiedAsset,
    CryptoFingerprint,
    PQCStatus,
    ProbeProfile,
    QScore,
    TriModeFingerprint,
)

logger = logging.getLogger("qarmor.classifier")

# ═══════════════════════════════════════════════════════════════════════════
# Phase 7 scoring tables
# ═══════════════════════════════════════════════════════════════════════════

# TLS version scoring (max 20)
TLS_VERSION_SCORES_V7 = {
    "TLSv1.3": 20,
    "TLSv1.2": 10,
    "TLSv1.1": 2,
    "TLSv1":   0,
    "TLSv1.0": 0,
    "SSLv3":   0,
    "SSLv2":   0,
}

# Key exchange scoring (max 30)
KEX_SCORES_V7 = {
    "ML-KEM-1024": 30, "ML-KEM-768": 30, "ML-KEM-512": 28,
    "X25519MLKEM768": 24, "X25519KYBER768": 24, "X448MLKEM1024": 24,
    "SECP256R1MLKEM768": 24, "0X11EC": 24,
    "KYBER": 22,
    "ECDHE": 12, "X25519": 12, "X448": 12,
    "DHE": 6, "DH": 0, "RSA": 0,
}

# Certificate algorithm scoring (max 20)
CERT_SCORES_V7 = {
    "ML-DSA-87": 20, "ML-DSA-65": 20, "ML-DSA-44": 20,
    "SLH-DSA": 20,
    "ECDSA-P384": 12, "ECDSA-P521": 12, "ED448": 12,
    "ECDSA-P256": 8,  "ECDSA": 8,  "ED25519": 8,
    "RSA-4096": 6, "RSA-2048": 4, "RSA-1024": 0, "RSA": 4,
}

# Cipher strength scoring (max 15)
CIPHER_STRENGTH_SCORES_V7 = {
    256: 15,  # AES-256-GCM, ChaCha20-Poly1305
    192: 10,  # AES-192
    128: 10,  # AES-128-GCM
    112: 0,   # 3DES
    0: 0,     # NULL / RC4
}

# PQC algorithm name fragments for detection
_PQC_KEX_NAMES = frozenset({"ML-KEM", "MLKEM", "KYBER"})
_PQC_SIG_NAMES = frozenset({"ML-DSA", "MLDSA", "SLH-DSA", "SLHDSA"})
_HYBRID_KEX = frozenset({"X25519MLKEM768", "X25519KYBER768", "X448MLKEM1024", "SECP256R1MLKEM768", "0X11EC"})
_LEGACY_TLS_VERSIONS = frozenset({"TLSV1.1", "TLSV1", "TLSV1.0", "SSLV3", "SSLV2"})


def _norm_alg(value: str | None) -> str:
    return str(value or "").upper().replace("-", "").replace("_", "").replace(" ", "").replace(".", "")


def _matches_any(value: str | None, patterns: set[str] | frozenset[str]) -> bool:
    norm = _norm_alg(value)
    return any(_norm_alg(pattern) in norm for pattern in patterns)


def _is_tls13_version(value: str | None) -> bool:
    return "13" in _norm_alg(value)


def _is_legacy_tls_version(value: str | None) -> bool:
    norm = _norm_alg(value)
    return norm in _LEGACY_TLS_VERSIONS or "11" in norm or norm.startswith("SSL")


def _is_hybrid_kex_name(value: str | None) -> bool:
    return _matches_any(value, _HYBRID_KEX)


def _is_pqc_kex_name(value: str | None) -> bool:
    norm = _norm_alg(value)
    if not norm:
        return False
    if _is_hybrid_kex_name(norm):
        return True
    return _matches_any(norm, _PQC_KEX_NAMES)


def _is_pqc_sig_name(*values: str | None) -> bool:
    return any(_matches_any(value, _PQC_SIG_NAMES) for value in values if value)


def _resolve_kex_score(kex_raw: str) -> int:
    best = 0
    for pattern, points in KEX_SCORES_V7.items():
        if _norm_alg(pattern) in kex_raw:
            best = max(best, points)
    return best


# ═══════════════════════════════════════════════════════════════════════════
# Phase 7: score a single probe profile
# ═══════════════════════════════════════════════════════════════════════════

def _score_probe(probe: ProbeProfile, agility: int = 0) -> QScore:
    """Score a single ProbeProfile → QScore (Phase 7 scale: max 100)."""
    score = QScore()
    findings: list[str] = []
    recommendations: list[str] = []

    if probe.error or (not probe.tls_version and (probe.cipher_bits or 0) == 0):
        score.status = PQCStatus.UNKNOWN
        score.findings = [f"Probe {probe.mode} failed: {probe.error or 'no data'}"]
        score.recommendations = ["Verify connectivity and retry"]
        return score

    # ── TLS Version ────────────────────────────────────────────────────
    tls_v = probe.tls_version or ""
    tls_score = TLS_VERSION_SCORES_V7.get(tls_v, 0)
    if not tls_score and "1.3" in tls_v:
        tls_score = 20
    score.tls_version_score = tls_score

    if tls_score <= 2:
        findings.append(f"CRITICAL: {tls_v or 'unknown'} is deprecated")
        recommendations.append("Upgrade to TLS 1.3 immediately")
    elif tls_v == "TLSv1.2":
        findings.append("TLS 1.2 cannot negotiate PQC key exchange natively")
        recommendations.append("Migrate to TLS 1.3 for PQC support")
    else:
        findings.append("TLS 1.3 — PQC extension support available")

    # ── Key Exchange ───────────────────────────────────────────────────
    kex_display = probe.key_exchange or probe.key_exchange_group or ""
    kex_raw = _norm_alg(kex_display)
    kex_score = _resolve_kex_score(kex_raw)
    score.key_exchange_score = kex_score

    has_pqc_kex = _is_pqc_kex_name(kex_raw)
    has_hybrid_kex = _is_hybrid_kex_name(kex_raw)

    if has_hybrid_kex:
        findings.append(f"Hybrid PQC key exchange: {kex_display or kex_raw}")
    elif has_pqc_kex:
        findings.append(f"PQC key exchange: {kex_display or kex_raw}")
    elif kex_score == 0:
        findings.append(f"CRITICAL: {kex_display or 'RSA'} key exchange — no forward secrecy, quantum-vulnerable")
        recommendations.append("Enable ECDHE/X25519 then migrate to ML-KEM hybrid")
    else:
        findings.append(f"{kex_display or kex_raw} — quantum-vulnerable but provides forward secrecy")
        recommendations.append("Enable X25519+ML-KEM-768 hybrid key exchange")

    # ── Certificate ────────────────────────────────────────────────────
    sig_algo = (probe.signature_algorithm or "").upper()
    pk_type = (probe.public_key_type or "").upper()
    pk_bits = probe.public_key_bits or 0

    cert_score = 0
    for pattern, pts in CERT_SCORES_V7.items():
        if pattern in sig_algo:
            cert_score = max(cert_score, pts)
    if cert_score == 0:
        if "RSA" in pk_type:
            if pk_bits >= 4096:
                cert_score = 6
            elif pk_bits >= 2048:
                cert_score = 4
            else:
                cert_score = 0
        elif "EC" in pk_type or "ECDSA" in pk_type:
            cert_score = 12 if pk_bits >= 384 else 8
        for pattern, pts in CERT_SCORES_V7.items():
            if pattern.replace("-", "") in pk_type.replace("-", ""):
                cert_score = max(cert_score, pts)

    score.certificate_score = cert_score

    has_pqc_sig = _is_pqc_sig_name(sig_algo, pk_type)
    if has_pqc_sig:
        findings.append("PQC digital signature — quantum-resistant certificate")
    else:
        findings.append(f"Classical certificate ({pk_type or sig_algo or 'UNKNOWN'}-{pk_bits}) — quantum-vulnerable")
        recommendations.append("Request ML-DSA or SLH-DSA certificate from CA")

    # ── Cipher Strength ────────────────────────────────────────────────
    bits = probe.cipher_bits or 0
    cipher_score = 0
    for threshold, pts in sorted(CIPHER_STRENGTH_SCORES_V7.items(), reverse=True):
        if bits >= threshold:
            cipher_score = pts
            break
    score.cipher_strength_score = cipher_score

    if 0 < bits < 128:
        findings.append(f"Weak cipher: {probe.cipher_suite} ({bits}-bit)")
        recommendations.append("Upgrade to AES-256-GCM or ChaCha20-Poly1305")

    # ── Agility ────────────────────────────────────────────────────────
    score.agility_score = agility

    # ── Total ──────────────────────────────────────────────────────────
    score.total = tls_score + kex_score + cert_score + cipher_score + agility

    score.findings = findings
    score.recommendations = recommendations
    return score


def _determine_probe_status(
    probe_q: QScore,
    probe: ProbeProfile,
    *,
    cert_sig: str = "",
    cert_pk: str = "",
) -> PQCStatus:
    """Classify one probe path using negotiated algorithms plus certificate posture."""
    if probe_q.status == PQCStatus.UNKNOWN:
        return PQCStatus.UNKNOWN

    tls_version = probe.tls_version or ""
    kex_name = probe.key_exchange or probe.key_exchange_group or ""
    has_tls13 = _is_tls13_version(tls_version)
    has_pqc_kex = _is_pqc_kex_name(kex_name)
    has_pqc_sig = _is_pqc_sig_name(probe.signature_algorithm, probe.public_key_type, cert_sig, cert_pk)

    if has_tls13 and has_pqc_kex and has_pqc_sig and probe_q.total >= 85:
        return PQCStatus.FULLY_QUANTUM_SAFE

    if has_tls13 and has_pqc_kex:
        return PQCStatus.PQC_TRANSITION

    # Slightly lenient transition posture: modern TLS 1.3 with forward secrecy
    # and a reasonable score is treated as transitional readiness.
    has_forward_secrecy = probe_q.key_exchange_score >= 12
    if has_tls13 and has_forward_secrecy and probe_q.total >= 55:
        return PQCStatus.PQC_TRANSITION

    if probe_q.total < 30 or _is_legacy_tls_version(tls_version):
        return PQCStatus.CRITICALLY_VULNERABLE

    if probe_q.total >= 30:
        return PQCStatus.QUANTUM_VULNERABLE

    return PQCStatus.CRITICALLY_VULNERABLE


def _determine_asset_status(
    best_q: QScore,
    typical_q: QScore,
    worst_q: QScore,
    fp: TriModeFingerprint,
) -> PQCStatus:
    """Derive overall asset posture from all three probes plus certificate metadata."""
    if all(q.status == PQCStatus.UNKNOWN for q in (best_q, typical_q, worst_q)):
        return PQCStatus.UNKNOWN

    probes = [fp.probe_a, fp.probe_b, fp.probe_c]
    cert_sig = fp.certificate.signature_algorithm or fp.probe_a.signature_algorithm or fp.probe_b.signature_algorithm or fp.probe_c.signature_algorithm or ""
    cert_pk = fp.certificate.public_key_type or fp.probe_a.public_key_type or fp.probe_b.public_key_type or fp.probe_c.public_key_type or ""

    has_tls13_path = any(_is_tls13_version(probe.tls_version) for probe in probes)
    has_pqc_path = any(_is_pqc_kex_name(probe.key_exchange or probe.key_exchange_group) for probe in probes)
    has_pqc_sig = _is_pqc_sig_name(cert_sig, cert_pk)
    has_forward_secrecy_path = any(q.key_exchange_score >= 12 for q in (best_q, typical_q, worst_q))
    all_legacy = all(
        not (probe.tls_version or probe.cipher_suite or probe.cipher_bits)
        or _is_legacy_tls_version(probe.tls_version)
        for probe in probes
    )

    if has_tls13_path and has_pqc_path and has_pqc_sig and _is_tls13_version(fp.probe_c.tls_version) and worst_q.total >= 85:
        return PQCStatus.FULLY_QUANTUM_SAFE

    # Any ML-KEM / hybrid-capable TLS 1.3 path should be treated as transition posture
    # even if a classical cert or downgrade path still drags the worst-case score down.
    if has_tls13_path and has_pqc_path:
        return PQCStatus.PQC_TRANSITION

    # Lenient transition path for assets that are modernized (TLS 1.3 + forward secrecy)
    # but not yet exposing explicit PQC KEX identifiers in all probe paths.
    if has_tls13_path and has_forward_secrecy_path and max(best_q.total, typical_q.total) >= 55:
        return PQCStatus.PQC_TRANSITION

    if worst_q.total < 30 or all_legacy:
        return PQCStatus.CRITICALLY_VULNERABLE

    return PQCStatus.QUANTUM_VULNERABLE


def _build_summary(hostname: str, status: PQCStatus, best: int, worst: int) -> str:
    """Generate a one-line plain English summary."""
    delta = best - worst
    delta_note = f" ({delta}-point spread across probes)" if delta > 5 else ""

    if status == PQCStatus.FULLY_QUANTUM_SAFE:
        return f"{hostname} is fully quantum-safe with PQC key exchange and certificate{delta_note}."
    if status == PQCStatus.PQC_TRANSITION:
        return f"{hostname} is in PQC transition with hybrid/PQC key exchange on TLS 1.3{delta_note}."
    if status == PQCStatus.QUANTUM_VULNERABLE:
        return f"{hostname} uses classical cryptography and is vulnerable to quantum attacks{delta_note}."
    if status == PQCStatus.CRITICALLY_VULNERABLE:
        return f"{hostname} has critical vulnerabilities: deprecated protocols or weak crypto{delta_note}."
    return f"{hostname} could not be classified — probe data insufficient."


def _build_action(status: PQCStatus, worst_q: QScore) -> str:
    """Generate a single recommended action string."""
    if status == PQCStatus.FULLY_QUANTUM_SAFE:
        return "Maintain current configuration; monitor NIST algorithm updates."
    if status == PQCStatus.PQC_TRANSITION:
        return "Replace hybrid key exchange with pure ML-KEM and deploy ML-DSA certificate."
    if status == PQCStatus.QUANTUM_VULNERABLE:
        if worst_q.tls_version_score < 20:
            return "Upgrade to TLS 1.3 then enable X25519+ML-KEM-768 hybrid key exchange."
        return "Enable X25519+ML-KEM-768 hybrid key exchange and request PQC certificate."
    if status == PQCStatus.CRITICALLY_VULNERABLE:
        return "Immediately disable TLS 1.0/1.1, replace weak keys, renew expired certificates."
    return "Verify asset reachability and retry the scan."


# ═══════════════════════════════════════════════════════════════════════════
# Phase 7 public API: classify_trimode
# ═══════════════════════════════════════════════════════════════════════════

def classify_trimode(fp: TriModeFingerprint) -> ClassifiedAsset:
    """Classify a tri-mode fingerprint → ClassifiedAsset with 3 Q-Scores.

    Probe A = best case (PQC-capable client hello)
    Probe B = typical  (TLS 1.3 classical)
    Probe C = worst case (TLS 1.2 downgrade)
    """
    try:
        from backend.scanner.agility_assessor import assess_agility
        agility, agility_details = assess_agility(fp)
    except Exception:
        agility, agility_details = 0, []

    best_q = _score_probe(fp.probe_a, agility)
    typical_q = _score_probe(fp.probe_b, agility)
    worst_q = _score_probe(fp.probe_c, agility)

    cert_sig = fp.certificate.signature_algorithm or ""
    cert_pk = fp.certificate.public_key_type or ""
    best_q.status = _determine_probe_status(best_q, fp.probe_a, cert_sig=cert_sig, cert_pk=cert_pk)
    typical_q.status = _determine_probe_status(typical_q, fp.probe_b, cert_sig=cert_sig, cert_pk=cert_pk)
    worst_q.status = _determine_probe_status(worst_q, fp.probe_c, cert_sig=cert_sig, cert_pk=cert_pk)
    status = _determine_asset_status(best_q, typical_q, worst_q, fp)

    return ClassifiedAsset(
        hostname=fp.hostname,
        port=fp.port,
        asset_type=fp.asset_type,
        best_case_score=best_q.total,
        typical_score=typical_q.total,
        worst_case_score=worst_q.total,
        best_case_q=best_q,
        typical_q=typical_q,
        worst_case_q=worst_q,
        status=status,
        summary=_build_summary(fp.hostname, status, best_q.total, worst_q.total),
        recommended_action=_build_action(status, worst_q),
        agility_score=agility,
        agility_details=agility_details,
    )


# ═══════════════════════════════════════════════════════════════════════════
# Legacy API (Phase 2 compat) — kept for demo_data.py and app.py
# ═══════════════════════════════════════════════════════════════════════════

TLS_VERSION_SCORES = {
    "TLSv1.3": 25, "TLSv1.2": 15, "TLSv1.1": 0,
    "TLSv1": 0, "TLSv1.0": 0, "SSLv3": 0,
}

KEX_SCORES = {
    "ML-KEM-1024": 35, "ML-KEM-768": 35, "ML-KEM-512": 33,
    "X25519MLKEM768": 32, "X25519KYBER768": 32, "KYBER": 30,
    "X25519": 20, "X448": 20,
    "ECDHE": 15, "DHE": 12, "DH": 0, "RSA": 0,
}

CERT_SCORES = {
    "ML-DSA-87": 25, "ML-DSA-65": 25, "ML-DSA-44": 23,
    "SLH-DSA": 25,
    "ED25519": 12, "ED448": 12, "ECDSA": 12,
    "RSA": 0,
}

CIPHER_STRENGTH_SCORES = {256: 15, 192: 12, 128: 10, 112: 5, 0: 0}


def classify(fingerprint: CryptoFingerprint, negotiation_policy: Any | None = None) -> QScore:
    """Legacy Phase 2 classifier — CryptoFingerprint → QScore (max 100).

    Kept for backward compatibility with demo_data, app.py, and Phases 1-6.
    """
    score = QScore()
    findings: list[str] = []
    recommendations: list[str] = []

    tls = fingerprint.tls
    cert = fingerprint.certificate

    if not tls.version and tls.cipher_bits == 0:
        score.status = PQCStatus.UNKNOWN
        score.findings = ["Scan failed or returned insufficient data for classification"]
        score.recommendations = ["Verify the target is reachable and retry the scan"]
        return score

    # TLS Version (max 25)
    tls_score = TLS_VERSION_SCORES.get(tls.version, 0)
    if tls_score == 0 and tls.version and "1.3" in tls.version:
        tls_score = 25
    score.tls_version_score = tls_score

    if tls_score == 0:
        findings.append(f"CRITICAL: {tls.version or 'Legacy Version'} is deprecated and insecure")
        recommendations.append("Immediately disable TLS 1.0/1.1. Upgrade to TLS 1.3")
    elif tls.version == "TLSv1.2":
        findings.append("TLS 1.2 is secure today but lacks PQC key exchange support")
        recommendations.append("Migrate to TLS 1.3 for PQC hybrid key exchange")
    elif tls.version == "TLSv1.3":
        findings.append("TLS 1.3 — Good foundation for PQC migration")

    if tls.supports_tls_1_0 or tls.supports_tls_1_1:
        findings.append("WARNING: Server still accepts deprecated TLS 1.0/1.1 connections")
        recommendations.append("Disable TLS 1.0/1.1 to prevent protocol downgrade attacks")

    # Key Exchange (max 35)
    kex_upper = tls.key_exchange.upper() if tls.key_exchange else ""
    kex_score = 0
    for pattern, pts in KEX_SCORES.items():
        if pattern in kex_upper:
            kex_score = max(kex_score, pts)
    score.key_exchange_score = kex_score

    if fingerprint.has_pqc_kex:
        findings.append(f"PQC key exchange detected ({tls.key_exchange}) — Quantum-resistant key exchange in use")
    elif kex_upper in ("RSA", "DH") or kex_score == 0:
        findings.append(f"{kex_upper or 'Legacy'} key exchange is vulnerable to Shor's algorithm")
        recommendations.append("Enable ECDHE or X25519 for forward secrecy, then migrate to ML-KEM hybrid")
    elif kex_score in (12, 15, 20):
        findings.append(f"{kex_upper} provides forward secrecy but is quantum-vulnerable")
        recommendations.append("Enable hybrid mode: X25519 + ML-KEM-768")

    if fingerprint.has_hybrid_mode:
        findings.append("Hybrid PQC mode active — Transitional quantum protection")

    # Certificate (max 25)
    sig_algo = (cert.signature_algorithm or "").upper()
    cert_score = 0
    for pattern, pts in CERT_SCORES.items():
        if pattern in sig_algo:
            cert_score = max(cert_score, pts)
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
            if cert.public_key_bits else cert.public_key_type or "Unknown"
        )
        findings.append(f"Certificate uses {pk_desc} — Vulnerable to quantum factoring")
        recommendations.append("Request a certificate with ML-DSA or SLH-DSA signature from your CA")

    if cert.public_key_bits and cert.public_key_bits < 2048 and "RSA" in (cert.public_key_type or "").upper():
        findings.append(f"CRITICAL: RSA key size {cert.public_key_bits} bits is below minimum")
        recommendations.append("Immediately replace with RSA-2048 minimum, prefer RSA-4096 or EC P-384")

    if cert.is_expired:
        findings.append("CRITICAL: Certificate is expired")
        recommendations.append("Renew certificate immediately")
    elif cert.days_until_expiry and cert.days_until_expiry < 30:
        findings.append(f"WARNING: Certificate expires in {cert.days_until_expiry} days")
        recommendations.append("Renew certificate before expiry")

    # Cipher Strength (max 15)
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

    # Total
    score.total = tls_score + kex_score + cert_score + cipher_score

    # Optional negotiation policy boost/penalty (Phase A integration)
    if negotiation_policy is not None:
        adjustment = 0
        try:
            if isinstance(negotiation_policy, dict):
                adjustment = int(negotiation_policy.get("negotiation_security_score", 0))
            else:
                adjustment = int(getattr(negotiation_policy, "negotiation_security_score", 0))
        except (TypeError, ValueError):
            adjustment = 0
        score.total += adjustment

    # Always clamp final score to valid range
    score.total = max(0, min(100, int(score.total)))

    # Status Classification
    has_tls13 = _is_tls13_version(tls.version)
    has_pqc_path = fingerprint.has_pqc_kex or _is_pqc_kex_name(tls.key_exchange)
    has_pqc_cert = fingerprint.has_pqc_signature or _is_pqc_sig_name(cert.signature_algorithm, cert.public_key_type)

    if tls_score == 0 or cert.is_expired:
        score.status = PQCStatus.CRITICALLY_VULNERABLE
        score.total = min(score.total, 39)
    elif has_tls13 and has_pqc_path and has_pqc_cert and score.total >= 90:
        score.status = PQCStatus.FULLY_QUANTUM_SAFE
    elif has_tls13 and has_pqc_path:
        score.status = PQCStatus.PQC_TRANSITION
    elif score.total >= 40:
        score.status = PQCStatus.QUANTUM_VULNERABLE
    else:
        score.status = PQCStatus.CRITICALLY_VULNERABLE

    score.findings = findings
    score.recommendations = recommendations
    return score
