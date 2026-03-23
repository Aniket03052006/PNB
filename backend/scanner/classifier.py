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
    CertificateInfo,
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

TLS_VERSION_SCORES_V7 = {
    "TLS1.3": 20,
    "TLS1.2": 10,
    "TLS1.1": 2,
    "TLS1.0": 0,
    "SSLv3": 0,
    "SSLv2": 0,
}

DISPLAY_TIER_BY_STATUS: dict[PQCStatus, str] = {
    PQCStatus.FULLY_QUANTUM_SAFE: "Elite-PQC",
    PQCStatus.PQC_TRANSITION: "Standard",
    PQCStatus.QUANTUM_VULNERABLE: "Legacy",
    PQCStatus.CRITICALLY_VULNERABLE: "Critical",
    PQCStatus.UNKNOWN: "Unclassified",
}

_PQC_KEX_NAMES = frozenset({"MLKEM", "KYBER"})
_PQC_SIG_NAMES = frozenset({"MLDSA", "SLHDSA", "DILITHIUM", "SPHINCS", "FALCON"})
_LEGACY_TLS_VERSIONS = frozenset({"TLS1.1", "TLS1.0", "SSLv3", "SSLv2"})
_CRITICAL_CIPHER_TOKENS = frozenset({"NULL", "EXPORT", "ANON", "RC4"})


def _norm_alg(value: str | None) -> str:
    return str(value or "").upper().replace("-", "").replace("_", "").replace(" ", "").replace(".", "")


def _matches_any(value: str | None, patterns: set[str] | frozenset[str]) -> bool:
    norm = _norm_alg(value)
    return any(_norm_alg(pattern) in norm for pattern in patterns)


def _canonical_tls_version(value: str | None) -> str:
    token = _norm_alg(value)
    if "TLS13" in token or "TLSV13" in token:
        return "TLS1.3"
    if "TLS12" in token or "TLSV12" in token:
        return "TLS1.2"
    if "TLS11" in token or "TLSV11" in token:
        return "TLS1.1"
    if token in {"TLS10", "TLS1", "TLSV1", "TLSV10"}:
        return "TLS1.0"
    if "SSLV3" in token:
        return "SSLv3"
    if "SSLV2" in token:
        return "SSLv2"
    return ""


def _is_tls13_version(value: str | None) -> bool:
    return _canonical_tls_version(value) == "TLS1.3"


def _is_legacy_tls_version(value: str | None) -> bool:
    return _canonical_tls_version(value) in _LEGACY_TLS_VERSIONS


def _probe_success(probe: ProbeProfile) -> bool:
    if probe.error:
        return False
    return bool(
        probe.tls_version
        or probe.cipher_suite
        or probe.key_exchange
        or probe.key_exchange_group
        or (probe.cipher_bits or 0) > 0
    )


def _probe_kex(probe: ProbeProfile) -> str:
    return str(probe.key_exchange or probe.key_exchange_group or "")


def _probe_hsts_enabled(probe: ProbeProfile) -> bool:
    return bool(getattr(probe, "hsts_enabled", False))


def _is_hybrid_kex_name(value: str | None) -> bool:
    token = _norm_alg(value)
    return "MLKEM" in token and ("X25519" in token or "ECDH" in token or "SECP" in token)


def _is_pqc_kex_name(value: str | None) -> bool:
    token = _norm_alg(value)
    return ("MLKEM" in token) or ("KYBER" in token)


def _is_pqc_sig_name(*values: str | None) -> bool:
    return any(_matches_any(value, _PQC_SIG_NAMES) for value in values if value)


def score_tls_version(tls_version: str | None) -> int:
    return TLS_VERSION_SCORES_V7.get(_canonical_tls_version(tls_version), 0)


def score_kex(kex_string: str | None) -> int:
    kex = _norm_alg(kex_string)
    if "MLKEM" in kex and "X25519" in kex:
        return 30
    if "MLKEM" in kex and "ECDH" in kex:
        return 28
    if "MLKEM" in kex:
        return 25
    if "KYBER" in kex:
        return 20

    if "X25519" in kex:
        return 14
    if "SECP384" in kex or "P384" in kex:
        return 13
    if "SECP256" in kex or "P256" in kex:
        return 12
    if "ECDHE" in kex or "ECDH" in kex:
        return 12

    if "DHE" in kex or "EDH" in kex:
        return 8
    if "DH" in kex:
        return 4
    if "RSA" in kex:
        return 0
    return 0


def score_certificate(cert_algorithm: str | None, cert_key_bits: int | None) -> int:
    algo = _norm_alg(cert_algorithm)
    bits = int(cert_key_bits or 0)

    if any(pqc in algo for pqc in ("MLDSA", "DILITHIUM", "SLHDSA", "SPHINCS")):
        return 20
    if "FALCON" in algo:
        return 18

    if "ECDSA" in algo:
        if bits >= 384:
            return 14
        if bits >= 256:
            return 12
        return 8

    if "RSA" in algo:
        if bits >= 4096:
            return 10
        if bits >= 3072:
            return 8
        if bits >= 2048:
            return 6
        if bits >= 1024:
            return 2
        return 0

    if "ED25519" in algo:
        return 13
    if "ED448" in algo:
        return 14
    return 0


def score_cipher(cipher_string: str | None) -> int:
    c = _norm_alg(cipher_string)
    for bad in ("NULL", "EXPORT", "ANON", "RC4", "DES", "3DES", "MD5", "RC2"):
        if bad in c:
            return 0

    if "AES256GCM" in c or "CHACHA20POLY1305" in c:
        return 15
    if "AES128GCM" in c:
        return 10
    if "AES256CCM" in c:
        return 12
    if "AES128CCM" in c:
        return 8
    if "AES256CBC" in c:
        return 5
    if "AES128CBC" in c:
        return 3
    if "CBC" in c:
        return 2
    return 5


def score_crypto_agility(
    probe_a: ProbeProfile,
    probe_b: ProbeProfile,
    probe_c: ProbeProfile,
    cert: CertificateInfo,
) -> tuple[int, list[dict[str, Any]], int]:
    indicators: list[dict[str, Any]] = []
    score = 0

    dynamic_kex = _probe_success(probe_a) and _probe_success(probe_b) and (_probe_kex(probe_a) != _probe_kex(probe_b))
    indicators.append({
        "id": "dynamic_kex_selection",
        "passed": dynamic_kex,
        "description": "Server selects KEX based on client capability" if dynamic_kex else "Server uses static KEX regardless of client",
    })
    if dynamic_kex:
        score += 3

    tls13_enabled = _probe_success(probe_b) and _canonical_tls_version(probe_b.tls_version) == "TLS1.3"
    indicators.append({
        "id": "tls13_enabled",
        "passed": tls13_enabled,
        "description": "TLS 1.3 supported — prerequisite for PQC groups",
    })
    if tls13_enabled:
        score += 3

    tls11_blocked = (not _probe_success(probe_c)) or (_canonical_tls_version(probe_c.tls_version) not in {"TLS1.1", "TLS1.0", "SSLv3", "SSLv2"})
    indicators.append({
        "id": "tls11_blocked",
        "passed": tls11_blocked,
        "description": "TLS 1.1 and lower blocked — migration path clear",
    })
    if tls11_blocked:
        score += 3

    cert_validity_window = int(cert.days_until_expiry or 0) > 90
    indicators.append({
        "id": "cert_validity_window",
        "passed": cert_validity_window,
        "description": "Certificate window allows algorithm migration",
    })
    if cert_validity_window:
        score += 3

    hsts_enabled = _probe_hsts_enabled(probe_b) or _probe_hsts_enabled(probe_a)
    indicators.append({
        "id": "hsts_enabled",
        "passed": hsts_enabled,
        "description": "HSTS signals active TLS configuration management",
    })
    if hsts_enabled:
        score += 3

    agility_index = sum(1 for indicator in indicators if indicator.get("passed"))
    return score, indicators, agility_index


def score_negotiation(probe_a: ProbeProfile, probe_b: ProbeProfile, probe_c: ProbeProfile) -> int:
    score = 0
    pqc_negotiated = _probe_success(probe_a) and ("MLKEM" in _norm_alg(_probe_kex(probe_a)))
    tls13_supported = _probe_success(probe_b) and _canonical_tls_version(probe_b.tls_version) == "TLS1.3"
    c_ver = _canonical_tls_version(probe_c.tls_version) if _probe_success(probe_c) else ""
    downgrade_tls12 = c_ver == "TLS1.2"
    downgrade_tls11 = c_ver in {"TLS1.1", "TLS1.0"}

    if pqc_negotiated:
        score += 10
    if tls13_supported:
        score += 5
    if downgrade_tls12:
        score -= 10
    if downgrade_tls11:
        score -= 20
    return score


def _compute_probe_q_score(
    probe: ProbeProfile,
    cert: CertificateInfo,
    probe_a: ProbeProfile,
    probe_b: ProbeProfile,
    probe_c: ProbeProfile,
    agility_score: int,
) -> QScore:
    if not _probe_success(probe):
        return QScore(
            total=0,
            status=PQCStatus.UNKNOWN,
            findings=[f"Probe {probe.mode or '?'} failed or returned insufficient data"],
            recommendations=["Verify target reachability and retry"],
        )

    cert_algorithm = cert.signature_algorithm or probe.signature_algorithm or probe.public_key_type or ""
    cert_bits = cert.public_key_bits or probe.public_key_bits or 0
    negotiation_score = score_negotiation(probe_a, probe_b, probe_c)

    tls_score = score_tls_version(probe.tls_version)
    kex_score = score_kex(_probe_kex(probe))
    certificate_score = score_certificate(cert_algorithm, cert_bits)
    cipher_score = score_cipher(probe.cipher_suite)

    raw = tls_score + kex_score + certificate_score + cipher_score + agility_score + negotiation_score
    total = max(0, min(100, int(raw)))

    findings = [
        f"TLS score={tls_score}, KEX score={kex_score}, Certificate score={certificate_score}, Cipher score={cipher_score}",
        f"Agility score={agility_score}, Negotiation score={negotiation_score}",
    ]
    recommendations: list[str] = []

    if tls_score == 0:
        recommendations.append("Upgrade to TLS 1.3 immediately")
    if kex_score < 20:
        recommendations.append("Enable X25519MLKEM768 hybrid key exchange")
    if certificate_score < 18:
        recommendations.append("Plan migration to ML-DSA or SLH-DSA certificates")
    if cipher_score == 0:
        recommendations.append("Disable NULL/export/RC4/DES class ciphers")

    return QScore(
        total=total,
        tls_version_score=tls_score,
        key_exchange_score=kex_score,
        certificate_score=certificate_score,
        cipher_strength_score=cipher_score,
        agility_score=agility_score,
        findings=findings,
        recommendations=recommendations,
    )


def _check_probe_status(probe_a: ProbeProfile, probe_b: ProbeProfile, probe_c: ProbeProfile) -> PQCStatus | None:
    all_failed = (not _probe_success(probe_a)) and (not _probe_success(probe_b)) and (not _probe_success(probe_c))
    if all_failed:
        return PQCStatus.UNKNOWN
    return None


def _pqc_cert_confirmed(cert: CertificateInfo, probe_a: ProbeProfile, probe_b: ProbeProfile, probe_c: ProbeProfile) -> bool:
    cert_alg = cert.signature_algorithm or ""
    return _is_pqc_sig_name(
        cert_alg,
        probe_a.signature_algorithm,
        probe_b.signature_algorithm,
        probe_c.signature_algorithm,
        cert.public_key_type,
    )


def _classify_tier(
    best_case: int,
    typical_case: int,
    worst_case: int,
    probe_a: ProbeProfile,
    probe_b: ProbeProfile,
    probe_c: ProbeProfile,
    cert: CertificateInfo,
) -> PQCStatus:
    probe_c_tls = _canonical_tls_version(probe_c.tls_version) if _probe_success(probe_c) else ""
    probe_c_cipher = _norm_alg(probe_c.cipher_suite)
    cert_bits = int(cert.public_key_bits or 0)
    cert_algo_token = _norm_alg(cert.signature_algorithm or cert.public_key_type)
    cert_days = int(cert.days_until_expiry or 0)
    cert_expired = bool(cert.is_expired) or (bool(cert.not_after) and cert_days <= 0)

    if probe_c_tls in {"TLS1.1", "TLS1.0", "SSLv3", "SSLv2"}:
        return PQCStatus.CRITICALLY_VULNERABLE

    if any(bad in probe_c_cipher for bad in _CRITICAL_CIPHER_TOKENS):
        return PQCStatus.CRITICALLY_VULNERABLE

    if ("RSA" in cert_algo_token) and cert_bits and cert_bits < 1024:
        return PQCStatus.CRITICALLY_VULNERABLE

    if cert_expired:
        return PQCStatus.CRITICALLY_VULNERABLE

    probe_a_success = _probe_success(probe_a)
    probe_b_success = _probe_success(probe_b)
    probe_c_success = _probe_success(probe_c)

    probe_a_kex = _probe_kex(probe_a)
    pqc_kex_confirmed = probe_a_success and (("MLKEM" in _norm_alg(probe_a_kex)) or ("X25519MLKEM" in _norm_alg(probe_a_kex)))
    pqc_cert_confirmed = _pqc_cert_confirmed(cert, probe_a, probe_b, probe_c)
    no_downgrade = (not probe_c_success) or (probe_c_tls == "TLS1.3")

    if pqc_kex_confirmed and pqc_cert_confirmed and no_downgrade and worst_case > 85:
        return PQCStatus.FULLY_QUANTUM_SAFE

    pqc_kex_available = probe_a_success and (("MLKEM" in _norm_alg(probe_a_kex)) or ("KYBER" in _norm_alg(probe_a_kex)))
    tls13_available = probe_b_success and _canonical_tls_version(probe_b.tls_version) == "TLS1.3"

    if pqc_kex_available and tls13_available and worst_case >= 55:
        return PQCStatus.PQC_TRANSITION

    if pqc_cert_confirmed and tls13_available and worst_case >= 50:
        return PQCStatus.PQC_TRANSITION

    classical_but_modern = tls13_available and (not pqc_kex_available) and (not pqc_cert_confirmed) and worst_case >= 25
    if classical_but_modern:
        return PQCStatus.QUANTUM_VULNERABLE

    if probe_b_success and _canonical_tls_version(probe_b.tls_version) == "TLS1.2" and worst_case >= 15:
        return PQCStatus.QUANTUM_VULNERABLE

    return PQCStatus.CRITICALLY_VULNERABLE


def _compute_hndl_risk(
    probe_a: ProbeProfile,
    probe_b: ProbeProfile,
    probe_c: ProbeProfile,
    cert: CertificateInfo,
) -> dict[str, Any]:
    risk_score = 0
    probes = [probe_a, probe_b, probe_c]

    def _kex(p: ProbeProfile) -> str:
        return _norm_alg(_probe_kex(p))

    if any(_probe_success(p) and ("RSA" in _kex(p)) for p in probes):
        risk_score += 40

    if _probe_success(probe_b):
        kex_b = _kex(probe_b)
        if ("ECDHE" in kex_b) and ("MLKEM" not in kex_b):
            risk_score += 30

    if _probe_success(probe_c) and _canonical_tls_version(probe_c.tls_version) == "TLS1.2" and ("ECDHE" in _kex(probe_c)):
        risk_score += 20

    if _probe_success(probe_c) and _canonical_tls_version(probe_c.tls_version) in {"TLS1.1", "TLS1.0"}:
        risk_score += 30

    if (
        _probe_success(probe_a)
        and ("MLKEM" in _kex(probe_a))
        and _probe_success(probe_b)
        and ("MLKEM" in _kex(probe_b))
    ):
        risk_score -= 40

    risk_score = max(0, min(100, risk_score))
    if risk_score >= 70:
        level = "CRITICAL"
    elif risk_score >= 40:
        level = "HIGH"
    elif risk_score >= 15:
        level = "MEDIUM"
    elif risk_score > 0:
        level = "LOW"
    else:
        level = "NONE"

    return {
        "hndl_risk_score": risk_score,
        "hndl_risk_level": level,
        "explanation": f"Recorded traffic has a {level} probability of future quantum decryption",
    }


def _generate_remediation_roadmap(
    tier: PQCStatus,
    probe_a: ProbeProfile,
    probe_b: ProbeProfile,
    probe_c: ProbeProfile,
    cert: CertificateInfo,
    agility_indicators: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    actions: list[dict[str, Any]] = []
    probe_c_tls = _canonical_tls_version(probe_c.tls_version) if _probe_success(probe_c) else ""

    if probe_c_tls in {"TLS1.1", "TLS1.0", "SSLv3", "SSLv2"}:
        actions.append({
            "priority": "CRITICAL",
            "action": "Disable TLS 1.1, TLS 1.0, and SSLv3 immediately",
            "rationale": "These versions are exploitable today, independent of quantum threat",
            "effort": "LOW",
            "fix_in_days": 7,
        })

    cert_days_left = int(cert.days_until_expiry or 0)
    if bool(cert.not_after) and cert_days_left <= 30:
        actions.append({
            "priority": "CRITICAL",
            "action": f"Renew certificate — expires in {cert_days_left} days",
            "rationale": "Expired or near-expired certificate breaks TLS entirely",
            "effort": "LOW",
            "fix_in_days": max(1, cert_days_left - 1),
        })

    cert_bits = int(cert.public_key_bits or 0)
    cert_algo_token = _norm_alg(cert.signature_algorithm or cert.public_key_type)
    if ("RSA" in cert_algo_token) and cert_bits and cert_bits < 2048:
        actions.append({
            "priority": "CRITICAL",
            "action": "Replace certificate — key length below 2048 bits",
            "rationale": "Keys below 2048-bit are weak for modern deployment baselines",
            "effort": "LOW",
            "fix_in_days": 14,
        })

    pqc_kex_missing = not (_probe_success(probe_a) and ("MLKEM" in _norm_alg(_probe_kex(probe_a))))
    if pqc_kex_missing:
        actions.append({
            "priority": "HIGH",
            "action": "Enable X25519MLKEM768 hybrid key exchange group in TLS config",
            "rationale": "Without PQC KEX, recorded traffic is vulnerable to future quantum decryption (HNDL)",
            "effort": "MEDIUM",
            "fix_in_days": 30,
            "reference": "NIST FIPS 203 — ML-KEM",
        })

    pqc_cert_missing = not _pqc_cert_confirmed(cert, probe_a, probe_b, probe_c)
    if pqc_cert_missing:
        actions.append({
            "priority": "HIGH",
            "action": "Migrate certificate to ML-DSA-65 or SLH-DSA-128s",
            "rationale": "RSA and ECDSA certificates are vulnerable to quantum-era attacks",
            "effort": "HIGH",
            "fix_in_days": 90,
            "reference": "NIST FIPS 204/205",
        })

    if not (_probe_success(probe_b) and _canonical_tls_version(probe_b.tls_version) == "TLS1.3"):
        actions.append({
            "priority": "MEDIUM",
            "action": "Enable TLS 1.3 — required for PQC cipher group negotiation",
            "rationale": "PQC key exchange groups are available only in TLS 1.3",
            "effort": "LOW",
            "fix_in_days": 14,
        })

    downgrade_allowed = _probe_success(probe_c) and _canonical_tls_version(probe_c.tls_version) in {"TLS1.2", "TLS1.1", "TLS1.0"}
    if downgrade_allowed:
        actions.append({
            "priority": "MEDIUM",
            "action": "Restrict minimum TLS version to TLS 1.3 where client base allows",
            "rationale": "Downgrade to classical TLS exposes legacy client traffic to HNDL",
            "effort": "MEDIUM",
            "fix_in_days": 30,
        })

    if not (_probe_hsts_enabled(probe_b) or _probe_hsts_enabled(probe_a)):
        actions.append({
            "priority": "MEDIUM",
            "action": "Enable HSTS with max-age 31536000 and includeSubDomains",
            "rationale": "HSTS prevents downgrade attacks and signals active TLS management",
            "effort": "LOW",
            "fix_in_days": 7,
        })

    if cert_bits and cert_bits < 3072 and "RSA" in _norm_alg(cert.signature_algorithm):
        actions.append({
            "priority": "LOW",
            "action": "Upgrade RSA certificate to 3072-bit or 4096-bit key",
            "rationale": "Improves long-term classical security margin during migration",
            "effort": "LOW",
            "fix_in_days": 60,
        })

    order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
    actions.sort(key=lambda action: order.get(str(action.get("priority")), 4))
    return actions


def _build_summary(hostname: str, status: PQCStatus, best: int, worst: int) -> str:
    delta = best - worst
    delta_note = f" ({delta}-point spread across probes)" if delta > 5 else ""
    display = DISPLAY_TIER_BY_STATUS.get(status, "Unclassified")
    return f"{hostname} classified as {display}{delta_note}."


def _recommended_action_from_roadmap(status: PQCStatus, roadmap: list[dict[str, Any]]) -> str:
    if roadmap:
        return str(roadmap[0].get("action") or "")
    if status == PQCStatus.FULLY_QUANTUM_SAFE:
        return "Maintain current configuration; monitor NIST algorithm updates."
    if status == PQCStatus.UNKNOWN:
        return "Verify asset reachability and retry the scan."
    return "Enable TLS 1.3 and begin ML-KEM + ML-DSA migration planning."


def _probe_status_from_score(score: QScore, probe: ProbeProfile, cert: CertificateInfo) -> PQCStatus:
    if score.status == PQCStatus.UNKNOWN:
        return PQCStatus.UNKNOWN
    if _is_legacy_tls_version(probe.tls_version):
        return PQCStatus.CRITICALLY_VULNERABLE
    if score.total >= 85 and _is_pqc_kex_name(_probe_kex(probe)) and _is_pqc_sig_name(cert.signature_algorithm, cert.public_key_type):
        return PQCStatus.FULLY_QUANTUM_SAFE
    if score.total >= 55 and (_is_pqc_kex_name(_probe_kex(probe)) or _is_pqc_sig_name(cert.signature_algorithm, cert.public_key_type)):
        return PQCStatus.PQC_TRANSITION
    if score.total >= 25:
        return PQCStatus.QUANTUM_VULNERABLE
    return PQCStatus.CRITICALLY_VULNERABLE


# ═══════════════════════════════════════════════════════════════════════════
# Phase 7 public API: classify_trimode
# ═══════════════════════════════════════════════════════════════════════════

def classify_trimode(fp: TriModeFingerprint) -> ClassifiedAsset:
    """Classify tri-mode fingerprint using worst-case driven 4-tier PQC logic."""
    early_exit = _check_probe_status(fp.probe_a, fp.probe_b, fp.probe_c)
    if early_exit == PQCStatus.UNKNOWN:
        unknown_q = QScore(
            total=0,
            status=PQCStatus.UNKNOWN,
            findings=["All three probes failed; classification unavailable"],
            recommendations=["Verify endpoint connectivity and retry"],
        )
        return ClassifiedAsset(
            hostname=fp.hostname,
            port=fp.port,
            asset_type=fp.asset_type,
            best_case_score=0,
            typical_score=0,
            worst_case_score=0,
            best_case_q=unknown_q,
            typical_q=unknown_q.model_copy(deep=True),
            worst_case_q=unknown_q.model_copy(deep=True),
            status=PQCStatus.UNKNOWN,
            summary=_build_summary(fp.hostname, PQCStatus.UNKNOWN, 0, 0),
            recommended_action="Verify asset reachability and retry the scan.",
            agility_score=0,
            agility_details=[{"id": "probe_failure", "passed": False, "description": "All tri-mode probes failed"}],
        )

    agility_score, agility_indicators, agility_index = score_crypto_agility(
        fp.probe_a,
        fp.probe_b,
        fp.probe_c,
        fp.certificate,
    )

    best_q = _compute_probe_q_score(fp.probe_a, fp.certificate, fp.probe_a, fp.probe_b, fp.probe_c, agility_score)
    typical_q = _compute_probe_q_score(fp.probe_b, fp.certificate, fp.probe_a, fp.probe_b, fp.probe_c, agility_score)
    worst_q = _compute_probe_q_score(fp.probe_c, fp.certificate, fp.probe_a, fp.probe_b, fp.probe_c, agility_score)

    best_case = best_q.total
    typical_case = typical_q.total
    worst_case = worst_q.total

    status = _classify_tier(best_case, typical_case, worst_case, fp.probe_a, fp.probe_b, fp.probe_c, fp.certificate)

    best_q.status = _probe_status_from_score(best_q, fp.probe_a, fp.certificate) if _probe_success(fp.probe_a) else PQCStatus.UNKNOWN
    typical_q.status = _probe_status_from_score(typical_q, fp.probe_b, fp.certificate) if _probe_success(fp.probe_b) else PQCStatus.UNKNOWN
    worst_q.status = status if _probe_success(fp.probe_c) else PQCStatus.UNKNOWN

    hndl_risk = _compute_hndl_risk(fp.probe_a, fp.probe_b, fp.probe_c, fp.certificate)
    roadmap = _generate_remediation_roadmap(status, fp.probe_a, fp.probe_b, fp.probe_c, fp.certificate, agility_indicators)

    worst_q.findings.append(hndl_risk["explanation"])
    worst_q.recommendations.extend(str(action.get("action")) for action in roadmap[:3] if action.get("action"))

    agility_details = list(agility_indicators)
    agility_details.append({
        "id": "agility_index",
        "passed": agility_index >= 3,
        "value": agility_index,
        "description": "0-5 migration readiness index",
    })
    agility_details.append({
        "id": "hndl_risk",
        "passed": hndl_risk.get("hndl_risk_score", 0) < 40,
        "value": hndl_risk,
        "description": "Harvest-Now-Decrypt-Later risk estimate",
    })
    agility_details.append({
        "id": "display_tier",
        "passed": status != PQCStatus.UNKNOWN,
        "value": DISPLAY_TIER_BY_STATUS.get(status, "Unclassified"),
        "description": "Human-readable PQC posture tier",
    })

    # Calculate pqc_support boolean
    probe_c_tls = _canonical_tls_version(fp.probe_c.tls_version) if _probe_success(fp.probe_c) else ""
    downgrade_allowed = _probe_success(fp.probe_c) and probe_c_tls in {"TLS1.2", "TLS1.1", "TLS1.0", "SSLv3", "SSLv2"}
    
    pqc_kex_detected = False
    for p in (fp.probe_a, fp.probe_b, fp.probe_c):
        if _probe_success(p):
            kex = _norm_alg(_probe_kex(p))
            if "MLKEM" in kex or "KYBER" in kex:
                pqc_kex_detected = True
                
    tls13_supported = _probe_success(fp.probe_b) and _canonical_tls_version(fp.probe_b.tls_version) == "TLS1.3"
    ecdhe_present = "ECDH" in _norm_alg(_probe_kex(fp.probe_b))
    
    if downgrade_allowed:
        is_pqc_supported = False
    elif pqc_kex_detected:
        is_pqc_supported = True
    elif tls13_supported and ecdhe_present:
        is_pqc_supported = True
    else:
        is_pqc_supported = False

    return ClassifiedAsset(
        hostname=fp.hostname,
        port=fp.port,
        asset_type=fp.asset_type,
        best_case_score=best_case,
        typical_score=typical_case,
        worst_case_score=worst_case,
        best_case_q=best_q,
        typical_q=typical_q,
        worst_case_q=worst_q,
        status=status,
        summary=_build_summary(fp.hostname, status, best_case, worst_case),
        recommended_action=_recommended_action_from_roadmap(status, roadmap),
        agility_score=agility_score,
        agility_details=agility_details,
        pqc_support=is_pqc_supported,
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
