"""
Phase 2 — PQC Assessment Engine.

Takes the extracted ``CryptoFingerprint`` from Phase 1 (live scan data)
and evaluates every cryptographic dimension against the NIST Validation
Matrix.  Returns a structured ``EndpointAssessment`` dictionary that
powers the dashboard KPIs and the remediation generator.

Public API
──────────
  analyze_endpoint(scan_result)  →  dict   (single target)
  analyze_batch(scan_summary)    →  dict   (batch with aggregates)
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Any, Dict, List

from backend.models import CryptoFingerprint, QScore, ScanResult, ScanSummary, PQCStatus
from backend.scanner.nist_matrix import (
    QuantumStatus,
    classify_kex,
    classify_signature,
    classify_protocol,
    classify_symmetric,
    lookup,
    VULNERABLE_KEY_EXCHANGE,
    VULNERABLE_SIGNATURES,
    HYBRID_PQC_KEX,
    PURE_PQC_KEM,
    PURE_PQC_SIGNATURES,
)

logger = logging.getLogger("qarmor.assessment")


# ───────────────────────────────────────────────────────────────────────────
# Status Labels
# ───────────────────────────────────────────────────────────────────────────

# TLS Protocol
TLS_PASS = "PASS"
TLS_FAIL = "FAIL"

# Key Exchange / Certificate
KX_VULNERABLE = "VULNERABLE"
KX_HYBRID = "HYBRID"
KX_PQC_SAFE = "PQC_SAFE"

# Symmetric Cipher
SYM_PASS = "PASS"
SYM_FAIL = "FAIL"

# Overall Risk
RISK_HIGH = "HIGH"
RISK_MEDIUM = "MEDIUM"
RISK_LOW = "LOW"


# ───────────────────────────────────────────────────────────────────────────
# Helper: Quantum-Status → Assessment Label
# ───────────────────────────────────────────────────────────────────────────

_KEX_STATUS_MAP = {
    QuantumStatus.PQC_SAFE: KX_PQC_SAFE,
    QuantumStatus.HYBRID_PQC: KX_HYBRID,
    QuantumStatus.COMPLIANT: KX_VULNERABLE,   # Classical-compliant ≠ PQC safe
    QuantumStatus.VULNERABLE: KX_VULNERABLE,
    QuantumStatus.WEAKENED: KX_VULNERABLE,
    QuantumStatus.LEGACY_PROTOCOL: KX_VULNERABLE,
}


# ───────────────────────────────────────────────────────────────────────────
# Core Assessment — Single Endpoint
# ───────────────────────────────────────────────────────────────────────────

def analyze_endpoint(scan_result: ScanResult) -> Dict[str, Any]:
    """Evaluate a single scan result against the NIST validation matrix.

    Parameters
    ----------
    scan_result : ScanResult
        A Phase 1 scan result containing ``fingerprint`` and ``q_score``.

    Returns
    -------
    dict
        Assessment dictionary with the following keys:

        - ``target``                  : str
        - ``port``                    : int
        - ``assessed_at``             : str  (ISO-8601)
        - ``tls_status``              : "PASS" | "FAIL"
        - ``tls_version``             : str
        - ``tls_details``             : str  (human-readable explanation)
        - ``key_exchange_status``     : "VULNERABLE" | "HYBRID" | "PQC_SAFE"
        - ``key_exchange_algorithm``  : str
        - ``key_exchange_details``    : str
        - ``certificate_status``      : "VULNERABLE" | "HYBRID" | "PQC_SAFE"
        - ``certificate_algorithm``   : str
        - ``certificate_details``     : str
        - ``symmetric_cipher_status`` : "PASS" | "FAIL"
        - ``symmetric_cipher``        : str
        - ``symmetric_bits``          : int
        - ``symmetric_details``       : str
        - ``overall_quantum_risk``    : "HIGH" | "MEDIUM" | "LOW"
        - ``risk_summary``            : str
        - ``hndl_vulnerable``         : bool  (Harvest-Now Decrypt-Later)
        - ``q_score``                 : int
        - ``findings``                : list[str]
        - ``nist_references``         : list[str]
    """
    fp: CryptoFingerprint = scan_result.fingerprint
    tls = fp.tls
    cert = fp.certificate
    q = scan_result.q_score

    assessment: Dict[str, Any] = {
        "target": scan_result.asset.hostname,
        "port": scan_result.asset.port,
        "assessed_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
    }

    findings: List[str] = []
    nist_refs: List[str] = []

    # ── 1.  TLS Protocol Status ──────────────────────────────────────────
    tls_qs = classify_protocol(tls.version) if tls.version else QuantumStatus.LEGACY_PROTOCOL

    if tls_qs == QuantumStatus.COMPLIANT:
        assessment["tls_status"] = TLS_PASS
        assessment["tls_details"] = (
            f"{tls.version} supports PQC key-exchange groups via the "
            "NamedGroup registry (RFC 8446). Foundation for quantum-safe transport."
        )
    else:
        assessment["tls_status"] = TLS_FAIL
        detail = f"{tls.version or 'Unknown'} is "
        if tls_qs == QuantumStatus.LEGACY_PROTOCOL:
            detail += "deprecated and cannot negotiate PQC extensions."
            findings.append(f"CRITICAL: {tls.version or 'Legacy protocol'} does not support PQC key exchange.")
        else:
            detail += "not compliant for PQC migration."
        assessment["tls_details"] = detail
        nist_refs.append("RFC 8996 — Deprecating TLS 1.0 and TLS 1.1")

    assessment["tls_version"] = tls.version or "Unknown"

    # ── 2.  Key Exchange Status ──────────────────────────────────────────
    kex_name = tls.key_exchange or "UNKNOWN"
    kex_qs = classify_kex(kex_name)
    assessment["key_exchange_status"] = _KEX_STATUS_MAP.get(kex_qs, KX_VULNERABLE)
    assessment["key_exchange_algorithm"] = kex_name

    if kex_qs == QuantumStatus.PQC_SAFE:
        assessment["key_exchange_details"] = (
            f"{kex_name} is a NIST-approved post-quantum KEM (FIPS 203). "
            "Key exchange is safe against both classical and quantum adversaries."
        )
        nist_refs.append("NIST FIPS 203 — ML-KEM (Module-Lattice Key Encapsulation)")
    elif kex_qs == QuantumStatus.HYBRID_PQC:
        assessment["key_exchange_details"] = (
            f"{kex_name} is a hybrid classical+PQC key exchange. "
            "Provides transitional quantum safety while maintaining classical interoperability."
        )
        nist_refs.append("NIST FIPS 203 — ML-KEM (hybrid transitional)")
        nist_refs.append("IETF draft-ietf-tls-hybrid-design")
    else:
        assessment["key_exchange_details"] = (
            f"{kex_name} is a classical key exchange vulnerable to Shor's algorithm. "
            "Recorded TLS sessions can be decrypted by a future quantum computer "
            "(Harvest-Now, Decrypt-Later attack)."
        )
        findings.append(
            f"Key exchange '{kex_name}' is quantum-vulnerable (Shor's Algorithm). "
            "Susceptible to HNDL attacks."
        )

    # ── 3.  Certificate / Signature Status ───────────────────────────────
    sig_algo = cert.signature_algorithm or ""
    pk_type = cert.public_key_type or ""
    pk_bits = cert.public_key_bits or 0

    # Evaluate signature algorithm
    sig_qs = classify_signature(sig_algo) if sig_algo else QuantumStatus.VULNERABLE
    # Also check public key type as fallback
    pk_qs = classify_signature(pk_type) if pk_type else QuantumStatus.VULNERABLE

    # Use the better of the two (in case one is PQC)
    cert_qs = sig_qs
    if pk_qs.value < cert_qs.value:  # PQC_SAFE < VULNERABLE in enum order
        cert_qs = pk_qs

    # Map to assessment label
    if cert_qs == QuantumStatus.PQC_SAFE:
        assessment["certificate_status"] = KX_PQC_SAFE
        assessment["certificate_details"] = (
            f"Certificate uses {sig_algo} — a NIST-approved post-quantum signature algorithm. "
            "Authentication is quantum-safe."
        )
        nist_refs.append("NIST FIPS 204 — ML-DSA (Module-Lattice Digital Signature)")
    elif fp.has_hybrid_mode and fp.has_pqc_signature:
        assessment["certificate_status"] = KX_HYBRID
        assessment["certificate_details"] = (
            f"Certificate uses hybrid classical+PQC signature. "
            "Transitional quantum safety for authentication."
        )
    else:
        assessment["certificate_status"] = KX_VULNERABLE
        pk_desc = f"{pk_type}-{pk_bits}" if pk_bits else (pk_type or sig_algo or "Unknown")
        assessment["certificate_details"] = (
            f"Certificate uses {pk_desc} signature — vulnerable to quantum factoring "
            "(Shor's Algorithm). A future CRQC could forge this certificate."
        )
        findings.append(
            f"Certificate signature ({pk_desc}) is quantum-vulnerable. "
            "Authentication can be forged by a Cryptographically Relevant Quantum Computer."
        )

    assessment["certificate_algorithm"] = f"{pk_type}-{pk_bits}" if pk_bits else (sig_algo or "Unknown")

    # ── 4.  Symmetric Cipher Status ──────────────────────────────────────
    cipher_algo = tls.cipher_algorithm or tls.cipher_suite or ""
    cipher_bits = tls.cipher_bits or 0

    sym_qs = classify_symmetric(cipher_algo, cipher_bits)

    if sym_qs in (QuantumStatus.COMPLIANT, QuantumStatus.PQC_SAFE):
        assessment["symmetric_cipher_status"] = SYM_PASS
        assessment["symmetric_details"] = (
            f"{cipher_algo} with {cipher_bits}-bit key — Grover's algorithm reduces "
            f"effective security to {cipher_bits // 2} bits, which is still considered safe."
        )
    elif sym_qs == QuantumStatus.WEAKENED:
        assessment["symmetric_cipher_status"] = SYM_FAIL
        assessment["symmetric_details"] = (
            f"{cipher_algo} with {cipher_bits}-bit key — Grover's algorithm reduces "
            f"effective security to {cipher_bits // 2} bits. Minimum AES-256 or "
            "ChaCha20-Poly1305 required for PQC compliance."
        )
        findings.append(
            f"Symmetric cipher {cipher_algo}-{cipher_bits} weakened by Grover's algorithm. "
            "Upgrade to AES-256."
        )
    else:
        assessment["symmetric_cipher_status"] = SYM_FAIL
        assessment["symmetric_details"] = (
            f"{cipher_algo or 'Unknown cipher'} ({cipher_bits}-bit) is insecure. "
            "Immediately replace with AES-256-GCM or ChaCha20-Poly1305."
        )
        findings.append(
            f"CRITICAL: Symmetric cipher {cipher_algo or 'Unknown'} is broken or severely weakened."
        )

    assessment["symmetric_cipher"] = cipher_algo or "Unknown"
    assessment["symmetric_bits"] = cipher_bits

    # ── 5.  Overall Quantum Risk ─────────────────────────────────────────
    statuses = [
        assessment["tls_status"],
        assessment["key_exchange_status"],
        assessment["certificate_status"],
        assessment["symmetric_cipher_status"],
    ]

    # HNDL vulnerability: if key exchange is not PQC-safe, recorded
    # sessions can be decrypted later by a quantum computer.
    hndl_vulnerable = assessment["key_exchange_status"] == KX_VULNERABLE
    assessment["hndl_vulnerable"] = hndl_vulnerable

    if hndl_vulnerable:
        findings.append(
            "HARVEST-NOW, DECRYPT-LATER: This endpoint's traffic can be recorded today "
            "and decrypted when a sufficiently powerful quantum computer exists."
        )

    # Risk calculation
    fail_count = statuses.count(TLS_FAIL) + statuses.count(KX_VULNERABLE)
    hybrid_count = statuses.count(KX_HYBRID)
    pqc_safe_count = statuses.count(KX_PQC_SAFE) + statuses.count(TLS_PASS)

    if assessment["tls_status"] == TLS_FAIL and assessment["key_exchange_status"] == KX_VULNERABLE:
        risk = RISK_HIGH
        risk_summary = (
            "CRITICAL: Legacy protocol with vulnerable key exchange. "
            "This endpoint is fully exposed to both classical and quantum attacks. "
            "Immediate remediation required."
        )
    elif fail_count >= 2:
        risk = RISK_HIGH
        risk_summary = (
            f"HIGH RISK: {fail_count} of 4 cryptographic dimensions are non-compliant. "
            "Significant exposure to Harvest-Now-Decrypt-Later attacks."
        )
    elif hndl_vulnerable and hybrid_count == 0:
        risk = RISK_HIGH
        risk_summary = (
            "HIGH RISK: Classical-only key exchange — all recorded traffic is vulnerable "
            "to future quantum decryption. No PQC protection in place."
        )
    elif hybrid_count >= 1 and fail_count <= 1:
        risk = RISK_MEDIUM
        risk_summary = (
            "MEDIUM RISK: Hybrid PQC transitional protection in place. "
            "Complete migration to pure PQC algorithms recommended."
        )
    elif pqc_safe_count >= 3:
        risk = RISK_LOW
        risk_summary = (
            "LOW RISK: Endpoint is well-protected with PQC-compliant algorithms. "
            "Continue monitoring for standard updates."
        )
    else:
        risk = RISK_MEDIUM
        risk_summary = (
            f"MEDIUM RISK: Mixed compliance — {pqc_safe_count} compliant, "
            f"{fail_count} non-compliant dimensions."
        )

    assessment["overall_quantum_risk"] = risk
    assessment["risk_summary"] = risk_summary
    assessment["q_score"] = q.total
    assessment["pqc_status"] = q.status.value
    assessment["findings"] = findings
    assessment["nist_references"] = sorted(set(nist_refs))

    return assessment


# ───────────────────────────────────────────────────────────────────────────
# Batch Assessment
# ───────────────────────────────────────────────────────────────────────────

def analyze_batch(summary: ScanSummary) -> Dict[str, Any]:
    """Assess all endpoints in a scan summary and compute aggregate KPIs.

    Returns
    -------
    dict
        - ``assessed_at``       : str
        - ``total_endpoints``   : int
        - ``assessments``       : list[dict]  (per-endpoint)
        - ``aggregate``         : dict  (KPI summary)
    """
    assessments: List[Dict[str, Any]] = []
    for result in summary.results:
        try:
            a = analyze_endpoint(result)
            assessments.append(a)
        except Exception as exc:
            logger.warning("Assessment failed for %s: %s", result.asset.hostname, exc)
            assessments.append({
                "target": result.asset.hostname,
                "port": result.asset.port,
                "overall_quantum_risk": RISK_HIGH,
                "error": str(exc),
            })

    # ── Aggregate KPIs ───────────────────────────────────────────────────
    total = len(assessments)

    # TLS
    tls_pass = sum(1 for a in assessments if a.get("tls_status") == TLS_PASS)
    tls_fail = total - tls_pass

    # Key Exchange
    kex_vuln = sum(1 for a in assessments if a.get("key_exchange_status") == KX_VULNERABLE)
    kex_hybrid = sum(1 for a in assessments if a.get("key_exchange_status") == KX_HYBRID)
    kex_pqc = sum(1 for a in assessments if a.get("key_exchange_status") == KX_PQC_SAFE)

    # Certificate
    cert_vuln = sum(1 for a in assessments if a.get("certificate_status") == KX_VULNERABLE)
    cert_hybrid = sum(1 for a in assessments if a.get("certificate_status") == KX_HYBRID)
    cert_pqc = sum(1 for a in assessments if a.get("certificate_status") == KX_PQC_SAFE)

    # Symmetric
    sym_pass = sum(1 for a in assessments if a.get("symmetric_cipher_status") == SYM_PASS)
    sym_fail = total - sym_pass

    # Risk
    risk_high = sum(1 for a in assessments if a.get("overall_quantum_risk") == RISK_HIGH)
    risk_medium = sum(1 for a in assessments if a.get("overall_quantum_risk") == RISK_MEDIUM)
    risk_low = sum(1 for a in assessments if a.get("overall_quantum_risk") == RISK_LOW)

    # HNDL
    hndl_count = sum(1 for a in assessments if a.get("hndl_vulnerable", False))

    # Average Q-Score
    scores = [a.get("q_score", 0) for a in assessments if "q_score" in a]
    avg_score = round(sum(scores) / len(scores), 1) if scores else 0.0

    aggregate = {
        "total_endpoints": total,
        "average_q_score": avg_score,

        # TLS breakdown
        "tls_pass": tls_pass,
        "tls_fail": tls_fail,
        "tls_pass_pct": round(tls_pass / total * 100, 1) if total else 0,

        # Key Exchange breakdown
        "kex_vulnerable": kex_vuln,
        "kex_hybrid": kex_hybrid,
        "kex_pqc_safe": kex_pqc,
        "kex_vulnerable_pct": round(kex_vuln / total * 100, 1) if total else 0,
        "kex_hybrid_pct": round(kex_hybrid / total * 100, 1) if total else 0,
        "kex_pqc_safe_pct": round(kex_pqc / total * 100, 1) if total else 0,

        # Certificate breakdown
        "cert_vulnerable": cert_vuln,
        "cert_hybrid": cert_hybrid,
        "cert_pqc_safe": cert_pqc,

        # Symmetric breakdown
        "sym_pass": sym_pass,
        "sym_fail": sym_fail,
        "sym_pass_pct": round(sym_pass / total * 100, 1) if total else 0,

        # Risk breakdown
        "risk_high": risk_high,
        "risk_medium": risk_medium,
        "risk_low": risk_low,
        "risk_high_pct": round(risk_high / total * 100, 1) if total else 0,

        # HNDL
        "hndl_vulnerable": hndl_count,
        "hndl_vulnerable_pct": round(hndl_count / total * 100, 1) if total else 0,

        # PQC Status breakdown (from Q-Score classifier)
        "fully_quantum_safe": summary.fully_quantum_safe,
        "pqc_transition": summary.pqc_transition,
        "quantum_vulnerable": summary.quantum_vulnerable,
        "critically_vulnerable": summary.critically_vulnerable,
    }

    return {
        "assessed_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "total_endpoints": total,
        "assessments": assessments,
        "aggregate": aggregate,
    }
