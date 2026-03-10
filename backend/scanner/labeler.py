"""Module 9: Certification Labeling Engine — 3-Tier PQC Compliance Labels.

Evaluates each endpoint's cryptographic posture from Phase 2 assessment results
and awards one of three certification tiers:

    ✅  Fully Quantum Safe   — TLS 1.3 + pure NIST PQC KEM (ML-KEM) + PQC cert chain (ML-DSA/SLH-DSA)
    🔶  PQC Ready            — TLS 1.3 + hybrid KEX (X25519+ML-KEM-768), classical cert acceptable
    ❌  Non-Compliant        — Legacy TLS (< 1.3) or purely classical KEX (RSA/ECDH)
"""

from __future__ import annotations

from typing import Any, Dict, List


# ── Constants ────────────────────────────────────────────────────────────────

LABEL_FULLY_QUANTUM_SAFE = "Fully Quantum Safe"
LABEL_PQC_READY = "PQC Ready"
LABEL_NON_COMPLIANT = "Non-Compliant"

TIER_FULLY_QUANTUM_SAFE = 1
TIER_PQC_READY = 2
TIER_NON_COMPLIANT = 3

# Assessment status values (must match assessment.py constants)
TLS_PASS = "PASS"
TLS_FAIL = "FAIL"
KX_PQC_SAFE = "PQC_SAFE"
KX_HYBRID = "HYBRID"
KX_VULNERABLE = "VULNERABLE"


# ── Core Evaluation ──────────────────────────────────────────────────────────

def _evaluate_single(assessment: Dict[str, Any]) -> Dict[str, Any]:
    """Evaluate a single endpoint assessment and return a label record.

    Parameters
    ----------
    assessment : dict
        A per-endpoint assessment dict produced by ``assessment.analyze_endpoint``.
        Expected keys: ``target``, ``port``, ``tls_status``, ``tls_version``,
        ``key_exchange_status``, ``key_exchange_algorithm``,
        ``certificate_status``, ``certificate_algorithm``,
        ``symmetric_cipher_status``, ``symmetric_cipher``,
        ``overall_quantum_risk``, ``hndl_vulnerable``, ``q_score``.

    Returns
    -------
    dict
        Label record with keys: ``target``, ``port``, ``label``, ``tier``,
        ``tier_icon``, ``reason``, ``tls_version``, ``key_exchange``,
        ``certificate``, ``risk``, ``q_score``.
    """
    target = assessment.get("target", "unknown")
    port = assessment.get("port", 443)

    tls_status = assessment.get("tls_status", TLS_FAIL)
    kex_status = assessment.get("key_exchange_status", KX_VULNERABLE)
    cert_status = assessment.get("certificate_status", KX_VULNERABLE)

    tls_version = assessment.get("tls_version", "")
    kex_algo = assessment.get("key_exchange_algorithm", "")
    cert_algo = assessment.get("certificate_algorithm", "")
    risk = assessment.get("overall_quantum_risk", "HIGH")
    q_score = assessment.get("q_score", 0)

    # ── Tier 1: Fully Quantum Safe ───────────────────────────────────
    # Requirements:
    #   1. TLS 1.3 (tls_status == PASS)
    #   2. Pure PQC key exchange (key_exchange_status == PQC_SAFE)
    #   3. PQC certificate chain (certificate_status == PQC_SAFE)
    if (
        tls_status == TLS_PASS
        and kex_status == KX_PQC_SAFE
        and cert_status == KX_PQC_SAFE
    ):
        return {
            "target": target,
            "port": port,
            "label": LABEL_FULLY_QUANTUM_SAFE,
            "tier": TIER_FULLY_QUANTUM_SAFE,
            "tier_icon": "✅",
            "reason": "TLS 1.3 with pure NIST PQC KEM and PQC certificate chain",
            "tls_version": tls_version,
            "key_exchange": kex_algo,
            "certificate": cert_algo,
            "risk": risk,
            "q_score": q_score,
        }

    # ── Tier 2: PQC Ready ────────────────────────────────────────────
    # Requirements:
    #   1. TLS 1.3 (tls_status == PASS)
    #   2. Hybrid key exchange (key_exchange_status == HYBRID)
    #   Classical certificate is acceptable
    if tls_status == TLS_PASS and kex_status == KX_HYBRID:
        return {
            "target": target,
            "port": port,
            "label": LABEL_PQC_READY,
            "tier": TIER_PQC_READY,
            "tier_icon": "🔶",
            "reason": "TLS 1.3 with hybrid key exchange (classical + PQC)",
            "tls_version": tls_version,
            "key_exchange": kex_algo,
            "certificate": cert_algo,
            "risk": risk,
            "q_score": q_score,
        }

    # ── Tier 3: Non-Compliant / No Label ─────────────────────────────
    # Catches everything else:
    #   - Legacy TLS (< 1.3)
    #   - Purely classical key exchange (RSA, ECDHE without PQC)
    #   - Any combination that doesn't meet Tier 1 or Tier 2
    reasons = []
    if tls_status != TLS_PASS:
        reasons.append(f"Legacy TLS ({tls_version or 'unknown'})")
    if kex_status == KX_VULNERABLE:
        reasons.append(f"Classical key exchange ({kex_algo or 'unknown'})")
    if not reasons:
        reasons.append("Does not meet PQC Ready or Fully Quantum Safe criteria")

    return {
        "target": target,
        "port": port,
        "label": LABEL_NON_COMPLIANT,
        "tier": TIER_NON_COMPLIANT,
        "tier_icon": "❌",
        "reason": "; ".join(reasons),
        "tls_version": tls_version,
        "key_exchange": kex_algo,
        "certificate": cert_algo,
        "risk": risk,
        "q_score": q_score,
    }


# ── Public API ───────────────────────────────────────────────────────────────

def evaluate_and_label(assessment_results: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Evaluate all endpoint assessments and return certification labels.

    Parameters
    ----------
    assessment_results : list[dict]
        List of per-endpoint assessment dicts from ``analyze_batch()["assessments"]``.

    Returns
    -------
    list[dict]
        List of label records, one per endpoint, sorted by tier (best first).
    """
    labels = [_evaluate_single(a) for a in assessment_results]
    labels.sort(key=lambda x: (x["tier"], -x["q_score"]))
    return labels


def summarize_labels(labels: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Produce aggregate statistics for the labeling results.

    Parameters
    ----------
    labels : list[dict]
        Output from ``evaluate_and_label()``.

    Returns
    -------
    dict
        Summary with counts and percentages for each tier.
    """
    total = len(labels)
    fully_safe = sum(1 for l in labels if l["tier"] == TIER_FULLY_QUANTUM_SAFE)
    pqc_ready = sum(1 for l in labels if l["tier"] == TIER_PQC_READY)
    non_compliant = sum(1 for l in labels if l["tier"] == TIER_NON_COMPLIANT)

    def pct(n: int) -> str:
        return f"{round(n / total * 100, 1)}%" if total > 0 else "0%"

    return {
        "total_endpoints": total,
        "fully_quantum_safe": fully_safe,
        "fully_quantum_safe_pct": pct(fully_safe),
        "pqc_ready": pqc_ready,
        "pqc_ready_pct": pct(pqc_ready),
        "non_compliant": non_compliant,
        "non_compliant_pct": pct(non_compliant),
        "labels": labels,
    }
