"""Phase 9 — PQC Certification Labeling Engine v2.

Evaluates each ClassifiedAsset from Phase 7 and assigns one of three tiers:

  Tier 1  FULLY_QUANTUM_SAFE  (#00C853 ✅)
    → best_case_score > 90
    → ML-KEM or hybrid with ML-KEM in Probe A findings
    → TLS 1.3
    → ML-DSA or SLH-DSA certificate

  Tier 2  PQC_READY  (#FF6D00 🔶)
    → best_case_score > 70
    → Hybrid KEX with ML-KEM
    → TLS 1.3

  Tier 3  NON_COMPLIANT  (#D50000 ❌)
    → Everything else
    → Includes primary_gap identification and fix_in_days:
        CRITICALLY_VULNERABLE → 7 days
        QUANTUM_VULNERABLE    → 30 days
        Near-miss (>60 best) → 90 days

All scoring draws from ClassifiedAsset — nothing is hardcoded except
the tier threshold constants (which are project-level policy).
"""

from __future__ import annotations

import logging
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any

from backend.models import (
    ClassifiedAsset,
    LabelSummary,
    PQCLabelV9,
    PQCStatus,
)

logger = logging.getLogger("qarmor.labeler")

# ── Tier Policy Constants ────────────────────────────────────────────────────

TIER_1_MIN_BEST = 90
TIER_2_MIN_BEST = 70
TIER_1_VALIDITY_DAYS = 180
TIER_2_VALIDITY_DAYS = 90

# NIST standard references
_NIST_FIPS_203 = "NIST FIPS 203 (ML-KEM)"
_NIST_FIPS_204 = "NIST FIPS 204 (ML-DSA)"
_NIST_FIPS_205 = "NIST FIPS 205 (SLH-DSA)"

# PQC algorithm detection fragments
_PQC_KEX = ("ML-KEM", "MLKEM", "KYBER")
_HYBRID_KEX = ("X25519MLKEM", "X25519KYBER", "X448MLKEM")
_PQC_SIG = ("ML-DSA", "MLDSA", "SLH-DSA", "SLHDSA")

# Badge definitions
BADGE_TIER_1 = {"color": "#00C853", "icon": "✅", "title": "FULLY_QUANTUM_SAFE"}
BADGE_TIER_2 = {"color": "#FF6D00", "icon": "🔶", "title": "PQC_READY"}
BADGE_TIER_3 = {"color": "#D50000", "icon": "❌", "title": "NON_COMPLIANT"}


# ── Legacy constants (backward compatibility with old labeler API) ───────────

LABEL_FULLY_QUANTUM_SAFE = "Fully Quantum Safe"
LABEL_PQC_READY = "PQC Ready"
LABEL_NON_COMPLIANT = "Non-Compliant"
TIER_FULLY_QUANTUM_SAFE = 1
TIER_PQC_READY = 2
TIER_NON_COMPLIANT = 3


# ═══════════════════════════════════════════════════════════════════════════
# Core: Label a single ClassifiedAsset
# ═══════════════════════════════════════════════════════════════════════════

def _label_asset(
    asset: ClassifiedAsset,
    is_demo: bool = False,
    base_url: str = "",
) -> PQCLabelV9:
    """Evaluate a single ClassifiedAsset and return a PQCLabelV9."""
    now = datetime.now(timezone.utc)
    label_id = f"LABEL-{uuid.uuid4().hex[:8].upper()}"

    best_q = asset.best_case_q
    worst_q = asset.worst_case_q
    best_score = asset.best_case_score

    # Extract algorithm info from best-case findings
    kex_algos = _extract_algorithms(best_q.findings, "key exchange")
    sig_algos = _extract_algorithms(best_q.findings, "certificate")
    all_algos = kex_algos + sig_algos if (kex_algos or sig_algos) else [asset.status.value]

    has_pqc_kex = any(
        any(frag in algo.upper() for frag in _PQC_KEX)
        for algo in kex_algos
    )
    has_hybrid_kex = any(
        any(frag in algo.upper() for frag in _HYBRID_KEX)
        for algo in kex_algos
    )
    has_pqc_sig = any(
        any(frag in algo.upper() for frag in _PQC_SIG)
        for algo in sig_algos
    )
    has_tls13 = any("TLS 1.3" in f for f in best_q.findings)

    # ── Tier 1: FULLY_QUANTUM_SAFE ──────────────────────────────────────
    if (
        best_score > TIER_1_MIN_BEST
        and (has_pqc_kex or has_hybrid_kex)
        and has_tls13
        and has_pqc_sig
    ):
        nist_stds = [_NIST_FIPS_203]
        if any("ML-DSA" in a.upper() or "MLDSA" in a.upper() for a in sig_algos):
            nist_stds.append(_NIST_FIPS_204)
        if any("SLH-DSA" in a.upper() or "SLHDSA" in a.upper() for a in sig_algos):
            nist_stds.append(_NIST_FIPS_205)

        return PQCLabelV9(
            label_id=label_id,
            hostname=asset.hostname,
            port=asset.port,
            tier=1,
            certification_title=BADGE_TIER_1["title"],
            badge_color=BADGE_TIER_1["color"],
            badge_icon=BADGE_TIER_1["icon"],
            nist_standards=nist_stds,
            algorithms_in_use=all_algos,
            issued_at=now.isoformat().replace("+00:00", "Z"),
            valid_until=(now + timedelta(days=TIER_1_VALIDITY_DAYS)).isoformat().replace("+00:00", "Z"),
            verification_url=f"{base_url}/api/registry/verify/{label_id}" if base_url else "",
            is_simulated=is_demo,
        )

    # ── Tier 2: PQC_READY ──────────────────────────────────────────────
    if (
        best_score > TIER_2_MIN_BEST
        and (has_hybrid_kex or has_pqc_kex)
        and has_tls13
    ):
        return PQCLabelV9(
            label_id=label_id,
            hostname=asset.hostname,
            port=asset.port,
            tier=2,
            certification_title=BADGE_TIER_2["title"],
            badge_color=BADGE_TIER_2["color"],
            badge_icon=BADGE_TIER_2["icon"],
            nist_standards=[_NIST_FIPS_203],
            algorithms_in_use=all_algos,
            issued_at=now.isoformat().replace("+00:00", "Z"),
            valid_until=(now + timedelta(days=TIER_2_VALIDITY_DAYS)).isoformat().replace("+00:00", "Z"),
            verification_url=f"{base_url}/api/registry/verify/{label_id}" if base_url else "",
            is_simulated=is_demo,
        )

    # ── Tier 3: NON_COMPLIANT ──────────────────────────────────────────
    primary_gap, fix_days = _identify_gap(asset, has_tls13, has_pqc_kex, has_hybrid_kex, has_pqc_sig)

    return PQCLabelV9(
        label_id=label_id,
        hostname=asset.hostname,
        port=asset.port,
        tier=3,
        certification_title=BADGE_TIER_3["title"],
        badge_color=BADGE_TIER_3["color"],
        badge_icon=BADGE_TIER_3["icon"],
        nist_standards=[],
        algorithms_in_use=all_algos,
        issued_at=now.isoformat().replace("+00:00", "Z"),
        valid_until=(now + timedelta(days=30)).isoformat().replace("+00:00", "Z"),
        verification_url=f"{base_url}/api/registry/verify/{label_id}" if base_url else "",
        is_simulated=is_demo,
        primary_gap=primary_gap,
        fix_in_days=fix_days,
    )


def _identify_gap(
    asset: ClassifiedAsset,
    has_tls13: bool,
    has_pqc_kex: bool,
    has_hybrid_kex: bool,
    has_pqc_sig: bool,
) -> tuple[str, int]:
    """Identify the primary compliance gap and recommended fix timeline."""
    if asset.status == PQCStatus.CRITICALLY_VULNERABLE:
        if not has_tls13:
            return "Deprecated TLS version — upgrade to TLS 1.3 immediately", 7
        return "Critical cryptographic weakness — replace deprecated ciphers/keys", 7

    if asset.status == PQCStatus.QUANTUM_VULNERABLE:
        if not has_tls13:
            return "No TLS 1.3 support — required for PQC key exchange", 30
        if not has_pqc_kex and not has_hybrid_kex:
            return "Classical key exchange only — enable X25519+ML-KEM-768 hybrid", 30
        return "Classical certificate — request ML-DSA cert from CA", 30

    # Near-miss: best > 60 but didn't meet Tier 2
    if asset.best_case_score > 60:
        if not has_pqc_kex and not has_hybrid_kex:
            return "Enable hybrid PQC key exchange to reach PQC Ready tier", 90
        if not has_pqc_sig:
            return "Deploy PQC certificate (ML-DSA/SLH-DSA) to reach Fully Quantum Safe", 90
        return "Score improvement needed — optimize cipher configuration", 90

    return "Full PQC migration required — see remediation roadmap", 30


def _extract_algorithms(findings: list[str], category: str) -> list[str]:
    """Extract algorithm names from Q-Score findings for a given category."""
    algos: list[str] = []
    for f in findings:
        lower = f.lower()
        if category in lower:
            # Try to extract algo name after colon or parentheses
            if ":" in f:
                algo_part = f.split(":")[-1].strip()
                if algo_part:
                    algos.append(algo_part)
            elif "(" in f and ")" in f:
                algo_part = f[f.index("(") + 1 : f.index(")")]
                if algo_part:
                    algos.append(algo_part)
    return algos


# ═══════════════════════════════════════════════════════════════════════════
# Public API: label all assets + produce summary
# ═══════════════════════════════════════════════════════════════════════════

def label_classified_assets(
    assets: list[ClassifiedAsset],
    is_demo: bool = False,
    base_url: str = "",
) -> LabelSummary:
    """Label all ClassifiedAssets and produce a LabelSummary.

    Parameters
    ----------
    assets : list[ClassifiedAsset]
        Phase 7 classified assets.
    is_demo : bool
        Whether running in demo mode (labels will have ``is_simulated=True``).
    base_url : str
        Base URL for verification links (e.g. ``http://localhost:8000``).

    Returns
    -------
    LabelSummary
    """
    labels = [_label_asset(a, is_demo=is_demo, base_url=base_url) for a in assets]

    total = len(labels)
    t1 = sum(1 for l in labels if l.tier == 1)
    t2 = sum(1 for l in labels if l.tier == 2)
    t3 = sum(1 for l in labels if l.tier == 3)

    # Aggregate quantum safety score: weighted by worst_case_score
    if assets:
        avg_worst = sum(a.worst_case_score for a in assets) / total
        safety_score = round(avg_worst)
    else:
        safety_score = 0

    exec_summary = _build_executive_summary(total, t1, t2, t3, safety_score, is_demo)

    return LabelSummary(
        labels=labels,
        total_assets=total,
        tier_1_count=t1,
        tier_2_count=t2,
        tier_3_count=t3,
        tier_1_pct=round(t1 / total * 100, 1) if total else 0.0,
        tier_2_pct=round(t2 / total * 100, 1) if total else 0.0,
        tier_3_pct=round(t3 / total * 100, 1) if total else 0.0,
        quantum_safety_score=safety_score,
        executive_summary=exec_summary,
        data_mode="demo" if is_demo else "live",
    )


def _build_executive_summary(
    total: int, t1: int, t2: int, t3: int, safety: int, is_demo: bool,
) -> str:
    """Build a plain-English executive summary."""
    if total == 0:
        return "No assets scanned."

    compliant_pct = round((t1 + t2) / total * 100, 1) if total else 0
    parts = [
        f"{total} cryptographic endpoints evaluated.",
        f"{t1} Fully Quantum Safe ({round(t1/total*100,1)}%), "
        f"{t2} PQC Ready ({round(t2/total*100,1)}%), "
        f"{t3} Non-Compliant ({round(t3/total*100,1)}%).",
        f"Aggregate quantum safety score: {safety}/100.",
    ]

    if compliant_pct >= 80:
        parts.append("Strong PQC posture — continue monitoring NIST algorithm updates.")
    elif compliant_pct >= 50:
        parts.append("Moderate PQC posture — prioritize Non-Compliant assets for hybrid KEX migration.")
    else:
        parts.append("Weak PQC posture — urgent action required on all Non-Compliant endpoints.")

    if is_demo:
        parts.append("[DEMO MODE — simulated data]")

    return " ".join(parts)


# ═══════════════════════════════════════════════════════════════════════════
# Legacy API (backward compatibility with Phase 4 labeler)
# ═══════════════════════════════════════════════════════════════════════════

def evaluate_and_label(assessment_results: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Legacy Phase 4 labeling from assessment dicts.

    Kept for backward compatibility with Phase 5 attestor and old app.py endpoints.
    """
    TLS_PASS = "PASS"
    KX_PQC_SAFE = "PQC_SAFE"
    KX_HYBRID = "HYBRID"

    labels = []
    for a in assessment_results:
        target = a.get("target", "unknown")
        port = a.get("port", 443)
        tls_status = a.get("tls_status", "FAIL")
        kex_status = a.get("key_exchange_status", "VULNERABLE")
        cert_status = a.get("certificate_status", "VULNERABLE")
        tls_version = a.get("tls_version", "")
        kex_algo = a.get("key_exchange_algorithm", "")
        cert_algo = a.get("certificate_algorithm", "")
        risk = a.get("overall_quantum_risk", "HIGH")
        q_score = a.get("q_score", 0)

        if tls_status == TLS_PASS and kex_status == KX_PQC_SAFE and cert_status == KX_PQC_SAFE:
            label_name, tier, icon = LABEL_FULLY_QUANTUM_SAFE, 1, "✅"
            reason = "TLS 1.3 with pure NIST PQC KEM and PQC certificate chain"
        elif tls_status == TLS_PASS and kex_status == KX_HYBRID:
            label_name, tier, icon = LABEL_PQC_READY, 2, "🔶"
            reason = "TLS 1.3 with hybrid key exchange (classical + PQC)"
        else:
            label_name, tier, icon = LABEL_NON_COMPLIANT, 3, "❌"
            reasons = []
            if tls_status != TLS_PASS:
                reasons.append(f"Legacy TLS ({tls_version or 'unknown'})")
            if kex_status == "VULNERABLE":
                reasons.append(f"Classical key exchange ({kex_algo or 'unknown'})")
            reason = "; ".join(reasons) if reasons else "Does not meet Tier 1 or Tier 2"

        labels.append({
            "target": target, "port": port, "label": label_name,
            "tier": tier, "tier_icon": icon, "reason": reason,
            "tls_version": tls_version, "key_exchange": kex_algo,
            "certificate": cert_algo, "risk": risk, "q_score": q_score,
        })

    labels.sort(key=lambda x: (x["tier"], -x["q_score"]))
    return labels


def summarize_labels(labels: list[dict[str, Any]]) -> dict[str, Any]:
    """Legacy Phase 4 summary — aggregate statistics for label list."""
    total = len(labels)
    fs = sum(1 for l in labels if l["tier"] == 1)
    pr = sum(1 for l in labels if l["tier"] == 2)
    nc = sum(1 for l in labels if l["tier"] == 3)
    pct = lambda n: f"{round(n / total * 100, 1)}%" if total else "0%"
    return {
        "total_endpoints": total,
        "fully_quantum_safe": fs, "fully_quantum_safe_pct": pct(fs),
        "pqc_ready": pr, "pqc_ready_pct": pct(pr),
        "non_compliant": nc, "non_compliant_pct": pct(nc),
        "labels": labels,
    }
