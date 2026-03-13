"""Enterprise cyber rating logic for PQC posture rollups."""

from __future__ import annotations

from typing import Any


TIER_CRITERIA = [
    {
        "tier": "Critical",
        "security_level": "Insecure/exploitable",
        "compliance_criteria": "SSL v2/v3; Key <1024-bit; weak ciphers; known CVEs",
        "priority_action": "Immediate: isolate, replace cert, patch",
    },
    {
        "tier": "Legacy",
        "security_level": "Weak but operational",
        "compliance_criteria": "TLS 1.0/1.1; CBC/3DES; no forward secrecy; ~1024-bit",
        "priority_action": "Remediation: upgrade TLS, rotate certs, remove weak suites",
    },
    {
        "tier": "Standard",
        "security_level": "Acceptable enterprise",
        "compliance_criteria": "TLS 1.2; key >2048-bit; mostly strong; backward compat allowed",
        "priority_action": "Improve: disable legacy protocols, standardise suites",
    },
    {
        "tier": "Elite-PQC",
        "security_level": "Modern best-practice",
        "compliance_criteria": "TLS 1.3; AES-GCM/ChaCha20; ECDHE+ML-KEM; >2048-bit; HSTS",
        "priority_action": "Maintain: periodic monitoring, recommended baseline",
    },
]


def get_display_tier(pqc_status: str) -> str:
    """Map per-asset PQC status values to UI display tiers."""
    mapping = {
        "FULLY_QUANTUM_SAFE": "Elite-PQC",
        "PQC_TRANSITION": "Standard",
        "QUANTUM_VULNERABLE": "Legacy",
        "CRITICALLY_VULNERABLE": "Critical",
        "UNKNOWN": "Unclassified",
    }
    return mapping.get((pqc_status or "UNKNOWN").upper(), "Unclassified")


def _clamp(value: int, minimum: int, maximum: int) -> int:
    return max(minimum, min(maximum, value))


def _as_int(value: Any, default: int = 0) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def _resolve_enterprise_tier(enterprise_score: int) -> str:
    if enterprise_score < 400:
        return "Legacy"
    if enterprise_score <= 700:
        return "Standard"
    return "Elite-PQC"


def _tier_label(tier: str) -> str:
    labels = {
        "Legacy": "Indicates a weaker security posture with urgent modernization needs",
        "Standard": "Indicates an acceptable enterprise posture with clear improvement headroom",
        "Elite-PQC": "Indicates a stronger security posture",
    }
    return labels.get(tier, "Indicates a baseline security posture")


def compute_enterprise_cyber_rating(asset_scores: list[dict]) -> dict[str, Any]:
    """Compute enterprise-wide score and tiering from per-asset q_scores."""
    normalized_assets: list[dict[str, Any]] = []
    q_values: list[int] = []

    for item in asset_scores or []:
        hostname = str(item.get("hostname") or "unknown")
        q_score = _clamp(_as_int(item.get("q_score"), 0), 0, 100)
        display_tier = get_display_tier(str(item.get("pqc_status") or "UNKNOWN"))

        normalized_assets.append(
            {
                "hostname": hostname,
                "q_score": q_score,
                "display_tier": display_tier,
            }
        )
        q_values.append(q_score)

    average_q = (sum(q_values) / len(q_values)) if q_values else 0.0
    enterprise_score = _clamp(int(round(average_q * 10)), 0, 1000)

    tier = _resolve_enterprise_tier(enterprise_score)

    return {
        "enterprise_score": enterprise_score,
        "tier": tier,
        "display_tier": tier,
        "tier_label": _tier_label(tier),
        "per_asset": normalized_assets,
    }
