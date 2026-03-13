"""Negotiation policy analysis and PQC migration heatmap logic."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from pydantic import BaseModel, Field


class NegotiationPolicy(BaseModel):
    """Negotiation posture for a single hostname based on tri-probe behavior."""

    hostname: str
    pqc_supported: bool
    tls13_supported: bool
    downgrade_possible: bool
    tls11_accepted: bool
    negotiation_tier: str
    negotiation_security_score: int
    client_segmentation: dict[str, str] = Field(default_factory=dict)
    policy_summary: str


def _get_field(obj: Any, *names: str) -> Any:
    """Read the first matching field from an object or mapping."""
    if obj is None:
        return None

    for name in names:
        if isinstance(obj, Mapping) and name in obj:
            return obj[name]
        if hasattr(obj, name):
            return getattr(obj, name)

    return None


def _as_text(value: Any) -> str:
    if value is None:
        return ""
    return str(value).strip()


def _contains_pqc_kex(kex_name: str) -> bool:
    normalized = kex_name.upper().replace("-", "").replace("_", "")
    return "MLKEM" in normalized or "X25519MLKEM768" in normalized


def _normalize_tls_version(value: str) -> str:
    normalized = value.strip().upper().replace(" ", "")
    normalized = normalized.replace("TLSV", "TLS")
    return normalized


def _derive_negotiation_tier(
    pqc_supported: bool,
    tls13_supported: bool,
    downgrade_possible: bool,
    tls11_accepted: bool,
) -> str:
    if tls11_accepted:
        return "CRITICAL"
    if pqc_supported and not downgrade_possible:
        return "STRONG"
    if pqc_supported and downgrade_possible:
        return "MEDIUM"
    if (not pqc_supported) and tls13_supported and (not downgrade_possible):
        return "CLASSICAL"
    return "WEAK"


def _build_client_segmentation(
    probe_a: Any,
    probe_b: Any,
    probe_c: Any,
    pqc_supported: bool,
    tls13_supported: bool,
    downgrade_possible: bool,
    tls11_accepted: bool,
) -> dict[str, str]:
    a_tls = _as_text(_get_field(probe_a, "tls_version", "version"))
    a_kex = _as_text(_get_field(probe_a, "kex", "key_exchange"))
    a_cipher = _as_text(_get_field(probe_a, "cipher", "cipher_suite"))

    b_tls = _as_text(_get_field(probe_b, "tls_version", "version"))
    b_kex = _as_text(_get_field(probe_b, "kex", "key_exchange"))
    b_cipher = _as_text(_get_field(probe_b, "cipher", "cipher_suite"))

    c_tls = _as_text(_get_field(probe_c, "tls_version", "version"))
    c_kex = _as_text(_get_field(probe_c, "kex", "key_exchange"))
    c_cipher = _as_text(_get_field(probe_c, "cipher", "cipher_suite"))

    if pqc_supported:
        pqc_clients = (
            f"PQC-capable clients negotiate {a_kex or 'a PQC-capable key exchange'} "
            f"on {a_tls or 'the modern path'} with {a_cipher or 'the preferred cipher suite'}."
        )
    else:
        pqc_clients = (
            "PQC-capable clients do not receive a PQC key exchange and instead fall back "
            "to classical negotiation behavior."
        )

    if tls13_supported:
        classical_clients = (
            f"Classical modern clients negotiate {b_tls or 'TLS 1.3'} using "
            f"{b_kex or 'classical ephemeral exchange'} and {b_cipher or 'a strong suite'}."
        )
    else:
        classical_clients = (
            "Classical modern clients are not consistently served by TLS 1.3 and may be "
            "forced onto older protocol paths."
        )

    if tls11_accepted:
        legacy_clients = (
            f"Legacy clients can negotiate {c_tls or 'legacy TLS'} with "
            f"{c_kex or 'legacy key exchange'} and {c_cipher or 'legacy suites'}, "
            "creating critical downgrade exposure."
        )
    elif downgrade_possible:
        legacy_clients = (
            f"Legacy clients can downgrade to {c_tls or 'TLS 1.2-class protocols'} "
            f"with {c_kex or 'classical key exchange'}, leaving residual downgrade risk."
        )
    else:
        legacy_clients = (
            "Legacy protocol negotiation appears constrained, reducing practical fallback "
            "paths for outdated clients."
        )

    return {
        "pqc_clients": pqc_clients,
        "classical_clients": classical_clients,
        "legacy_clients": legacy_clients,
    }


def _build_policy_summary(
    pqc_supported: bool,
    tls13_supported: bool,
    downgrade_possible: bool,
    tls11_accepted: bool,
) -> str:
    if tls11_accepted:
        return (
            "The endpoint accepts TLS 1.1 or older negotiation, which creates a critical "
            "downgrade pathway and high HNDL exposure despite any modern protocol support."
        )
    if pqc_supported and not downgrade_possible:
        return (
            "The endpoint presents a strong PQC-capable negotiation posture with no observed "
            "downgrade path, materially lowering long-term HNDL risk."
        )
    if pqc_supported and downgrade_possible:
        return (
            "The endpoint offers PQC-capable negotiation but still permits downgrade behavior, "
            "so HNDL risk remains for sessions that fall back."
        )
    if (not pqc_supported) and tls13_supported and (not downgrade_possible):
        return (
            "The endpoint is classical-only but modern and stable in negotiation, resulting in "
            "moderate HNDL risk driven by non-PQC key exchange dependence."
        )
    if tls13_supported:
        return (
            "The endpoint has mixed negotiation behavior with downgrade risk, leaving meaningful "
            "HNDL exposure under less capable client paths."
        )
    return (
        "The endpoint lacks robust modern negotiation controls and remains highly exposed to "
        "downgrade and HNDL risk."
    )


def _derive_hostname(*probes: Any) -> str:
    for probe in probes:
        hostname = _as_text(_get_field(probe, "hostname", "host", "target", "sni"))
        if hostname:
            return hostname
    return "unknown"


def analyze_negotiation_policy(probe_a: Any, probe_b: Any, probe_c: Any) -> NegotiationPolicy:
    """Analyze tri-probe negotiation behavior into a policy model."""
    a_kex = _as_text(_get_field(probe_a, "kex", "key_exchange"))
    b_tls = _normalize_tls_version(_as_text(_get_field(probe_b, "tls_version", "version")))
    c_tls = _normalize_tls_version(_as_text(_get_field(probe_c, "tls_version", "version")))

    pqc_supported = _contains_pqc_kex(a_kex)
    tls13_supported = b_tls == "TLS1.3"
    downgrade_possible = c_tls in {"TLS1.2", "TLS1.1", "TLS1.0"}
    tls11_accepted = c_tls in {"TLS1.1", "TLS1.0", "SSLv3"}

    negotiation_tier = _derive_negotiation_tier(
        pqc_supported=pqc_supported,
        tls13_supported=tls13_supported,
        downgrade_possible=downgrade_possible,
        tls11_accepted=tls11_accepted,
    )

    security_score = 0
    if pqc_supported:
        security_score += 10
    if tls13_supported:
        security_score += 5
    if downgrade_possible:
        security_score -= 10
    if tls11_accepted:
        security_score -= 20

    return NegotiationPolicy(
        hostname=_derive_hostname(probe_a, probe_b, probe_c),
        pqc_supported=pqc_supported,
        tls13_supported=tls13_supported,
        downgrade_possible=downgrade_possible,
        tls11_accepted=tls11_accepted,
        negotiation_tier=negotiation_tier,
        negotiation_security_score=security_score,
        client_segmentation=_build_client_segmentation(
            probe_a=probe_a,
            probe_b=probe_b,
            probe_c=probe_c,
            pqc_supported=pqc_supported,
            tls13_supported=tls13_supported,
            downgrade_possible=downgrade_possible,
            tls11_accepted=tls11_accepted,
        ),
        policy_summary=_build_policy_summary(
            pqc_supported=pqc_supported,
            tls13_supported=tls13_supported,
            downgrade_possible=downgrade_possible,
            tls11_accepted=tls11_accepted,
        ),
    )


def _status_to_row(pqc_status: str) -> str:
    normalized = pqc_status.upper()
    if normalized == "FULLY_QUANTUM_SAFE":
        return "pqc_ready"
    if normalized == "PQC_TRANSITION":
        return "transition"
    return "legacy"


def _tier_to_col(negotiation_tier: str) -> str:
    normalized = negotiation_tier.upper()
    if normalized in {"STRONG", "CLASSICAL"}:
        return "strong"
    if normalized == "MEDIUM":
        return "medium"
    return "weak"


def compute_heatmap(assets: list) -> dict[str, Any]:
    """Build a 3x3 migration heatmap from PQC status and negotiation tier."""
    rows = ("pqc_ready", "transition", "legacy")
    cols = ("strong", "medium", "weak")

    grid: dict[str, dict[str, dict[str, Any]]] = {
        row: {col: {"count": 0, "hostnames": []} for col in cols}
        for row in rows
    }

    for idx, asset in enumerate(assets or []):
        pqc_status = _as_text(_get_field(asset, "pqc_status", "status"))
        negotiation_tier = _as_text(_get_field(asset, "negotiation_tier"))
        hostname = _as_text(_get_field(asset, "hostname", "host", "target"))

        row = _status_to_row(pqc_status)
        col = _tier_to_col(negotiation_tier)
        cell = grid[row][col]
        cell["count"] += 1
        cell["hostnames"].append(hostname or f"asset-{idx + 1}")

    best_row = rows[0]
    best_col = cols[0]
    best_count = -1
    for row in rows:
        for col in cols:
            cell_count = int(grid[row][col]["count"])
            if cell_count > best_count:
                best_count = cell_count
                best_row = row
                best_col = col

    return {
        "grid": grid,
        "migration_arrow": {
            "current_state": {"row": best_row, "col": best_col},
            "target_state": {"row": "pqc_ready", "col": "strong"},
        },
    }
