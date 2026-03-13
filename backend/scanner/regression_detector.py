"""Phase 8 — Regression Detection Engine.

Compares the current classified scan against the previous scan stored in the
database and detects three categories of regression:

  1. **New Assets (Shadow IT)**
     Hostnames present in the current scan but absent from the previous scan.
     Urgency: HIGH — unknown attack surface.

  2. **Q-Score Regressions**
     worst_case_score dropped between scans.
       • Drop ≥ 5  → HIGH
       • Drop 1-4  → MEDIUM

  3. **Missed Upgrades**
     Certificate serial changed (i.e. cert was renewed) but the signature
     algorithm did NOT improve toward PQC.  Urgency: MEDIUM — missed window.

All logic reads from ``database.py`` — nothing is hardcoded.
"""

from __future__ import annotations

import json
import logging
from typing import Any

from backend.models import RegressionEntry, RegressionReport
from backend.scanner import database as db

logger = logging.getLogger("qarmor.regression")

# PQC algorithm fragments — ordered by strength.  Any algo containing one of
# these is considered "better" than classical (RSA / ECDSA / SHA-*).
_PQC_SIG_FRAGMENTS = ("ML-DSA", "MLDSA", "SLH-DSA", "SLHDSA")
_HYBRID_FRAGMENTS = ("X25519MLKEM", "X25519KYBER", "X448MLKEM")

# Signature improvement hierarchy (higher index = better).
_SIG_RANK: dict[str, int] = {
    "SHA1":    0,
    "SHA256":  1,
    "SHA384":  2,
    "SHA512":  2,
    "ECDSA":   3,
    "ED25519": 4,
    "ED448":   4,
    "ML-DSA":  5,
    "SLH-DSA": 5,
}


def _sig_rank(algo: str) -> int:
    """Return a numeric rank for a signature algorithm string."""
    upper = (algo or "").upper()
    best = 0
    for frag, rank in _SIG_RANK.items():
        if frag in upper:
            best = max(best, rank)
    return best


def _parse_assets(scan_row: dict) -> dict[str, dict[str, Any]]:
    """Parse ``results_json`` from a scan row into {hostname: asset_dict}."""
    raw = scan_row.get("results_json", "[]")
    try:
        items = json.loads(raw) if isinstance(raw, str) else raw
    except (json.JSONDecodeError, TypeError):
        items = []
    return {a.get("hostname", ""): a for a in items if isinstance(a, dict) and a.get("hostname")}


def _get_asset_scores(scan_id: int) -> dict[str, dict[str, Any]]:
    """Load asset_scores rows for a scan and return {hostname: row_dict}."""
    try:
        with db._connect() as conn:
            rows = conn.execute(
                "SELECT * FROM asset_scores WHERE scan_id=?", (scan_id,)
            ).fetchall()
        return {r["hostname"]: dict(r) for r in rows}
    except Exception:
        return {}


# ═══════════════════════════════════════════════════════════════════════════
# Public API
# ═══════════════════════════════════════════════════════════════════════════

def detect_regressions(
    current_assets: list[dict[str, Any]],
    current_scan_id: int | None = None,
    previous_scan: dict[str, Any] | None = None,
    data_mode: str = "live",
) -> RegressionReport:
    """Compare *current_assets* against the previous scan and return findings.

    Parameters
    ----------
    current_assets : list[dict]
        ClassifiedAsset dicts from the current scan (model_dump output).
    current_scan_id : int | None
        Database scan ID for the current scan (informational).
    previous_scan : dict | None
        If ``None`` the function loads the previous scan from the database
        via ``db.load_previous_scan()``.
    data_mode : str
        ``"live"`` or ``"demo"``.

    Returns
    -------
    RegressionReport
    """
    report = RegressionReport(
        scan_id=current_scan_id,
        data_mode=data_mode,
    )

    # ── Load previous scan ───────────────────────────────────────────────
    if previous_scan is None:
        previous_scan = db.load_previous_scan()

    if not previous_scan:
        logger.info("No previous scan found — regression detection skipped")
        return report

    prev_id = previous_scan.get("id")
    report.previous_scan_id = prev_id

    # Build lookup maps
    prev_assets_json = _parse_assets(previous_scan)
    prev_scores = _get_asset_scores(prev_id) if prev_id else {}

    # Merge both sources for best coverage
    prev_map: dict[str, dict] = {}
    for hostname, data in prev_assets_json.items():
        prev_map[hostname] = data
    for hostname, data in prev_scores.items():
        if hostname not in prev_map:
            prev_map[hostname] = data
        else:
            prev_map[hostname].update(data)

    current_map: dict[str, dict] = {
        a.get("hostname", ""): a for a in current_assets if a.get("hostname")
    }

    # ── 1. New Assets (Shadow IT) ────────────────────────────────────────
    new_hostnames = sorted(set(current_map.keys()) - set(prev_map.keys()))
    for hostname in new_hostnames:
        asset = current_map[hostname]
        report.new_assets.append(RegressionEntry(
            hostname=hostname,
            port=asset.get("port", 443),
            urgency="HIGH",
            category="new_asset",
            description=f"New asset discovered: {hostname} — not present in previous scan",
            current_value=asset.get("status", "UNKNOWN"),
            recommended_action="Investigate origin; verify this asset is authorized and scan its cryptographic posture",
        ))

    # ── 2. Q-Score Regressions ───────────────────────────────────────────
    common_hosts = sorted(set(current_map.keys()) & set(prev_map.keys()))
    for hostname in common_hosts:
        curr = current_map[hostname]
        prev = prev_map[hostname]

        curr_worst = curr.get("worst_case_score", curr.get("worst_score", 0))
        prev_worst = prev.get("worst_case_score", prev.get("worst_score", 0))

        drop = prev_worst - curr_worst
        if drop >= 1:
            urgency = "HIGH" if drop >= 5 else "MEDIUM"
            report.score_regressions.append(RegressionEntry(
                hostname=hostname,
                port=curr.get("port", 443),
                urgency=urgency,
                category="score_regression",
                description=(
                    f"Q-Score dropped by {drop} points "
                    f"(from {prev_worst} to {curr_worst})"
                ),
                previous_value=str(prev_worst),
                current_value=str(curr_worst),
                recommended_action=(
                    "Immediate investigation required — significant security degradation"
                    if urgency == "HIGH"
                    else "Review configuration changes since last scan"
                ),
            ))

    # ── 3. Missed Upgrades ───────────────────────────────────────────────
    for hostname in common_hosts:
        curr = current_map[hostname]
        prev = prev_map[hostname]

        # Detect certificate renewal: different serial number
        curr_cert_serial = _extract_cert_serial(curr)
        prev_cert_serial = _extract_cert_serial(prev)

        if not curr_cert_serial or not prev_cert_serial:
            continue
        if curr_cert_serial == prev_cert_serial:
            continue  # cert not renewed

        # Certificate was renewed.  Did the sig algo improve?
        curr_sig = _extract_sig_algo(curr)
        prev_sig = _extract_sig_algo(prev)

        curr_rank = _sig_rank(curr_sig)
        prev_rank = _sig_rank(prev_sig)

        if curr_rank <= prev_rank and curr_rank < 5:
            # Signature did not improve toward PQC
            report.missed_upgrades.append(RegressionEntry(
                hostname=hostname,
                port=curr.get("port", 443),
                urgency="MEDIUM",
                category="missed_upgrade",
                description=(
                    f"Certificate renewed (serial changed) but signature algorithm "
                    f"not upgraded toward PQC: {prev_sig} → {curr_sig}"
                ),
                previous_value=prev_sig,
                current_value=curr_sig,
                recommended_action=(
                    "Request ML-DSA or SLH-DSA certificate from CA at next renewal opportunity"
                ),
            ))

    report.total_findings = (
        len(report.new_assets) + len(report.score_regressions) + len(report.missed_upgrades)
    )

    # Persist alerts for HIGH-urgency findings
    _persist_alerts(report, current_scan_id)

    return report


def detect_regressions_demo(
    current_assets: list[Any],
    baseline_assets: list[Any],
    current_scan_id: int | None = None,
) -> RegressionReport:
    """Detect regressions by comparing two in-memory asset lists (demo mode).

    Instead of querying the database for the previous scan, this accepts
    ``baseline_assets`` directly — used with ``get_demo_baseline_fingerprints()``.

    Accepts both Pydantic model objects and plain dicts.
    """
    # Normalise to dicts (handles both ClassifiedAsset Pydantic models and raw dicts)
    def _to_dict(obj: Any) -> dict:
        if isinstance(obj, dict):
            return obj
        if hasattr(obj, "model_dump"):
            return obj.model_dump(mode="json")
        return dict(obj)

    curr_dicts = [_to_dict(a) for a in current_assets]
    base_dicts = [_to_dict(a) for a in baseline_assets]

    report = RegressionReport(
        scan_id=current_scan_id,
        data_mode="demo",
    )

    current_map = {a.get("hostname", ""): a for a in curr_dicts if a.get("hostname")}
    prev_map = {a.get("hostname", ""): a for a in base_dicts if a.get("hostname")}

    # 1. New assets
    for hostname in sorted(set(current_map.keys()) - set(prev_map.keys())):
        asset = current_map[hostname]
        report.new_assets.append(RegressionEntry(
            hostname=hostname,
            port=asset.get("port", 443),
            urgency="HIGH",
            category="new_asset",
            description=f"New asset discovered: {hostname} — not present in baseline scan",
            current_value=asset.get("status", "UNKNOWN"),
            recommended_action="Investigate origin; verify authorization and scan posture",
        ))

    # 2. Score regressions
    for hostname in sorted(set(current_map.keys()) & set(prev_map.keys())):
        curr = current_map[hostname]
        prev = prev_map[hostname]
        curr_worst = curr.get("worst_case_score", curr.get("worst_score", 0))
        prev_worst = prev.get("worst_case_score", prev.get("worst_score", 0))
        drop = prev_worst - curr_worst
        if drop >= 1:
            urgency = "HIGH" if drop >= 5 else "MEDIUM"
            report.score_regressions.append(RegressionEntry(
                hostname=hostname,
                port=curr.get("port", 443),
                urgency=urgency,
                category="score_regression",
                description=f"Q-Score dropped by {drop} points (from {prev_worst} to {curr_worst})",
                previous_value=str(prev_worst),
                current_value=str(curr_worst),
                recommended_action=(
                    "Immediate investigation required" if urgency == "HIGH"
                    else "Review configuration changes"
                ),
            ))

    # 3. Missed upgrades
    for hostname in sorted(set(current_map.keys()) & set(prev_map.keys())):
        curr = current_map[hostname]
        prev = prev_map[hostname]
        curr_serial = _extract_cert_serial(curr)
        prev_serial = _extract_cert_serial(prev)
        if not curr_serial or not prev_serial or curr_serial == prev_serial:
            continue
        curr_sig = _extract_sig_algo(curr)
        prev_sig = _extract_sig_algo(prev)
        if _sig_rank(curr_sig) <= _sig_rank(prev_sig) and _sig_rank(curr_sig) < 5:
            report.missed_upgrades.append(RegressionEntry(
                hostname=hostname,
                port=curr.get("port", 443),
                urgency="MEDIUM",
                category="missed_upgrade",
                description=f"Certificate renewed but sig algo not upgraded: {prev_sig} → {curr_sig}",
                previous_value=prev_sig,
                current_value=curr_sig,
                recommended_action="Request ML-DSA or SLH-DSA certificate at next renewal",
            ))

    report.total_findings = (
        len(report.new_assets) + len(report.score_regressions) + len(report.missed_upgrades)
    )
    return report


# ── Helpers ──────────────────────────────────────────────────────────────────

def _extract_cert_serial(asset: dict) -> str:
    """Extract certificate serial from various asset dict formats."""
    # ClassifiedAsset (flat) won't have cert info directly — check nested structures
    cert = asset.get("certificate", {})
    if isinstance(cert, dict):
        serial = cert.get("serial_number", "")
        if serial:
            return str(serial)
    # TriModeFingerprint with nested certificate
    for probe_key in ("probe_a", "probe_b", "probe_c"):
        probe = asset.get(probe_key, {})
        if isinstance(probe, dict):
            s = probe.get("certificate_serial", "")
            if s:
                return str(s)
    return ""


def _extract_sig_algo(asset: dict) -> str:
    """Extract best signature algorithm from asset dict."""
    cert = asset.get("certificate", {})
    if isinstance(cert, dict):
        sig = cert.get("signature_algorithm", "")
        if sig:
            return sig
    # Fall back to probe A
    probe_a = asset.get("probe_a", {})
    if isinstance(probe_a, dict):
        return probe_a.get("signature_algorithm", "")
    # Fall back to best_case_q findings
    return ""


def _persist_alerts(report: RegressionReport, scan_id: int | None) -> None:
    """Save HIGH-urgency regression findings as database alerts."""
    all_entries = report.new_assets + report.score_regressions + report.missed_upgrades
    for entry in all_entries:
        if entry.urgency == "HIGH":
            try:
                db.save_alert(
                    scan_id=scan_id,
                    severity="HIGH",
                    category=f"regression:{entry.category}",
                    message=entry.description,
                    hostname=entry.hostname,
                )
            except Exception as exc:
                logger.warning("Failed to persist alert for %s: %s", entry.hostname, exc)
