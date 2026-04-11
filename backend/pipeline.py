"""Q-ARMOR unified scanner pipeline with negotiation and cyber-rating outputs."""

from __future__ import annotations

import asyncio
import json
from datetime import datetime, timezone
from typing import Any, Literal

from pydantic import BaseModel, Field

from backend.cyber_rating import compute_enterprise_cyber_rating
from backend.demo_data import DEMO_TRIMODE_FINGERPRINTS
from backend.models import ClassifiedAsset, DiscoveredAsset, PQCStatus, TriModeFingerprint
from backend.scanner import database
from backend.scanner.agility_assessor import assess_agility
from backend.scanner.attestor import generate_attestation_v2, set_latest_attestation_context
from backend.scanner.cbom_generator import generate_cbom_v2
from backend.scanner.classifier import classify_trimode
from backend.scanner.discoverer import discover_assets
from backend.scanner.label_registry import append_all_labels
from backend.scanner.labeler import label_classified_assets
from backend.scanner.negotiation_policy import (
    NegotiationPolicy,
    analyze_negotiation_policy,
    compute_heatmap,
)
from backend.scanner.notifier import detect_alerts
from backend.scanner.prober import probe_batch
from backend.scanner.regression_detector import detect_regressions


class PipelineResult(BaseModel):
    scan_id: int | None = None
    timestamp: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"))
    mode: Literal["live", "demo"]
    assets: list[dict[str, Any]] = Field(default_factory=list)
    negotiation_policies: dict[str, NegotiationPolicy] = Field(default_factory=dict)
    heatmap: dict[str, Any] = Field(default_factory=dict)
    enterprise_cyber_rating: dict[str, Any] = Field(default_factory=dict)
    cbom: dict[str, Any] = Field(default_factory=dict)
    labels: dict[str, Any] = Field(default_factory=dict)
    alerts: list[dict[str, Any]] = Field(default_factory=list)
    regression_summary: dict[str, Any] = Field(default_factory=dict)
    attestation: dict[str, Any] = Field(default_factory=dict)


def _clamp_score(value: int) -> int:
    return max(0, min(100, int(value)))


def _status_from_obj(status_obj: Any) -> str:
    if isinstance(status_obj, PQCStatus):
        return status_obj.value
    return str(status_obj or "UNKNOWN")


def _apply_negotiation_score(asset: ClassifiedAsset, adjustment: int) -> ClassifiedAsset:
    """Inject negotiation security score into per-probe and aggregate scores."""
    asset.best_case_score = _clamp_score(asset.best_case_score + adjustment)
    asset.typical_score = _clamp_score(asset.typical_score + adjustment)
    asset.worst_case_score = _clamp_score(asset.worst_case_score + adjustment)

    asset.best_case_q.total = _clamp_score(asset.best_case_q.total + adjustment)
    asset.typical_q.total = _clamp_score(asset.typical_q.total + adjustment)
    asset.worst_case_q.total = _clamp_score(asset.worst_case_q.total + adjustment)
    return asset


def _classify_with_negotiation(fp: TriModeFingerprint, policy: NegotiationPolicy) -> ClassifiedAsset:
    """Classify a tri-mode fingerprint while honoring negotiation score policy."""
    asset = classify_trimode(fp)
    return _apply_negotiation_score(asset, policy.negotiation_security_score)


def _build_asset_counts(assets: list[ClassifiedAsset]) -> dict[str, int]:
    counts = {status.value: 0 for status in PQCStatus}
    for asset in assets:
        counts[_status_from_obj(asset.status)] = counts.get(_status_from_obj(asset.status), 0) + 1
    return counts


def _regression_to_assessment_like(regression_summary: dict[str, Any]) -> list[dict[str, Any]]:
    """Transform regression entries into notifier-compatible records."""
    assessments: list[dict[str, Any]] = []

    for key in ("new_assets", "score_regressions", "missed_upgrades"):
        for entry in regression_summary.get(key, []):
            urgency = str(entry.get("urgency", "MEDIUM")).upper()
            risk = "HIGH" if urgency == "HIGH" else "MEDIUM"
            hndl_vulnerable = urgency == "HIGH" or entry.get("category") == "score_regression"
            assessments.append(
                {
                    "target": entry.get("hostname", "unknown"),
                    "port": entry.get("port", 443),
                    "hndl_vulnerable": hndl_vulnerable,
                    "overall_quantum_risk": risk,
                }
            )

    return assessments


async def _collect_fingerprints(
    mode: Literal["live", "demo"],
    domain: str | None,
    assets: list[DiscoveredAsset] | None,
    limit: int,
    include_port_scan: bool = False,
    include_api_crawl: bool = False,
) -> list[TriModeFingerprint]:
    if mode == "demo":
        return list(DEMO_TRIMODE_FINGERPRINTS)

    if assets is None:
        if not domain:
            raise ValueError("domain is required for live mode when assets are not provided")
        assets = await discover_assets(
            domain,
            demo=False,
            include_ct=True,
            include_port_scan=include_port_scan,
            include_api_crawl=include_api_crawl,
        )

    if not assets:
        return []

    selected_assets = assets if limit <= 0 else assets[:limit]
    return await probe_batch(selected_assets, concurrency=10, demo=False)


async def run_pipeline(
    *,
    mode: Literal["live", "demo"] = "demo",
    domain: str | None = None,
    assets: list[DiscoveredAsset] | None = None,
    limit: int = 0,
    include_port_scan: bool = False,
    include_api_crawl: bool = False,
) -> PipelineResult:
    """Execute the complete scanner pipeline in the required order."""
    database.init_db()

    # 1. Get fingerprints
    fingerprints = await _collect_fingerprints(
        mode=mode,
        domain=domain,
        assets=assets,
        limit=limit,
        include_port_scan=include_port_scan,
        include_api_crawl=include_api_crawl,
    )

    negotiation_policies: dict[str, NegotiationPolicy] = {}
    classified_assets: list[ClassifiedAsset] = []
    enriched_assets: list[dict[str, Any]] = []

    # 2 + 3 + 4. Negotiation policy -> classify with negotiation -> agility assessor
    for fp in fingerprints:
        policy = analyze_negotiation_policy(fp.probe_a, fp.probe_b, fp.probe_c)
        negotiation_policies[fp.hostname] = policy

        classified = _classify_with_negotiation(fp, policy)
        agility_score, agility_details = assess_agility(fp)
        classified.agility_score = agility_score
        classified.agility_details = agility_details

        classified_assets.append(classified)
        enriched = classified.model_dump(mode="json")
        enriched["ip"] = fp.ip or ""
        enriched["tls_version"] = fp.probe_b.tls_version or fp.probe_a.tls_version or ""
        enriched["cipher_suite"] = fp.probe_b.cipher_suite or fp.probe_a.cipher_suite or fp.probe_c.cipher_suite or ""
        enriched["cipher_bits"] = fp.probe_b.cipher_bits or fp.probe_a.cipher_bits or fp.probe_c.cipher_bits or 0
        enriched["key_exchange"] = fp.probe_a.key_exchange or ""
        enriched["cert_algorithm"] = fp.certificate.signature_algorithm or fp.probe_a.signature_algorithm or ""
        enriched["negotiation_tier"] = policy.negotiation_tier
        enriched["negotiation_security_score"] = policy.negotiation_security_score
        enriched_assets.append(enriched)

    classified_dicts = list(enriched_assets)

    # 5. Regression detector against previous DB scan
    previous_scan = database.load_previous_scan()
    regression_report = detect_regressions(
        current_assets=classified_dicts,
        current_scan_id=None,
        previous_scan=previous_scan,
        data_mode=mode,
    )

    # 6. CBOM generation
    cbom = generate_cbom_v2(classified_assets, regression_report, data_mode=mode)

    # 7. Labeler + label registry
    label_summary = label_classified_assets(classified_assets, is_demo=(mode == "demo"))
    append_all_labels(label_summary)

    # 8. Attestor over CBOM
    set_latest_attestation_context(label_summary, cbom)
    attestation = generate_attestation_v2(label_summary, cbom)

    # 9. Alerts from regression results
    alert_input = _regression_to_assessment_like(regression_report.model_dump(mode="json"))
    alerts = detect_alerts(alert_input)

    # 10. Enterprise cyber rating
    enterprise_input = [
        {
            "hostname": asset.hostname,
            "q_score": asset.worst_case_score,
            "pqc_status": _status_from_obj(asset.status),
        }
        for asset in classified_assets
    ]
    enterprise_cyber_rating = compute_enterprise_cyber_rating(enterprise_input)

    # 11. Negotiation heatmap
    heatmap_assets = [
        {
            "hostname": asset["hostname"],
            "pqc_status": asset.get("status", "UNKNOWN"),
            "negotiation_tier": asset.get("negotiation_tier", "WEAK"),
        }
        for asset in classified_dicts
    ]
    heatmap = compute_heatmap(heatmap_assets)

    # Save completed result in scans table
    counts = _build_asset_counts(classified_assets)
    avg_score = round(sum(a.worst_case_score for a in classified_assets) / len(classified_assets), 1) if classified_assets else 0.0
    scan_id = database.save_scan(
        mode=mode,
        domain=domain or "",
        total_assets=len(classified_assets),
        avg_score=avg_score,
        fully_safe=counts.get("FULLY_QUANTUM_SAFE", 0),
        pqc_trans=counts.get("PQC_TRANSITION", 0),
        q_vuln=counts.get("QUANTUM_VULNERABLE", 0),
        crit_vuln=counts.get("CRITICALLY_VULNERABLE", 0),
        unknown=counts.get("UNKNOWN", 0),
        results_json=json.dumps(classified_dicts),
        classified_assets=classified_dicts,
    )

    return PipelineResult(
        scan_id=scan_id,
        mode=mode,
        assets=classified_dicts,
        negotiation_policies=negotiation_policies,
        heatmap=heatmap,
        enterprise_cyber_rating=enterprise_cyber_rating,
        cbom=cbom,
        labels=label_summary.model_dump(mode="json"),
        alerts=alerts,
        regression_summary=regression_report.model_dump(mode="json"),
        attestation=attestation,
    )


def run_pipeline_sync(
    *,
    mode: Literal["live", "demo"] = "demo",
    domain: str | None = None,
    assets: list[DiscoveredAsset] | None = None,
    limit: int = 0,
    include_port_scan: bool = False,
    include_api_crawl: bool = False,
) -> PipelineResult:
    """Synchronous wrapper around the async pipeline entrypoint."""
    return asyncio.run(
        run_pipeline(
            mode=mode,
            domain=domain,
            assets=assets,
            limit=limit,
            include_port_scan=include_port_scan,
            include_api_crawl=include_api_crawl,
        )
    )
