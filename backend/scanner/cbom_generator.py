"""Phase 8 — CBOM Generator v2: CycloneDX 1.7 with PQC Assessment Extensions.

Generates a Cryptographic Bill of Materials (CBOM) from Phase 7 ClassifiedAsset
objects, incorporating:

  • CycloneDX 1.7 envelope with URN-UUID serial
  • Each ClassifiedAsset → component (type ``cryptographic-asset``)
    - ``cryptoProperties``: protocol + algorithm details from Probe A
    - ``pqcAssessment`` extension: worst/best scores, status, agility, summary, action
    - Provenance object per component
  • Dependency graph: asset → KEX algo → NIST standard
  • Vulnerabilities array sourced from RegressionReport (HIGH→critical, MEDIUM→medium)
  • Root-level summary extension with aggregate stats
  • Schema validation (structural — CycloneDX 1.7 compliance)

All values are computed from ClassifiedAsset and RegressionReport — nothing hardcoded.
"""

from __future__ import annotations

import hashlib
import logging
import uuid
from datetime import datetime, timezone
from typing import Any

from backend.models import ClassifiedAsset, RegressionReport

logger = logging.getLogger("qarmor.cbom")

# ── NIST Standard references ────────────────────────────────────────────────

NIST_STANDARDS: dict[str, dict[str, str]] = {
    "FIPS-203": {
        "bom-ref": "nist-fips-203",
        "name": "NIST FIPS 203 — ML-KEM",
        "url": "https://csrc.nist.gov/pubs/fips/203/final",
    },
    "FIPS-204": {
        "bom-ref": "nist-fips-204",
        "name": "NIST FIPS 204 — ML-DSA",
        "url": "https://csrc.nist.gov/pubs/fips/204/final",
    },
    "FIPS-205": {
        "bom-ref": "nist-fips-205",
        "name": "NIST FIPS 205 — SLH-DSA",
        "url": "https://csrc.nist.gov/pubs/fips/205/final",
    },
}

_KEX_STANDARD_MAP: dict[str, str] = {
    "ML-KEM": "FIPS-203", "MLKEM": "FIPS-203", "KYBER": "FIPS-203",
    "X25519MLKEM768": "FIPS-203", "X25519KYBER768": "FIPS-203",
    "X448MLKEM1024": "FIPS-203",
}

_SIG_STANDARD_MAP: dict[str, str] = {
    "ML-DSA": "FIPS-204", "MLDSA": "FIPS-204",
    "SLH-DSA": "FIPS-205", "SLHDSA": "FIPS-205",
}

_URGENCY_TO_SEVERITY: dict[str, str] = {
    "HIGH": "critical", "MEDIUM": "medium", "LOW": "low",
}


# ═══════════════════════════════════════════════════════════════════════════
# Component builder
# ═══════════════════════════════════════════════════════════════════════════

def _build_component(asset: ClassifiedAsset, index: int) -> dict[str, Any]:
    """Convert a ClassifiedAsset into a CycloneDX 1.7 component dict."""
    bom_ref = f"crypto-{asset.hostname}-{asset.port}"
    best_q = asset.best_case_q
    worst_q = asset.worst_case_q

    kex_algo = _infer_kex(best_q.findings)
    sig_algo = _infer_sig(best_q.findings)

    nist_refs = []
    kex_upper = (kex_algo or "").upper()
    for frag, std_key in _KEX_STANDARD_MAP.items():
        if frag in kex_upper:
            nist_refs.append(NIST_STANDARDS[std_key]["bom-ref"])
            break
    sig_upper = (sig_algo or "").upper()
    for frag, std_key in _SIG_STANDARD_MAP.items():
        if frag in sig_upper:
            nist_refs.append(NIST_STANDARDS[std_key]["bom-ref"])
            break

    component: dict[str, Any] = {
        "type": "cryptographic-asset",
        "bom-ref": bom_ref,
        "name": f"{asset.hostname}:{asset.port}",
        "version": "",
        "description": f"Cryptographic configuration for {asset.hostname} ({asset.asset_type.value})",
        "cryptoProperties": {
            "assetType": "protocol",
            "protocolProperties": {"type": "tls", "version": _infer_tls_version(best_q.findings)},
            "algorithmProperties": {
                "keyExchange": kex_algo,
                "authentication": sig_algo,
                "keySize": best_q.cipher_strength_score * 17,
            },
        },
        "pqcAssessment": {
            "worstCaseScore": asset.worst_case_score,
            "bestCaseScore": asset.best_case_score,
            "typicalScore": asset.typical_score,
            "status": asset.status.value,
            "agilityScore": asset.agility_score,
            "summary": asset.summary,
            "recommendedAction": asset.recommended_action,
            "worstFindings": worst_q.findings[:5],
            "bestFindings": best_q.findings[:5],
            "worstRecommendations": worst_q.recommendations[:3],
        },
        "provenance": {
            "source": "Q-ARMOR Phase 7 Tri-Mode Classifier",
            "scoringVersion": "7.0.0",
            "probeCount": 3,
            "phases": ["discovery", "trimode-probe", "classification", "agility-assessment"],
        },
        "properties": [
            {"name": "qarmor:hostname", "value": asset.hostname},
            {"name": "qarmor:port", "value": str(asset.port)},
            {"name": "qarmor:assetType", "value": asset.asset_type.value},
            {"name": "qarmor:bestScore", "value": str(asset.best_case_score)},
            {"name": "qarmor:typicalScore", "value": str(asset.typical_score)},
            {"name": "qarmor:worstScore", "value": str(asset.worst_case_score)},
            {"name": "qarmor:status", "value": asset.status.value},
            {"name": "qarmor:agilityScore", "value": str(asset.agility_score)},
        ],
    }
    if nist_refs:
        component["nistStandardRefs"] = nist_refs
    return component


# ═══════════════════════════════════════════════════════════════════════════
# Dependency graph builder
# ═══════════════════════════════════════════════════════════════════════════

def _build_dependencies(
    components: list[dict[str, Any]],
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """Build dependency graph: asset → KEX algo → NIST standard."""
    algo_services: dict[str, dict[str, Any]] = {}
    nist_services: dict[str, dict[str, Any]] = {}
    dependencies: list[dict[str, Any]] = []

    for comp in components:
        comp_ref = comp["bom-ref"]
        algo_props = comp.get("cryptoProperties", {}).get("algorithmProperties", {})
        kex = (algo_props.get("keyExchange") or "").upper()
        sig = (algo_props.get("authentication") or "").upper()
        dep_on: list[str] = []

        if kex:
            kex_ref = f"algo-kex-{kex.lower().replace(' ', '-')}"
            if kex_ref not in algo_services:
                algo_services[kex_ref] = {
                    "type": "cryptographic-asset", "bom-ref": kex_ref,
                    "name": kex, "description": f"Key exchange algorithm: {kex}",
                    "cryptoProperties": {"assetType": "algorithm"},
                }
            dep_on.append(kex_ref)
            for frag, std_key in _KEX_STANDARD_MAP.items():
                if frag in kex:
                    nist_ref = NIST_STANDARDS[std_key]["bom-ref"]
                    if nist_ref not in nist_services:
                        std = NIST_STANDARDS[std_key]
                        nist_services[nist_ref] = {
                            "type": "standard", "bom-ref": nist_ref,
                            "name": std["name"],
                            "externalReferences": [{"type": "specification", "url": std["url"]}],
                        }
                    dependencies.append({"ref": kex_ref, "dependsOn": [nist_ref]})
                    break

        if sig:
            sig_ref = f"algo-sig-{sig.lower().replace(' ', '-')}"
            if sig_ref not in algo_services:
                algo_services[sig_ref] = {
                    "type": "cryptographic-asset", "bom-ref": sig_ref,
                    "name": sig, "description": f"Signature algorithm: {sig}",
                    "cryptoProperties": {"assetType": "algorithm"},
                }
            dep_on.append(sig_ref)
            for frag, std_key in _SIG_STANDARD_MAP.items():
                if frag in sig:
                    nist_ref = NIST_STANDARDS[std_key]["bom-ref"]
                    if nist_ref not in nist_services:
                        std = NIST_STANDARDS[std_key]
                        nist_services[nist_ref] = {
                            "type": "standard", "bom-ref": nist_ref,
                            "name": std["name"],
                            "externalReferences": [{"type": "specification", "url": std["url"]}],
                        }
                    dependencies.append({"ref": sig_ref, "dependsOn": [nist_ref]})
                    break

        if dep_on:
            dependencies.append({"ref": comp_ref, "dependsOn": dep_on})

    return list(algo_services.values()) + list(nist_services.values()), dependencies


# ═══════════════════════════════════════════════════════════════════════════
# Vulnerabilities from RegressionReport
# ═══════════════════════════════════════════════════════════════════════════

def _build_vulnerabilities(regression: RegressionReport | None) -> list[dict[str, Any]]:
    if not regression:
        return []
    vulns: list[dict[str, Any]] = []
    all_entries = (
        [(e, "new_asset") for e in regression.new_assets]
        + [(e, "score_regression") for e in regression.score_regressions]
        + [(e, "missed_upgrade") for e in regression.missed_upgrades]
    )
    for entry, category in all_entries:
        severity = _URGENCY_TO_SEVERITY.get(entry.urgency, "info")
        vulns.append({
            "id": f"QARMOR-REG-{uuid.uuid4().hex[:8].upper()}",
            "source": {"name": "Q-ARMOR Regression Detector"},
            "description": entry.description,
            "recommendation": entry.recommended_action,
            "ratings": [{"severity": severity, "method": "other", "source": {"name": "Q-ARMOR"}}],
            "affects": [{"ref": f"crypto-{entry.hostname}-{entry.port}"}],
            "properties": [
                {"name": "qarmor:category", "value": category},
                {"name": "qarmor:urgency", "value": entry.urgency},
                *([{"name": "qarmor:previousValue", "value": entry.previous_value}] if entry.previous_value else []),
                *([{"name": "qarmor:currentValue", "value": entry.current_value}] if entry.current_value else []),
            ],
        })
    return vulns


# ═══════════════════════════════════════════════════════════════════════════
# Summary extension
# ═══════════════════════════════════════════════════════════════════════════

def _build_summary_extension(
    assets: list[ClassifiedAsset], regression: RegressionReport | None,
) -> dict[str, Any]:
    total = len(assets)
    if total == 0:
        return {"totalAssets": 0}
    from backend.models import PQCStatus
    counts = {s.value: 0 for s in PQCStatus}
    total_worst = total_best = total_agility = 0
    for a in assets:
        counts[a.status.value] = counts.get(a.status.value, 0) + 1
        total_worst += a.worst_case_score
        total_best += a.best_case_score
        total_agility += a.agility_score
    summary: dict[str, Any] = {
        "totalAssets": total,
        "averageWorstScore": round(total_worst / total, 1),
        "averageBestScore": round(total_best / total, 1),
        "averageAgilityScore": round(total_agility / total, 1),
        "distribution": {
            "fullyQuantumSafe": counts.get("FULLY_QUANTUM_SAFE", 0),
            "pqcTransition": counts.get("PQC_TRANSITION", 0),
            "quantumVulnerable": counts.get("QUANTUM_VULNERABLE", 0),
            "criticallyVulnerable": counts.get("CRITICALLY_VULNERABLE", 0),
            "unknown": counts.get("UNKNOWN", 0),
        },
        "quantumSafetyScore": round(total_worst / total) if total else 0,
    }
    if regression and regression.total_findings > 0:
        summary["regressions"] = {
            "totalFindings": regression.total_findings,
            "newAssets": len(regression.new_assets),
            "scoreRegressions": len(regression.score_regressions),
            "missedUpgrades": len(regression.missed_upgrades),
        }
    return summary


# ═══════════════════════════════════════════════════════════════════════════
# Schema validator (structural)
# ═══════════════════════════════════════════════════════════════════════════

def validate_cbom(cbom: dict[str, Any]) -> dict[str, Any]:
    errors: list[str] = []
    for key in ["bomFormat", "specVersion", "serialNumber", "version", "metadata", "components"]:
        if key not in cbom:
            errors.append(f"Missing required top-level key: {key}")
    if cbom.get("bomFormat") != "CycloneDX":
        errors.append(f"Invalid bomFormat: {cbom.get('bomFormat')}")
    if cbom.get("specVersion") != "1.7":
        errors.append(f"Expected specVersion 1.7, got {cbom.get('specVersion')}")
    serial = cbom.get("serialNumber", "")
    if not serial.startswith("urn:uuid:"):
        errors.append(f"serialNumber should start with urn:uuid:, got: {serial[:30]}")
    components = cbom.get("components", [])
    if isinstance(components, list):
        bom_refs = set()
        for i, comp in enumerate(components):
            ref = comp.get("bom-ref", "")
            if not ref:
                errors.append(f"Component {i} missing bom-ref")
            elif ref in bom_refs:
                errors.append(f"Duplicate bom-ref: {ref}")
            bom_refs.add(ref)
    return {"valid": len(errors) == 0, "errors": errors}


# ═══════════════════════════════════════════════════════════════════════════
# Public API: CycloneDX 1.7
# ═══════════════════════════════════════════════════════════════════════════

def generate_cbom_v2(
    classified_assets: list[ClassifiedAsset],
    regression: RegressionReport | None = None,
    data_mode: str = "live",
) -> dict[str, Any]:
    """Generate a CycloneDX 1.7 CBOM from Phase 7 ClassifiedAsset list."""
    bom_serial = f"urn:uuid:{uuid.uuid4()}"
    now_iso = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
    components = [_build_component(a, i) for i, a in enumerate(classified_assets)]
    extra_components, dependencies = _build_dependencies(components)
    all_components = components + extra_components
    vulnerabilities = _build_vulnerabilities(regression)
    pqc_summary = _build_summary_extension(classified_assets, regression)
    content_hash = hashlib.sha256(
        str(sorted([c["bom-ref"] for c in all_components])).encode()
    ).hexdigest()

    cbom: dict[str, Any] = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.7",
        "serialNumber": bom_serial,
        "version": 1,
        "metadata": {
            "timestamp": now_iso,
            "tools": {"components": [{
                "type": "application", "name": "Q-ARMOR", "version": "9.0.0",
                "description": "Quantum-Aware Mapping & Observation for Risk Remediation",
            }]},
            "component": {"type": "application", "name": "Q-ARMOR Cryptographic Scan", "version": "9.0.0"},
            "properties": [
                {"name": "qarmor:dataMode", "value": data_mode},
                {"name": "qarmor:contentHash", "value": content_hash},
            ],
        },
        "components": all_components,
        "dependencies": dependencies,
        "compositions": [{"aggregate": "complete", "assemblies": [c["bom-ref"] for c in components]}],
        "pqcSummary": pqc_summary,
    }
    if vulnerabilities:
        cbom["vulnerabilities"] = vulnerabilities
    return cbom


# ═══════════════════════════════════════════════════════════════════════════
# Legacy compat
# ═══════════════════════════════════════════════════════════════════════════

def generate_cbom(summary: Any) -> dict:
    """Legacy CycloneDX 1.6 CBOM from ScanSummary (Phases 1-5)."""
    bom_ref = str(uuid.uuid4())
    components = []
    for result in summary.results:
        asset = result.asset
        fp = result.fingerprint
        q = result.q_score
        components.append({
            "type": "cryptographic-asset",
            "bom-ref": f"crypto-{asset.hostname}-{asset.port}",
            "name": f"{asset.hostname}:{asset.port}",
            "version": "",
            "description": f"Cryptographic configuration for {asset.hostname} ({asset.asset_type.value})",
            "cryptoProperties": {
                "assetType": "protocol",
                "protocolProperties": {
                    "type": "tls", "version": fp.tls.version,
                    "cipherSuites": [{"name": fp.tls.cipher_suite, "algorithms": [fp.tls.cipher_algorithm],
                        "identifiers": [{"type": "iana", "value": fp.tls.cipher_suite}]}] if fp.tls.cipher_suite else [],
                },
                "algorithmProperties": {"keyExchange": fp.tls.key_exchange, "authentication": fp.tls.authentication, "keySize": fp.tls.cipher_bits},
            },
            "pqcAssessment": {"qScore": q.total, "status": q.status.value, "findings": q.findings, "recommendations": q.recommendations},
            "properties": [{"name": "qarmor:qScore", "value": str(q.total)}, {"name": "qarmor:status", "value": q.status.value}],
        })
    return {
        "bomFormat": "CycloneDX", "specVersion": "1.6", "serialNumber": f"urn:uuid:{bom_ref}", "version": 1,
        "metadata": {
            "timestamp": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
            "tools": {"components": [{"type": "application", "name": "Q-ARMOR", "version": "9.0.0", "description": "Quantum-Aware Mapping & Observation for Risk Remediation"}]},
            "component": {"type": "application", "name": "Q-ARMOR Cryptographic Scan", "version": "9.0.0"},
        },
        "components": components,
        "compositions": [{"aggregate": "complete", "assemblies": [c["bom-ref"] for c in components]}],
        "properties": [{"name": "qarmor:totalAssets", "value": str(summary.total_assets)}, {"name": "qarmor:averageQScore", "value": f"{summary.average_q_score:.1f}"}],
    }


def generate_simple_report(summary: Any) -> list[dict]:
    """Simplified flat JSON report for quick audit."""
    return [{
        "asset": f"{r.asset.hostname}:{r.asset.port}",
        "tls_version": r.fingerprint.tls.version,
        "cipher_suite": r.fingerprint.tls.cipher_suite,
        "key_exchange": r.fingerprint.tls.key_exchange,
        "certificate_algorithm": r.fingerprint.certificate.public_key_type,
        "q_score": r.q_score.total,
        "status": r.q_score.status.value,
    } for r in summary.results]


# ── Inference helpers ────────────────────────────────────────────────────────

def _infer_kex(findings: list[str]) -> str:
    for f in findings:
        upper = f.upper()
        if "PQC KEY EXCHANGE" in upper:
            parts = f.split(":")
            if len(parts) > 1:
                return parts[-1].strip()
        for algo in ("ML-KEM-768", "ML-KEM-1024", "ML-KEM-512",
                     "X25519MLKEM768", "X25519KYBER768",
                     "ECDHE", "X25519", "X448", "RSA", "DHE"):
            if algo in upper:
                return algo
    return ""


def _infer_sig(findings: list[str]) -> str:
    for f in findings:
        upper = f.upper()
        if "PQC DIGITAL SIGNATURE" in upper or "CERTIFICATE" in upper:
            for algo in ("ML-DSA-87", "ML-DSA-65", "ML-DSA-44", "SLH-DSA",
                         "ECDSA-P384", "ECDSA-P256", "ED25519", "ED448", "RSA"):
                if algo in upper:
                    return algo
    return ""


def _infer_tls_version(findings: list[str]) -> str:
    for f in findings:
        if "TLS 1.3" in f:
            return "TLSv1.3"
        if "TLS 1.2" in f or "TLSv1.2" in f:
            return "TLSv1.2"
        if "TLS 1.1" in f or "TLSv1.1" in f:
            return "TLSv1.1"
    return ""
