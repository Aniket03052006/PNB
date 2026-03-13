"""Q-ARMOR — FastAPI Application (v9.0.0)."""

from __future__ import annotations
import asyncio
import hashlib
import json
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from fastapi import FastAPI, HTTPException
from fastapi.staticfiles import StaticFiles
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.middleware.cors import CORSMiddleware
import logging

from backend.models import ScanSummary, PQCStatus, TriModeFingerprint, ClassifiedAsset
from backend.demo_data import (
    generate_demo_results,
    DEMO_TRIMODE_FINGERPRINTS,
    get_demo_baseline_fingerprints,
    get_historical_scan_summaries,
    get_demo_domain_assets,
    get_demo_ssl_assets,
    get_demo_ip_assets,
    get_demo_software_assets,
    get_demo_network_graph,
    _trimode_to_crypto,
)
from backend.cyber_rating import TIER_CRITERIA
from backend.pipeline import run_pipeline
from backend.scanner.cbom_generator import generate_cbom, generate_cbom_v2
from backend.scanner.classifier import classify, classify_trimode
from backend.scanner.prober import probe_tls, probe_trimode, probe_batch
from backend.scanner.discoverer import discover_assets
from backend.scanner.assessment import analyze_endpoint, analyze_batch
from backend.scanner.remediation import generate_remediation, generate_batch_remediation
from backend.scanner.attestor import (
    generate_attestation, verify_attestation, get_attestation_summary,
    generate_attestation_v2, attestation_router, set_latest_attestation_context,
)
from backend.scanner.notifier import detect_alerts, send_alerts, get_alert_summary
from backend.scanner.regression_detector import detect_regressions, detect_regressions_demo
from backend.scanner.labeler import label_classified_assets
from backend.scanner.label_registry import (
    registry_router, append_all_labels, auto_revoke_on_scan,
)
from backend.scanner import database as db

logger = logging.getLogger("qarmor.app")

app = FastAPI(
    title="Q-ARMOR",
    description="Quantum-Aware Mapping & Observation for Risk Remediation",
    version="9.0.0",
)

# CORS — allow Vercel frontend in production, wildcard in dev
_frontend_url = os.environ.get("FRONTEND_URL", "")
_allowed_origins = [_frontend_url] if _frontend_url else ["*"]

app.add_middleware(
    CORSMiddleware,
    allow_origins=_allowed_origins,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Ensure data directory exists for SQLite
Path("data").mkdir(exist_ok=True)

# Mount Phase 8+9 sub-routers
app.include_router(registry_router)
app.include_router(attestation_router)

# Serve frontend static files
FRONTEND_DIR = Path(__file__).parent.parent / "frontend"
app.mount("/static", StaticFiles(directory=str(FRONTEND_DIR)), name="static")

# In-memory cache for latest scan
_latest_scan: ScanSummary | None = None
_latest_trimode: list[TriModeFingerprint] = []
_latest_classified: list[ClassifiedAsset] = []
_latest_phase9: dict = {}
_latest_pipeline_result: dict[str, Any] = {}
_latest_pipeline_context: dict[str, Any] = {"mode": "demo", "domain": None}


def _data_notice(demo_mode: bool) -> str:
    return "SIMULATED DATA" if demo_mode else "LIVE DATA"


def _normalize_pipeline_mode(mode: str | None) -> str:
    normalized = (mode or "demo").strip().lower()
    if normalized not in {"demo", "live"}:
        raise HTTPException(status_code=400, detail="mode must be one of: demo, live")
    return normalized


def _status_to_asset_state(status: str) -> str:
    if status in {"FULLY_QUANTUM_SAFE", "PQC_TRANSITION"}:
        return "confirmed"
    if status in {"QUANTUM_VULNERABLE", "CRITICALLY_VULNERABLE"}:
        return "new"
    return "review"


def _status_to_display_tier(status: str) -> str:
    mapping = {
        "FULLY_QUANTUM_SAFE": "Elite-PQC",
        "PQC_TRANSITION": "Standard",
        "QUANTUM_VULNERABLE": "Legacy",
        "CRITICALLY_VULNERABLE": "Critical",
        "UNKNOWN": "Unclassified",
    }
    return mapping.get(status, "Unclassified")


def _company_from_hostname(hostname: str) -> str:
    parts = [p for p in hostname.split(".") if p]
    if len(parts) >= 2:
        return parts[-2].upper()
    return "LIVE"


def _pipeline_detection_date(pipeline_result: dict[str, Any]) -> str:
    ts = str(pipeline_result.get("timestamp", ""))
    if ts:
        return ts.split("T")[0]
    return datetime.now(timezone.utc).date().isoformat()


def _live_domain_assets(pipeline_result: dict[str, Any]) -> list[dict[str, Any]]:
    detection_date = _pipeline_detection_date(pipeline_result)
    records: list[dict[str, Any]] = []
    for asset in pipeline_result.get("assets", []):
        host = str(asset.get("hostname", ""))
        if not host:
            continue
        records.append({
            "detection_date": detection_date,
            "domain_name": host,
            "registration_date": "",
            "registrar": "Live DNS/CT Discovery",
            "company_name": _company_from_hostname(host),
            "status": _status_to_asset_state(str(asset.get("status", "UNKNOWN"))),
        })
    return records


def _live_ssl_assets(pipeline_result: dict[str, Any]) -> list[dict[str, Any]]:
    detection_date = _pipeline_detection_date(pipeline_result)
    records: list[dict[str, Any]] = []
    for asset in pipeline_result.get("assets", []):
        host = str(asset.get("hostname", ""))
        if not host:
            continue
        fp_hash = hashlib.sha1(host.encode("utf-8")).hexdigest()
        records.append({
            "detection_date": detection_date,
            "ssl_sha_fingerprint": fp_hash,
            "valid_from": detection_date,
            "common_name": host,
            "company_name": _company_from_hostname(host),
            "certificate_authority": str(asset.get("cert_algorithm") or "Unknown"),
        })
    return records


def _live_ip_assets(pipeline_result: dict[str, Any]) -> list[dict[str, Any]]:
    detection_date = _pipeline_detection_date(pipeline_result)
    dedup: dict[str, dict[str, Any]] = {}

    for asset in pipeline_result.get("assets", []):
        ip = str(asset.get("ip") or "").strip()
        if not ip:
            continue
        port = int(asset.get("port", 443))
        if ip not in dedup:
            dedup[ip] = {
                "detection_date": detection_date,
                "ip_address": ip,
                "ports": [port],
                "subnet": "",
                "asn": "",
                "netname": "Live Discovery",
                "location": "",
                "company": _company_from_hostname(str(asset.get("hostname", ""))),
            }
        elif port not in dedup[ip]["ports"]:
            dedup[ip]["ports"].append(port)

    return list(dedup.values())


def _live_software_assets(pipeline_result: dict[str, Any]) -> list[dict[str, Any]]:
    detection_date = _pipeline_detection_date(pipeline_result)
    records: list[dict[str, Any]] = []
    for asset in pipeline_result.get("assets", []):
        host = str(asset.get("hostname", ""))
        if not host:
            continue
        records.append({
            "detection_date": detection_date,
            "product": str(asset.get("key_exchange") or "Crypto Stack"),
            "version": str(asset.get("tls_version") or ""),
            "type": "CryptoProfile",
            "port": int(asset.get("port", 443)),
            "host": host,
            "company_name": _company_from_hostname(host),
        })
    return records


def _live_network_graph(pipeline_result: dict[str, Any]) -> dict[str, Any]:
    nodes: list[dict[str, Any]] = []
    edges: list[dict[str, str]] = []
    ip_nodes: set[str] = set()
    domain_nodes: list[str] = []

    for asset in pipeline_result.get("assets", []):
        host = str(asset.get("hostname", "")).strip()
        if not host:
            continue

        status = str(asset.get("status", "UNKNOWN"))
        ip = str(asset.get("ip") or "").strip()

        nodes.append({
            "id": host,
            "label": host.split(".")[0] if "." in host else host,
            "type": "domain",
            "pqc_status": status,
            "display_tier": _status_to_display_tier(status),
            "ip_address": ip,
        })
        domain_nodes.append(host)

        if ip:
            ip_id = f"ip-{ip}"
            if ip_id not in ip_nodes:
                nodes.append({
                    "id": ip_id,
                    "label": ip,
                    "type": "ip",
                    "pqc_status": status,
                    "display_tier": _status_to_display_tier(status),
                    "ip_address": ip,
                })
                ip_nodes.add(ip_id)
            edges.append({"source": host, "target": ip_id})

    for idx in range(len(domain_nodes) - 1):
        edges.append({"source": domain_nodes[idx], "target": domain_nodes[idx + 1]})

    return {"nodes": nodes, "edges": edges}


def _derive_asset_discovery_payload(pipeline_result: dict[str, Any]) -> dict[str, Any]:
    demo_mode = pipeline_result.get("mode") == "demo"
    return {
        "domains": get_demo_domain_assets() if demo_mode else _live_domain_assets(pipeline_result),
        "ssl": get_demo_ssl_assets() if demo_mode else _live_ssl_assets(pipeline_result),
        "ip": get_demo_ip_assets() if demo_mode else _live_ip_assets(pipeline_result),
        "software": get_demo_software_assets() if demo_mode else _live_software_assets(pipeline_result),
        "network_graph": get_demo_network_graph() if demo_mode else _live_network_graph(pipeline_result),
    }


async def _ensure_latest_pipeline_result(
    *,
    mode: str = "demo",
    domain: str | None = None,
    force_refresh: bool = False,
) -> dict[str, Any]:
    """Return the latest pipeline result, generating requested mode if needed."""
    global _latest_pipeline_result, _latest_pipeline_context

    requested_mode = _normalize_pipeline_mode(mode)
    requested_domain = (domain or "").strip() or None

    if requested_mode == "live" and not requested_domain:
        cached_mode = _latest_pipeline_context.get("mode")
        cached_domain = _latest_pipeline_context.get("domain")
        if cached_mode == "live" and cached_domain:
            requested_domain = str(cached_domain)
        else:
            raise HTTPException(status_code=400, detail="domain is required when mode=live")

    if (
        not force_refresh
        and _latest_pipeline_result
        and _latest_pipeline_context.get("mode") == requested_mode
        and _latest_pipeline_context.get("domain") == requested_domain
    ):
        return _latest_pipeline_result

    result = await run_pipeline(mode=requested_mode, domain=requested_domain)
    _latest_pipeline_result = result.model_dump(mode="json")
    _latest_pipeline_context = {"mode": requested_mode, "domain": requested_domain}
    return _latest_pipeline_result


def _compute_home_summary(pipeline_result: dict[str, Any]) -> dict[str, Any]:
    """Assemble the home dashboard summary payload."""
    assets = pipeline_result.get("assets", [])
    enterprise = pipeline_result.get("enterprise_cyber_rating", {})
    cbom = pipeline_result.get("cbom", {})
    demo_mode = pipeline_result.get("mode") == "demo"

    total_assets = len(assets)
    fully_safe = sum(1 for a in assets if a.get("status") == "FULLY_QUANTUM_SAFE")
    transition = sum(1 for a in assets if a.get("status") == "PQC_TRANSITION")

    if demo_mode:
        domain_count = 212450
        ip_count = 48192
        subdomain_count = 84671
        cloud_asset_count = 13372
        ssl_cert_count = 8761
        software_count = 13211
        iot_device_count = 3854
        login_form_count = 1198
        vulnerable_component_count = 8248
        total_applications = 13211
        weak_crypto_count = 5176
    else:
        components = cbom.get("components", [])
        vulnerabilities = cbom.get("vulnerabilities", [])
        domain_count = total_assets
        ip_count = total_assets
        subdomain_count = total_assets
        cloud_asset_count = 0
        ssl_cert_count = total_assets
        software_count = len(components)
        iot_device_count = 0
        login_form_count = 0
        vulnerable_component_count = len(vulnerabilities)
        total_applications = len(components)
        weak_crypto_count = sum(
            1 for a in assets if a.get("status") in {"QUANTUM_VULNERABLE", "CRITICALLY_VULNERABLE"}
        )

    pqc_adoption_pct = round((fully_safe / total_assets) * 100, 1) if total_assets else 0.0
    transition_pct = round((transition / total_assets) * 100, 1) if total_assets else 0.0

    return {
        "asset_discovery_summary": {
            "domain_count": domain_count,
            "ip_count": ip_count,
            "subdomain_count": subdomain_count,
            "cloud_asset_count": cloud_asset_count,
        },
        "cyber_rating_summary": {
            "enterprise_score": int(enterprise.get("enterprise_score", 0)),
            "tier": str(enterprise.get("tier", "Unknown")),
        },
        "assets_inventory_summary": {
            "ssl_cert_count": ssl_cert_count,
            "software_count": software_count,
            "iot_device_count": iot_device_count,
            "login_form_count": login_form_count,
        },
        "posture_of_pqc": {
            "pqc_adoption_pct": pqc_adoption_pct,
            "transition_pct": transition_pct,
        },
        "cbom_summary": {
            "vulnerable_component_count": vulnerable_component_count,
            "total_applications": total_applications,
            "weak_crypto_count": weak_crypto_count,
        },
        "demo_mode": demo_mode,
        "data_notice": _data_notice(demo_mode),
    }


def _build_report_section(report_type: str, pipeline_result: dict[str, Any]) -> dict[str, Any]:
    """Build a report section for the reporting API."""
    home_summary = _compute_home_summary(pipeline_result)
    assets_payload = _derive_asset_discovery_payload(pipeline_result)

    if report_type == "executive":
        return {
            "home_summary": home_summary,
            "enterprise_cyber_rating": pipeline_result.get("enterprise_cyber_rating", {}),
            "heatmap": pipeline_result.get("heatmap", {}),
        }

    if report_type == "discovery":
        return {
            "domains": assets_payload["domains"],
            "ip_assets": assets_payload["ip"],
            "network_graph": assets_payload["network_graph"],
            "summary": home_summary.get("asset_discovery_summary", {}),
        }

    if report_type == "inventory":
        return {
            "ssl_assets": assets_payload["ssl"],
            "software_assets": assets_payload["software"],
            "summary": home_summary.get("assets_inventory_summary", {}),
        }

    if report_type == "cbom":
        return {
            "cbom": pipeline_result.get("cbom", {}),
            "summary": home_summary.get("cbom_summary", {}),
        }

    if report_type == "posture":
        return {
            "posture_of_pqc": home_summary.get("posture_of_pqc", {}),
            "heatmap": pipeline_result.get("heatmap", {}),
            "negotiation_policies": pipeline_result.get("negotiation_policies", {}),
        }

    if report_type == "cyber_rating":
        return {
            "cyber_rating": pipeline_result.get("enterprise_cyber_rating", {}),
            "tier_criteria": TIER_CRITERIA,
        }

    raise HTTPException(status_code=400, detail=f"Unsupported report_type: {report_type}")


def _render_report_html(report_type: str, data: dict[str, Any]) -> str:
    """Render a minimal HTML wrapper for report payloads."""
    pretty = json.dumps(data, indent=2, default=str)
    return (
        "<html><head><title>Q-ARMOR Report</title></head>"
        "<body><h1>Q-ARMOR Report</h1>"
        f"<h2>{report_type.title()}</h2>"
        f"<pre>{pretty}</pre>"
        "</body></html>"
    )


@app.get("/", response_class=HTMLResponse)
async def serve_dashboard():
    """Serve the Q-ARMOR dashboard."""
    index_file = FRONTEND_DIR / "index.html"
    if not index_file.exists():
        raise HTTPException(status_code=404, detail="Dashboard not found")
    return HTMLResponse(content=index_file.read_text())


@app.get("/dashboard", response_class=HTMLResponse)
async def serve_dashboard_alias():
    """Serve dashboard on /dashboard for landing-page CTAs."""
    return await serve_dashboard()


@app.get("/api/health")
async def health_check():
    """Health check endpoint."""
    return {"status": "operational", "service": "Q-ARMOR", "version": "9.0.0"}


@app.get("/api/scan/demo")
async def run_demo_scan():
    """Run a demo scan with simulated bank assets."""
    global _latest_scan
    _latest_scan = generate_demo_results()
    return _latest_scan.model_dump(mode="json")


@app.post("/api/scan/domain/{domain}")
async def scan_domain(domain: str):
    """Scan a real domain for cryptographic configuration."""
    global _latest_scan
    from backend.models import ScanResult
    import asyncio

    try:
        # Discovery with timeout — CT logs can be slow
        try:
            assets = await asyncio.wait_for(
                discover_assets(domain, include_ct=True, include_port_scan=False),
                timeout=20.0,
            )
        except asyncio.TimeoutError:
            # Fall back to DNS-only if CT takes too long
            logger.warning("CT log timeout for %s, falling back to DNS-only", domain)
            assets = await asyncio.wait_for(
                discover_assets(domain, include_ct=False, include_port_scan=False),
                timeout=10.0,
            )

        if not assets:
            raise HTTPException(status_code=404, detail=f"No assets discovered for {domain}")

        # Probe with per-asset timeout to avoid hanging
        sem = asyncio.Semaphore(10)

        async def scan_single_asset(asset) -> ScanResult:
            async with sem:
                try:
                    fp = await asyncio.wait_for(
                        probe_tls(asset.hostname, asset.port),
                        timeout=15.0,
                    )
                    q = classify(fp)
                    return ScanResult(asset=asset, fingerprint=fp, q_score=q)
                except asyncio.TimeoutError:
                    return ScanResult(asset=asset, error="probe timeout")
                except Exception as e:
                    return ScanResult(asset=asset, error=str(e))

        tasks = [scan_single_asset(asset) for asset in assets[:20]]
        results = await asyncio.gather(*tasks)

        counts = {s: 0 for s in PQCStatus}
        total = 0
        for r in results:
            if r.q_score:
                counts[r.q_score.status] += 1
                total += r.q_score.total

        from backend.scanner.label_issuer import issue_label
        labels = []
        for r in results:
            if r.q_score:
                label = issue_label(r.asset.hostname, r.asset.port, r.q_score)
                if label:
                    labels.append(label)

        from backend.demo_data import _build_remediation_roadmap
        _latest_scan = ScanSummary(
            total_assets=len(results),
            fully_quantum_safe=counts[PQCStatus.FULLY_QUANTUM_SAFE],
            pqc_transition=counts[PQCStatus.PQC_TRANSITION],
            quantum_vulnerable=counts[PQCStatus.QUANTUM_VULNERABLE],
            critically_vulnerable=counts[PQCStatus.CRITICALLY_VULNERABLE],
            unknown=counts.get(PQCStatus.UNKNOWN, 0),
            average_q_score=round(total / len(results), 1) if results else 0,
            results=results,
            remediation_roadmap=_build_remediation_roadmap(results),
            labels=labels,
        )
        return _latest_scan.model_dump(mode="json")

    except HTTPException:
        raise
    except Exception as e:
        logger.exception("Domain scan failed for %s", domain)
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/scan/single/{hostname}")
async def scan_single(hostname: str, port: int = 443):
    """Scan a single hostname:port for cryptographic configuration."""
    try:
        fp = await probe_tls(hostname, port)
        q = classify(fp)
        from backend.models import DiscoveredAsset, ScanResult
        asset = DiscoveredAsset(hostname=hostname, port=port)
        result = ScanResult(asset=asset, fingerprint=fp, q_score=q)
        return result.model_dump(mode="json")
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/cbom")
async def get_cbom():
    """Export the latest scan results as CycloneDX 1.6 CBOM JSON."""
    if not _latest_scan:
        raise HTTPException(status_code=404, detail="No scan data. Run /api/scan/demo first.")
    cbom = generate_cbom(_latest_scan)
    return JSONResponse(
        content=cbom,
        headers={"Content-Disposition": "attachment; filename=qarmor-cbom.json"},
    )


@app.get("/api/report")
async def get_simple_report():
    """Export the latest scan results as a simplified flat JSON report."""
    if not _latest_scan:
        raise HTTPException(status_code=404, detail="No scan data. Run /api/scan/demo first.")
    from backend.scanner.cbom_generator import generate_simple_report
    report = generate_simple_report(_latest_scan)
    return JSONResponse(
        content=report,
        headers={"Content-Disposition": "attachment; filename=qarmor-report.json"},
    )


@app.get("/api/summary")
async def get_summary():
    """Get summary statistics of the latest scan."""
    if not _latest_scan:
        raise HTTPException(status_code=404, detail="No scan data. Run /api/scan/demo first.")
    return {
        "total_assets": _latest_scan.total_assets,
        "fully_quantum_safe": _latest_scan.fully_quantum_safe,
        "pqc_transition": _latest_scan.pqc_transition,
        "quantum_vulnerable": _latest_scan.quantum_vulnerable,
        "critically_vulnerable": _latest_scan.critically_vulnerable,
        "unknown": _latest_scan.unknown,
        "average_q_score": _latest_scan.average_q_score,
        "scan_timestamp": _latest_scan.scan_timestamp,
    }


@app.get("/api/remediation")
async def get_remediation():
    """Get the prioritized remediation roadmap."""
    if not _latest_scan:
        raise HTTPException(status_code=404, detail="No scan data. Run /api/scan/demo first.")
    return [r.model_dump(mode="json") for r in _latest_scan.remediation_roadmap]


@app.get("/api/labels")
async def get_labels():
    """Get all PQC-Ready labels issued."""
    if not _latest_scan:
        raise HTTPException(status_code=404, detail="No scan data. Run /api/scan/demo first.")
    return [l.model_dump(mode="json") for l in _latest_scan.labels]


# ── Phase 2: PQC Assessment Endpoints ───────────────────────────────────────

@app.get("/api/assess")
async def get_assessment():
    """Run Phase 2 PQC assessment on the latest scan data."""
    if not _latest_scan:
        raise HTTPException(status_code=404, detail="No scan data. Run /api/scan/demo first.")
    batch = analyze_batch(_latest_scan)
    return JSONResponse(content=batch)


@app.get("/api/assess/endpoint/{hostname}")
async def assess_endpoint(hostname: str, port: int = 443):
    """Assess a single endpoint against the NIST PQC validation matrix."""
    try:
        fp = await probe_tls(hostname, port)
        q = classify(fp)
        from backend.models import DiscoveredAsset, ScanResult
        asset = DiscoveredAsset(hostname=hostname, port=port)
        result = ScanResult(asset=asset, fingerprint=fp, q_score=q)
        assessment = analyze_endpoint(result)
        remediation = generate_remediation(assessment)
        return JSONResponse(content={
            "assessment": assessment,
            "remediation": remediation,
        })
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/assess/remediation")
async def get_remediation_plan():
    """Get the full Phase 2 remediation plan for the latest scan."""
    if not _latest_scan:
        raise HTTPException(status_code=404, detail="No scan data. Run /api/scan/demo first.")
    batch = analyze_batch(_latest_scan)
    rems = generate_batch_remediation(batch)
    return JSONResponse(content=rems)


@app.get("/api/assess/matrix")
async def get_nist_matrix():
    """Return the NIST PQC validation matrix reference."""
    from backend.scanner.nist_matrix import (
        get_vulnerable_algorithms,
        get_pqc_safe_algorithms,
        get_hybrid_algorithms,
    )
    return JSONResponse(content={
        "vulnerable": get_vulnerable_algorithms(),
        "pqc_safe": get_pqc_safe_algorithms(),
        "hybrid": get_hybrid_algorithms(),
    })


# ── Phase 3: CBOM Generation Endpoints ──────────────────────────────────────

@app.get("/api/cbom/phase3")
async def get_cbom_phase3():
    """Generate a CycloneDX 1.6 CBOM with Phase 2 assessment annotations.

    Combines Phase 1 scan data + Phase 2 NIST assessment into a single
    CycloneDX 1.6 document with cryptographic-asset components and a
    full dependency graph.
    """
    if not _latest_scan:
        raise HTTPException(status_code=404, detail="No scan data. Run /api/scan/demo first.")
    from backend.scanner.cbom_generator import generate_cbom_from_summary
    summary_dict = _latest_scan.model_dump()
    # Convert datetimes to strings for JSON serialization
    import json
    summary_dict = json.loads(_latest_scan.model_dump_json())
    # Get Phase 2 assessments
    batch = analyze_batch(_latest_scan)
    assessment_list = batch.get("assessments", [])
    cbom = generate_cbom_from_summary(summary_dict, assessment_list, output_file=None)
    return JSONResponse(content=cbom)


@app.get("/api/cbom/phase3/download")
async def download_cbom_phase3():
    """Generate and download the Phase 3 CBOM as a JSON file."""
    if not _latest_scan:
        raise HTTPException(status_code=404, detail="No scan data. Run /api/scan/demo first.")
    from backend.scanner.cbom_generator import generate_cbom_from_summary
    import json as _json
    summary_dict = _json.loads(_latest_scan.model_dump_json())
    batch = analyze_batch(_latest_scan)
    assessment_list = batch.get("assessments", [])
    cbom = generate_cbom_from_summary(summary_dict, assessment_list, output_file=None)
    return JSONResponse(
        content=cbom,
        headers={"Content-Disposition": "attachment; filename=qarmor-cbom-phase3.json"},
    )


# ── Phase 4: Certification Labeling Endpoints ───────────────────────────────

@app.get("/api/labels/phase4")
async def get_phase4_labels():
    """Evaluate all endpoints with the 3-tier certification labeling engine.

    Returns per-endpoint labels (Fully Quantum Safe / PQC Ready / Non-Compliant)
    plus aggregate summary statistics.
    """
    if not _latest_scan:
        raise HTTPException(status_code=404, detail="No scan data. Run /api/scan/demo first.")
    from backend.scanner.labeler import evaluate_and_label, summarize_labels
    batch = analyze_batch(_latest_scan)
    labels = evaluate_and_label(batch.get("assessments", []))
    summary = summarize_labels(labels)
    return JSONResponse(content=summary)


# ── Phase 5: Compliance-as-Code Attestation & Automation ─────────────────────

@app.get("/api/attestation/generate")
async def generate_attestation_endpoint():
    """Generate a signed CycloneDX Attestation (CDXA) document.

    Combines Phase 2 assessments + Phase 4 labels into a digitally
    signed compliance attestation with NIST FIPS 203/204 claims.
    """
    if not _latest_scan:
        raise HTTPException(status_code=404, detail="No scan data. Run /api/scan/demo first.")
    batch = analyze_batch(_latest_scan)
    assessments = batch.get("assessments", [])

    # Optionally include Phase 3 CBOM as evidence
    from backend.scanner.cbom_generator import generate_cbom_from_summary
    import json as _json
    summary_dict = _json.loads(_latest_scan.model_dump_json())
    cbom = generate_cbom_from_summary(summary_dict, assessments, output_file=None)

    cdxa = generate_attestation(
        assessment_results=assessments,
        cbom_data=cbom,
    )
    return JSONResponse(content=cdxa)


@app.get("/api/attestation/download")
async def download_attestation():
    """Generate and download the signed CDXA document as a JSON file."""
    if not _latest_scan:
        raise HTTPException(status_code=404, detail="No scan data. Run /api/scan/demo first.")
    batch = analyze_batch(_latest_scan)
    assessments = batch.get("assessments", [])

    cdxa = generate_attestation(assessment_results=assessments)
    return JSONResponse(
        content=cdxa,
        headers={"Content-Disposition": "attachment; filename=qarmor-attestation-cdxa.json"},
    )


@app.get("/api/attestation/verify")
async def verify_attestation_endpoint():
    """Generate a fresh attestation and verify its signature."""
    if not _latest_scan:
        raise HTTPException(status_code=404, detail="No scan data. Run /api/scan/demo first.")
    batch = analyze_batch(_latest_scan)
    assessments = batch.get("assessments", [])

    cdxa = generate_attestation(assessment_results=assessments)
    verification = verify_attestation(cdxa)
    return JSONResponse(content=verification)


@app.get("/api/attestation/summary")
async def attestation_summary():
    """Get a concise summary of the latest attestation."""
    if not _latest_scan:
        raise HTTPException(status_code=404, detail="No scan data. Run /api/scan/demo first.")
    batch = analyze_batch(_latest_scan)
    assessments = batch.get("assessments", [])

    cdxa = generate_attestation(assessment_results=assessments)
    summary = get_attestation_summary(cdxa)
    return JSONResponse(content=summary)


@app.get("/api/alerts")
async def get_alerts():
    """Detect security alerts from the latest scan data.

    Returns active alerts for HNDL vulnerabilities, HIGH quantum risk,
    and non-compliance threshold exceeding.
    """
    if not _latest_scan:
        raise HTTPException(status_code=404, detail="No scan data. Run /api/scan/demo first.")
    batch = analyze_batch(_latest_scan)
    assessments = batch.get("assessments", [])

    from backend.scanner.labeler import evaluate_and_label
    labels = evaluate_and_label(assessments)
    alerts = detect_alerts(assessments, labels)
    alert_summary = get_alert_summary(alerts)

    return JSONResponse(content={
        "summary": alert_summary,
        "alerts": alerts,
    })


@app.post("/api/alerts/notify")
async def send_alert_notifications(
    slack_webhook: str = "",
    teams_webhook: str = "",
):
    """Send alert notifications to configured Slack/Teams webhooks.

    Webhook URLs can be passed as query params or set via environment
    variables QARMOR_SLACK_WEBHOOK / QARMOR_TEAMS_WEBHOOK.
    """
    if not _latest_scan:
        raise HTTPException(status_code=404, detail="No scan data. Run /api/scan/demo first.")
    batch = analyze_batch(_latest_scan)
    assessments = batch.get("assessments", [])

    from backend.scanner.labeler import evaluate_and_label, summarize_labels
    labels = evaluate_and_label(assessments)
    label_summary = summarize_labels(labels)

    result = send_alerts(
        assessment_results=assessments,
        labels=labels,
        slack_webhook=slack_webhook or None,
        teams_webhook=teams_webhook or None,
        scan_summary={
            "total": label_summary["total_endpoints"],
            "safe": label_summary["fully_quantum_safe"],
            "pqc_ready": label_summary["pqc_ready"],
            "non_compliant": label_summary["non_compliant"],
        },
    )
    return JSONResponse(content=result)


# ── Phase 6: Tri-Mode Probing & Asset Discovery ─────────────────────────────

@app.get("/api/scan/trimode/demo")
async def trimode_demo_scan():
    """Run tri-mode scan with demo data (21 pre-built TriModeFingerprints).

    Returns all 21 fingerprints with mode='demo' flag.  Downstream
    classification uses the REAL classifier engine.
    """
    global _latest_scan, _latest_trimode
    _latest_trimode = list(DEMO_TRIMODE_FINGERPRINTS)
    _latest_scan = generate_demo_results()

    classified = []
    for fp in _latest_trimode:
        crypto = _trimode_to_crypto(fp)
        q = classify(crypto)
        classified.append({
            **fp.model_dump(mode="json"),
            "q_score": q.model_dump(mode="json"),
        })

    return JSONResponse(content={
        "mode": "demo",
        "total_assets": len(classified),
        "fingerprints": classified,
        "summary": {
            "total_assets": _latest_scan.total_assets,
            "fully_quantum_safe": _latest_scan.fully_quantum_safe,
            "pqc_transition": _latest_scan.pqc_transition,
            "quantum_vulnerable": _latest_scan.quantum_vulnerable,
            "critically_vulnerable": _latest_scan.critically_vulnerable,
            "unknown": _latest_scan.unknown,
            "average_q_score": _latest_scan.average_q_score,
        },
    })


@app.post("/api/scan/trimode/live/{domain}")
async def trimode_live_scan(domain: str):
    """Run real tri-mode scan against a domain.

    Pipeline: discover_assets -> probe_batch (tri-mode A/B/C) -> classify.
    """
    global _latest_scan, _latest_trimode

    try:
        assets = await discover_assets(domain, demo=False, include_ct=True, include_port_scan=False)
        if not assets:
            raise HTTPException(status_code=404, detail=f"No assets discovered for {domain}")

        fingerprints = await probe_batch(assets[:20], concurrency=20, demo=False)
        _latest_trimode = fingerprints

        classified = []
        for fp in fingerprints:
            crypto = _trimode_to_crypto(fp)
            q = classify(crypto)
            classified.append({
                **fp.model_dump(mode="json"),
                "q_score": q.model_dump(mode="json"),
            })

        # Build legacy ScanSummary for backward compat
        from backend.models import ScanResult, DiscoveredAsset
        results = []
        counts = {s: 0 for s in PQCStatus}
        total_score = 0
        for fp in fingerprints:
            crypto = _trimode_to_crypto(fp)
            q = classify(crypto)
            asset = DiscoveredAsset(hostname=fp.hostname, ip=fp.ip, port=fp.port, asset_type=fp.asset_type)
            results.append(ScanResult(asset=asset, fingerprint=crypto, q_score=q, scan_duration_ms=fp.scan_duration_ms))
            counts[q.status] += 1
            total_score += q.total

        from backend.demo_data import _build_remediation_roadmap
        from backend.scanner.label_issuer import issue_label
        labels = [l for r in results if (l := issue_label(r.asset.hostname, r.asset.port, r.q_score))]
        _latest_scan = ScanSummary(
            total_assets=len(results),
            fully_quantum_safe=counts[PQCStatus.FULLY_QUANTUM_SAFE],
            pqc_transition=counts[PQCStatus.PQC_TRANSITION],
            quantum_vulnerable=counts[PQCStatus.QUANTUM_VULNERABLE],
            critically_vulnerable=counts[PQCStatus.CRITICALLY_VULNERABLE],
            unknown=counts.get(PQCStatus.UNKNOWN, 0),
            average_q_score=round(total_score / len(results), 1) if results else 0,
            results=results,
            remediation_roadmap=_build_remediation_roadmap(results),
            labels=labels,
        )

        return JSONResponse(content={
            "mode": "live",
            "domain": domain,
            "total_assets": len(classified),
            "fingerprints": classified,
            "summary": {
                "total_assets": _latest_scan.total_assets,
                "fully_quantum_safe": _latest_scan.fully_quantum_safe,
                "pqc_transition": _latest_scan.pqc_transition,
                "quantum_vulnerable": _latest_scan.quantum_vulnerable,
                "critically_vulnerable": _latest_scan.critically_vulnerable,
                "unknown": _latest_scan.unknown,
                "average_q_score": _latest_scan.average_q_score,
            },
        })
    except HTTPException:
        raise
    except Exception as e:
        logger.exception("Tri-mode live scan failed for %s", domain)
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/scan/trimode/single/{hostname}")
async def trimode_single(hostname: str, port: int = 443):
    """Tri-mode probe a single hostname:port."""
    try:
        fp = await probe_trimode(hostname, port)
        crypto = _trimode_to_crypto(fp)
        q = classify(crypto)
        return JSONResponse(content={
            **fp.model_dump(mode="json"),
            "q_score": q.model_dump(mode="json"),
        })
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/scan/trimode/fingerprints")
async def get_trimode_fingerprints():
    """Return the latest tri-mode fingerprints."""
    if not _latest_trimode:
        raise HTTPException(status_code=404, detail="No tri-mode scan data. Run /api/scan/trimode/demo first.")
    classified = []
    for fp in _latest_trimode:
        crypto = _trimode_to_crypto(fp)
        q = classify(crypto)
        classified.append({**fp.model_dump(mode="json"), "q_score": q.model_dump(mode="json")})
    return JSONResponse(content={"fingerprints": classified, "total": len(classified)})


@app.get("/api/scan/trimode/baseline")
async def get_baseline():
    """Return the demo baseline fingerprints (one-week-ago degraded snapshot)."""
    baseline = get_demo_baseline_fingerprints()
    classified = []
    for fp in baseline:
        crypto = _trimode_to_crypto(fp)
        q = classify(crypto)
        classified.append({**fp.model_dump(mode="json"), "q_score": q.model_dump(mode="json")})
    return JSONResponse(content={
        "mode": "demo",
        "description": "Baseline snapshot — 1 week ago (degraded)",
        "total_assets": len(classified),
        "fingerprints": classified,
    })


@app.get("/api/scan/trimode/history")
async def get_history():
    """Return 4 weeks of historical scan summaries (demo seed data)."""
    summaries = get_historical_scan_summaries()
    return JSONResponse(content={
        "mode": "demo",
        "weeks": [s.model_dump(mode="json") for s in summaries],
    })


@app.get("/api/discover/demo")
async def discover_demo():
    """Return the 21 demo discovered assets."""
    assets = await discover_assets("bank.com", demo=True)
    return JSONResponse(content={
        "mode": "demo",
        "total": len(assets),
        "assets": [a.model_dump(mode="json") for a in assets],
    })


@app.post("/api/discover/{domain}")
async def discover_domain(domain: str, include_ct: bool = True, include_port_scan: bool = False):
    """Live asset discovery for a domain."""
    try:
        assets = await discover_assets(
            domain, demo=False, include_ct=include_ct, include_port_scan=include_port_scan,
        )
        return JSONResponse(content={
            "mode": "live",
            "domain": domain,
            "total": len(assets),
            "assets": [a.model_dump(mode="json") for a in assets],
        })
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


# ── Phase 7: PQC Classification + Agility + Database ────────────────────────

@app.get("/api/classify/demo")
async def classify_demo():
    """Classify all 21 demo assets with Phase 7 tri-mode classifier.

    Returns ClassifiedAsset list with best/typical/worst Q-Scores,
    status derived from worst case, plain English summary, and agility score.
    """
    classified = []
    for fp in DEMO_TRIMODE_FINGERPRINTS:
        ca = classify_trimode(fp)
        classified.append(ca.model_dump(mode="json"))

    # Persist to database
    counts = {s.value: 0 for s in PQCStatus}
    total_worst = 0
    for c in classified:
        counts[c["status"]] = counts.get(c["status"], 0) + 1
        total_worst += c["worst_case_score"]

    avg = round(total_worst / len(classified), 1) if classified else 0
    scan_id = db.save_scan(
        mode="demo",
        domain="bank.com",
        total_assets=len(classified),
        avg_score=avg,
        fully_safe=counts.get("FULLY_QUANTUM_SAFE", 0),
        pqc_trans=counts.get("PQC_TRANSITION", 0),
        q_vuln=counts.get("QUANTUM_VULNERABLE", 0),
        crit_vuln=counts.get("CRITICALLY_VULNERABLE", 0),
        unknown=counts.get("UNKNOWN", 0),
        results_json=json.dumps(classified),
        classified_assets=classified,
    )

    return JSONResponse(content={
        "mode": "demo",
        "scan_id": scan_id,
        "total_assets": len(classified),
        "avg_worst_score": avg,
        "summary": {
            "fully_quantum_safe": counts.get("FULLY_QUANTUM_SAFE", 0),
            "pqc_transition": counts.get("PQC_TRANSITION", 0),
            "quantum_vulnerable": counts.get("QUANTUM_VULNERABLE", 0),
            "critically_vulnerable": counts.get("CRITICALLY_VULNERABLE", 0),
            "unknown": counts.get("UNKNOWN", 0),
        },
        "assets": classified,
    })


@app.get("/api/classify/single/{hostname}")
async def classify_single(hostname: str, port: int = 443):
    """Classify a single host with Phase 7 tri-mode classifier."""
    try:
        fp = await probe_trimode(hostname, port)
        ca = classify_trimode(fp)
        return JSONResponse(content=ca.model_dump(mode="json"))
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/api/classify/live/{domain}")
async def classify_live(domain: str):
    """Discover + tri-mode probe + Phase 7 classify a live domain."""
    try:
        import asyncio
        try:
            assets = await asyncio.wait_for(
                discover_assets(domain, include_ct=True, include_port_scan=False),
                timeout=20.0,
            )
        except asyncio.TimeoutError:
            assets = await asyncio.wait_for(
                discover_assets(domain, include_ct=False, include_port_scan=False),
                timeout=10.0,
            )
        if not assets:
            raise HTTPException(status_code=404, detail=f"No assets discovered for {domain}")

        fingerprints = await probe_batch(assets[:20], concurrency=20, demo=False)

        classified = []
        for fp in fingerprints:
            ca = classify_trimode(fp)
            classified.append(ca.model_dump(mode="json"))

        counts = {s.value: 0 for s in PQCStatus}
        total_worst = 0
        for c in classified:
            counts[c["status"]] = counts.get(c["status"], 0) + 1
            total_worst += c["worst_case_score"]

        avg = round(total_worst / len(classified), 1) if classified else 0
        scan_id = db.save_scan(
            mode="live",
            domain=domain,
            total_assets=len(classified),
            avg_score=avg,
            fully_safe=counts.get("FULLY_QUANTUM_SAFE", 0),
            pqc_trans=counts.get("PQC_TRANSITION", 0),
            q_vuln=counts.get("QUANTUM_VULNERABLE", 0),
            crit_vuln=counts.get("CRITICALLY_VULNERABLE", 0),
            unknown=counts.get("UNKNOWN", 0),
            results_json=json.dumps(classified),
            classified_assets=classified,
        )

        return JSONResponse(content={
            "mode": "live",
            "domain": domain,
            "scan_id": scan_id,
            "total_assets": len(classified),
            "avg_worst_score": avg,
            "summary": {
                "fully_quantum_safe": counts.get("FULLY_QUANTUM_SAFE", 0),
                "pqc_transition": counts.get("PQC_TRANSITION", 0),
                "quantum_vulnerable": counts.get("QUANTUM_VULNERABLE", 0),
                "critically_vulnerable": counts.get("CRITICALLY_VULNERABLE", 0),
                "unknown": counts.get("UNKNOWN", 0),
            },
            "assets": classified,
        })
    except HTTPException:
        raise
    except Exception as e:
        logger.exception("Phase 7 live classify failed for %s", domain)
        raise HTTPException(status_code=500, detail=str(e))


# ── Phase 7: Database Endpoints ──────────────────────────────────────────────

@app.get("/api/db/scans")
async def db_list_scans(limit: int = 20):
    """List recent scans from the database."""
    return JSONResponse(content=db.list_scans(limit))


@app.get("/api/db/scans/{scan_id}")
async def db_get_scan(scan_id: int):
    """Load a specific scan by ID."""
    scan = db.load_scan(scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    return JSONResponse(content=scan)


@app.get("/api/db/scans/latest")
async def db_latest_scan():
    """Load the most recent scan."""
    scan = db.load_latest_scan()
    if not scan:
        raise HTTPException(status_code=404, detail="No scans in database")
    return JSONResponse(content=scan)


@app.get("/api/db/compare/{scan_a}/{scan_b}")
async def db_compare_scans(scan_a: int, scan_b: int):
    """Compare two scans and return delta analysis."""
    result = db.compare_scans(scan_a, scan_b)
    if "error" in result:
        raise HTTPException(status_code=404, detail=result["error"])
    return JSONResponse(content=result)


@app.get("/api/db/asset/{hostname}/history")
async def db_asset_history(hostname: str, limit: int = 10):
    """Get score history for a specific asset."""
    return JSONResponse(content=db.get_asset_history(hostname, limit))


@app.get("/api/db/labels")
async def db_list_labels(include_revoked: bool = False):
    """List PQC labels from the database."""
    return JSONResponse(content=db.list_labels(include_revoked))


@app.get("/api/db/labels/{label_id}")
async def db_verify_label(label_id: str):
    """Verify / look up a label by ID."""
    label = db.verify_label(label_id)
    if not label:
        raise HTTPException(status_code=404, detail="Label not found")
    return JSONResponse(content=label)


@app.post("/api/db/labels/{label_id}/revoke")
async def db_revoke_label(label_id: str):
    """Revoke a PQC label."""
    ok = db.revoke_label(label_id)
    if not ok:
        raise HTTPException(status_code=500, detail="Revocation failed")
    return {"status": "revoked", "label_id": label_id}


@app.get("/api/db/alerts")
async def db_get_alerts(scan_id: int | None = None, severity: str | None = None, limit: int = 50):
    """Retrieve alerts with optional filters."""
    return JSONResponse(content=db.get_alerts(scan_id=scan_id, severity=severity, limit=limit))


# ── Phase 8+9: Full Pipeline (Regression + Labels + CBOM v2 + Attestation) ──

@app.get("/api/phase9/demo")
async def phase9_demo_pipeline():
    """Run the complete Phase 8+9 demo pipeline.

    Pipeline steps:
      1. Classify all 21 demo assets (Phase 7 tri-mode classifier)
      2. Classify baseline assets (degraded one-week-ago snapshot)
      3. Detect regressions between current and baseline (Phase 8)
      4. Label classified assets with 3-tier PQC certification (Phase 9)
      5. Persist labels to append-only registry
      6. Auto-revoke stale labels if regressions detected
      7. Generate CycloneDX 1.7 CBOM with vulnerabilities from regressions
      8. Generate signed CDXA attestation with FIPS compliance claims
      9. Return the full pipeline result
    """
    global _latest_classified, _latest_phase9

    # Step 1: Classify current assets
    current_assets = [classify_trimode(fp) for fp in DEMO_TRIMODE_FINGERPRINTS]
    _latest_classified = current_assets

    # Step 2: Classify baseline (degraded) assets
    baseline_fps = get_demo_baseline_fingerprints()
    baseline_assets = [classify_trimode(fp) for fp in baseline_fps]

    # Step 3: Regression detection
    regression = detect_regressions_demo(current_assets, baseline_assets)

    # Step 4: Phase 9 labeling
    label_summary = label_classified_assets(
        current_assets,
        is_demo=True,
        base_url="/api/registry/verify",
    )

    # Step 5: Persist labels to registry
    append_all_labels(label_summary)

    # Step 6: Auto-revoke stale labels
    revocations = auto_revoke_on_scan(current_assets, baseline_assets)

    # Step 7: CycloneDX 1.7 CBOM
    cbom = generate_cbom_v2(current_assets, regression, data_mode="demo")

    # Step 8: Signed CDXA attestation
    set_latest_attestation_context(label_summary, cbom)
    cdxa = generate_attestation_v2(label_summary, cbom)

    # Build full result
    _latest_phase9 = {
        "pipeline": "Phase 8+9 Demo",
        "version": "9.0.0",
        "steps_completed": 8,
        "classification": {
            "total_assets": len(current_assets),
            "assets": [a.model_dump(mode="json") for a in current_assets],
        },
        "regression": regression.model_dump(mode="json"),
        "labels": label_summary.model_dump(mode="json"),
        "registry": {
            "labels_persisted": len(label_summary.labels),
            "auto_revocations": revocations,
        },
        "cbom": cbom,
        "attestation": cdxa,
        "attestation_summary": get_attestation_summary(cdxa),
    }

    return JSONResponse(content=_latest_phase9)


@app.post("/api/phase9/live/{domain}")
async def phase9_live_pipeline(domain: str):
    """Run the complete Phase 8+9 pipeline on a LIVE domain.

    Pipeline:
      1. Discover real assets (DNS + CT logs)
      2. Tri-mode probe all discovered assets
      3. Classify each with Phase 7 tri-mode classifier
      4. Detect regressions vs previous DB scan
      5. Label with 3-tier PQC certification
      6. Persist labels + auto-revoke stale
      7. Generate CycloneDX 1.7 CBOM
      8. Generate signed CDXA attestation
    """
    global _latest_classified, _latest_phase9
    import asyncio

    try:
        # Step 1: Discover assets
        try:
            assets = await asyncio.wait_for(
                discover_assets(domain, include_ct=True, include_port_scan=False),
                timeout=20.0,
            )
        except asyncio.TimeoutError:
            assets = await asyncio.wait_for(
                discover_assets(domain, include_ct=False, include_port_scan=False),
                timeout=10.0,
            )
        if not assets:
            raise HTTPException(status_code=404, detail=f"No assets discovered for {domain}")

        # Step 2: Tri-mode probe
        fingerprints = await probe_batch(assets[:20], concurrency=20, demo=False)

        # Step 3: Classify each
        current_assets = []
        for fp in fingerprints:
            ca = classify_trimode(fp)
            current_assets.append(ca)

        _latest_classified = current_assets

        # Save scan to DB for future regression baseline
        counts = {s.value: 0 for s in PQCStatus}
        total_worst = 0
        for ca in current_assets:
            d = ca.model_dump(mode="json")
            counts[d["status"]] = counts.get(d["status"], 0) + 1
            total_worst += d["worst_case_score"]
        avg = round(total_worst / len(current_assets), 1) if current_assets else 0

        classified_dicts = [ca.model_dump(mode="json") for ca in current_assets]
        scan_id = db.save_scan(
            mode="live",
            domain=domain,
            total_assets=len(current_assets),
            avg_score=avg,
            fully_safe=counts.get("FULLY_QUANTUM_SAFE", 0),
            pqc_trans=counts.get("PQC_TRANSITION", 0),
            q_vuln=counts.get("QUANTUM_VULNERABLE", 0),
            crit_vuln=counts.get("CRITICALLY_VULNERABLE", 0),
            unknown=counts.get("UNKNOWN", 0),
            results_json=json.dumps(classified_dicts),
            classified_assets=classified_dicts,
        )

        # Step 4: Regression detection (live — uses DB for baseline)
        previous_scan = db.load_previous_scan()
        regression = detect_regressions(classified_dicts, scan_id, previous_scan, data_mode="live")

        # Step 5: Phase 9 labeling
        label_summary = label_classified_assets(
            current_assets,
            is_demo=False,
            base_url="/api/registry/verify",
        )

        # Step 6: Persist labels + auto-revoke
        append_all_labels(label_summary)
        revocations = auto_revoke_on_scan(current_assets, [])

        # Step 7: CycloneDX 1.7 CBOM
        cbom = generate_cbom_v2(current_assets, regression, data_mode="live")

        # Step 8: Signed CDXA attestation
        set_latest_attestation_context(label_summary, cbom)
        cdxa = generate_attestation_v2(label_summary, cbom)

        # Build full result
        _latest_phase9 = {
            "pipeline": "Phase 8+9 Live",
            "version": "9.0.0",
            "mode": "live",
            "domain": domain,
            "scan_id": scan_id,
            "steps_completed": 8,
            "classification": {
                "total_assets": len(current_assets),
                "assets": classified_dicts,
            },
            "regression": regression.model_dump(mode="json"),
            "labels": label_summary.model_dump(mode="json"),
            "registry": {
                "labels_persisted": len(label_summary.labels),
                "auto_revocations": revocations,
            },
            "cbom": cbom,
            "attestation": cdxa,
            "attestation_summary": get_attestation_summary(cdxa),
        }

        return JSONResponse(content=_latest_phase9)

    except HTTPException:
        raise
    except Exception as e:
        logger.exception("Phase 9 live pipeline failed for %s", domain)
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/phase9/regression")
async def phase9_regression():
    """Return the latest Phase 8 regression report."""
    if not _latest_phase9:
        raise HTTPException(status_code=404, detail="Run /api/phase9/demo first.")
    return JSONResponse(content=_latest_phase9.get("regression", {}))


@app.get("/api/phase9/labels")
async def phase9_labels():
    """Return the latest Phase 9 label summary."""
    if not _latest_phase9:
        raise HTTPException(status_code=404, detail="Run /api/phase9/demo first.")
    return JSONResponse(content=_latest_phase9.get("labels", {}))


@app.get("/api/phase9/cbom")
async def phase9_cbom():
    """Return the latest CycloneDX 1.7 CBOM."""
    if not _latest_phase9:
        raise HTTPException(status_code=404, detail="Run /api/phase9/demo first.")
    return JSONResponse(content=_latest_phase9.get("cbom", {}))


@app.get("/api/phase9/cbom/download")
async def phase9_cbom_download():
    """Download the CycloneDX 1.7 CBOM."""
    if not _latest_phase9:
        raise HTTPException(status_code=404, detail="Run /api/phase9/demo first.")
    return JSONResponse(
        content=_latest_phase9.get("cbom", {}),
        headers={"Content-Disposition": "attachment; filename=qarmor-cbom-v2.json"},
    )


@app.get("/api/phase9/attestation")
async def phase9_attestation():
    """Return the latest signed CDXA attestation."""
    if not _latest_phase9:
        raise HTTPException(status_code=404, detail="Run /api/phase9/demo first.")
    return JSONResponse(content=_latest_phase9.get("attestation", {}))


# ── New Dashboard/Data APIs ─────────────────────────────────────────────────

@app.get("/api/home/summary")
async def api_home_summary(mode: str = "demo", domain: str | None = None, refresh: bool = False):
    """Return aggregate home dashboard summary from the latest pipeline result."""
    pipeline_result = await _ensure_latest_pipeline_result(mode=mode, domain=domain, force_refresh=refresh)
    return JSONResponse(content=_compute_home_summary(pipeline_result))


@app.get("/api/assets/domains")
async def api_assets_domains(mode: str = "demo", domain: str | None = None):
    """Return discovered domain assets for the dashboard."""
    pipeline_result = await _ensure_latest_pipeline_result(mode=mode, domain=domain)
    demo_mode = pipeline_result.get("mode") == "demo"
    assets_payload = _derive_asset_discovery_payload(pipeline_result)
    return JSONResponse(content={
        "items": assets_payload["domains"],
        "demo_mode": demo_mode,
        "data_notice": _data_notice(demo_mode),
    })


@app.get("/api/assets/ssl")
async def api_assets_ssl(mode: str = "demo", domain: str | None = None):
    """Return SSL certificate assets for the dashboard."""
    pipeline_result = await _ensure_latest_pipeline_result(mode=mode, domain=domain)
    demo_mode = pipeline_result.get("mode") == "demo"
    assets_payload = _derive_asset_discovery_payload(pipeline_result)
    return JSONResponse(content={
        "items": assets_payload["ssl"],
        "demo_mode": demo_mode,
        "data_notice": _data_notice(demo_mode),
    })


@app.get("/api/assets/ip")
async def api_assets_ip(mode: str = "demo", domain: str | None = None):
    """Return IP assets for the dashboard."""
    pipeline_result = await _ensure_latest_pipeline_result(mode=mode, domain=domain)
    demo_mode = pipeline_result.get("mode") == "demo"
    assets_payload = _derive_asset_discovery_payload(pipeline_result)
    return JSONResponse(content={
        "items": assets_payload["ip"],
        "demo_mode": demo_mode,
        "data_notice": _data_notice(demo_mode),
    })


@app.get("/api/assets/software")
async def api_assets_software(mode: str = "demo", domain: str | None = None):
    """Return exposed software assets for the dashboard."""
    pipeline_result = await _ensure_latest_pipeline_result(mode=mode, domain=domain)
    demo_mode = pipeline_result.get("mode") == "demo"
    assets_payload = _derive_asset_discovery_payload(pipeline_result)
    return JSONResponse(content={
        "items": assets_payload["software"],
        "demo_mode": demo_mode,
        "data_notice": _data_notice(demo_mode),
    })


@app.get("/api/assets/network-graph")
async def api_assets_network_graph(mode: str = "demo", domain: str | None = None):
    """Return network graph data for the dashboard."""
    pipeline_result = await _ensure_latest_pipeline_result(mode=mode, domain=domain)
    demo_mode = pipeline_result.get("mode") == "demo"
    graph = _derive_asset_discovery_payload(pipeline_result)["network_graph"]
    graph["demo_mode"] = demo_mode
    graph["data_notice"] = _data_notice(demo_mode)
    return JSONResponse(content=graph)


@app.get("/api/cyber-rating")
async def api_cyber_rating(mode: str = "demo", domain: str | None = None):
    """Return enterprise cyber rating and display metadata."""
    pipeline_result = await _ensure_latest_pipeline_result(mode=mode, domain=domain)
    demo_mode = pipeline_result.get("mode") == "demo"
    rating = dict(pipeline_result.get("enterprise_cyber_rating", {}))
    rating["tier_criteria"] = TIER_CRITERIA
    rating["demo_mode"] = demo_mode
    rating["data_notice"] = _data_notice(demo_mode)
    return JSONResponse(content=rating)


@app.get("/api/pqc/heatmap")
async def api_pqc_heatmap(mode: str = "demo", domain: str | None = None):
    """Return PQC migration heatmap data."""
    pipeline_result = await _ensure_latest_pipeline_result(mode=mode, domain=domain)
    demo_mode = pipeline_result.get("mode") == "demo"
    heatmap = dict(pipeline_result.get("heatmap", {}))
    heatmap["demo_mode"] = demo_mode
    heatmap["data_notice"] = _data_notice(demo_mode)
    return JSONResponse(content=heatmap)


@app.get("/api/pqc/negotiation")
async def api_pqc_negotiation_all(mode: str = "demo", domain: str | None = None):
    """Return all negotiation policy records from the latest pipeline result."""
    pipeline_result = await _ensure_latest_pipeline_result(mode=mode, domain=domain)
    demo_mode = pipeline_result.get("mode") == "demo"
    return JSONResponse(content={
        "policies": pipeline_result.get("negotiation_policies", {}),
        "demo_mode": demo_mode,
        "data_notice": _data_notice(demo_mode),
    })


@app.get("/api/pqc/negotiation/{hostname}")
async def api_pqc_negotiation_one(hostname: str, mode: str = "demo", domain: str | None = None):
    """Return a single negotiation policy by hostname."""
    pipeline_result = await _ensure_latest_pipeline_result(mode=mode, domain=domain)
    demo_mode = pipeline_result.get("mode") == "demo"
    policy = pipeline_result.get("negotiation_policies", {}).get(hostname)
    if not policy:
        raise HTTPException(status_code=404, detail=f"Negotiation policy not found for {hostname}")

    content = dict(policy)
    content["demo_mode"] = demo_mode
    content["data_notice"] = _data_notice(demo_mode)
    return JSONResponse(content=content)


@app.get("/api/reporting/generate")
async def api_reporting_generate(
    report_type: str = "executive",
    format: str = "json",
    mode: str = "demo",
    domain: str | None = None,
    refresh: bool = False,
):
    """Generate a report payload from the latest pipeline result."""
    if format not in {"json", "html"}:
        raise HTTPException(status_code=400, detail="format must be one of: json, html")

    pipeline_result = await _ensure_latest_pipeline_result(mode=mode, domain=domain, force_refresh=refresh)
    demo_mode = pipeline_result.get("mode") == "demo"
    report_data = _build_report_section(report_type, pipeline_result)

    if format == "html":
        payload_data: dict[str, Any] = {
            "html": _render_report_html(report_type, report_data),
            "source": report_data,
        }
    else:
        payload_data = report_data

    return JSONResponse(content={
        "report_type": report_type,
        "generated_at": pipeline_result.get("timestamp"),
        "demo_mode": demo_mode,
        "data_notice": _data_notice(demo_mode),
        "data": payload_data,
    })