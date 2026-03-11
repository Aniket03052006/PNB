"""Q-ARMOR — FastAPI Application."""

from __future__ import annotations
import json
from pathlib import Path
from fastapi import FastAPI, HTTPException
from fastapi.staticfiles import StaticFiles
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.middleware.cors import CORSMiddleware
import logging

from backend.models import ScanSummary, PQCStatus, TriModeFingerprint
from backend.demo_data import (
    generate_demo_results,
    DEMO_TRIMODE_FINGERPRINTS,
    get_demo_baseline_fingerprints,
    get_historical_scan_summaries,
    _trimode_to_crypto,
)
from backend.scanner.cbom_generator import generate_cbom
from backend.scanner.classifier import classify
from backend.scanner.prober import probe_tls, probe_trimode, probe_batch
from backend.scanner.discoverer import discover_assets
from backend.scanner.assessment import analyze_endpoint, analyze_batch
from backend.scanner.remediation import generate_remediation, generate_batch_remediation
from backend.scanner.attestor import generate_attestation, verify_attestation, get_attestation_summary
from backend.scanner.notifier import detect_alerts, send_alerts, get_alert_summary

logger = logging.getLogger("qarmor.app")

app = FastAPI(
    title="Q-ARMOR",
    description="Quantum-Aware Mapping & Observation for Risk Remediation",
    version="6.0.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# Serve frontend static files
FRONTEND_DIR = Path(__file__).parent.parent / "frontend"
app.mount("/static", StaticFiles(directory=str(FRONTEND_DIR)), name="static")

# In-memory cache for latest scan
_latest_scan: ScanSummary | None = None
_latest_trimode: list[TriModeFingerprint] = []


@app.get("/", response_class=HTMLResponse)
async def serve_dashboard():
    """Serve the Q-ARMOR dashboard."""
    index_file = FRONTEND_DIR / "index.html"
    if not index_file.exists():
        raise HTTPException(status_code=404, detail="Dashboard not found")
    return HTMLResponse(content=index_file.read_text())


@app.get("/api/health")
async def health_check():
    """Health check endpoint."""
    return {"status": "operational", "service": "Q-ARMOR", "version": "6.0.0"}


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