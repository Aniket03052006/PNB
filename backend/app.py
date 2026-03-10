"""Q-ARMOR — FastAPI Application."""

from __future__ import annotations
import json
from pathlib import Path
from fastapi import FastAPI, HTTPException
from fastapi.staticfiles import StaticFiles
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.middleware.cors import CORSMiddleware
import logging

from backend.models import ScanSummary, PQCStatus
from backend.demo_data import generate_demo_results
from backend.scanner.cbom_generator import generate_cbom
from backend.scanner.classifier import classify
from backend.scanner.prober import probe_tls
from backend.scanner.discoverer import discover_assets
from backend.scanner.assessment import analyze_endpoint, analyze_batch
from backend.scanner.remediation import generate_remediation, generate_batch_remediation

logger = logging.getLogger("qarmor.app")

app = FastAPI(
    title="Q-ARMOR",
    description="Quantum-Aware Mapping & Observation for Risk Remediation",
    version="1.0.0",
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
    return {"status": "operational", "service": "Q-ARMOR", "version": "1.0.0"}


@app.get("/api/scan/demo")
async def run_demo_scan():
    """Run a demo scan with simulated bank assets."""
    global _latest_scan
    _latest_scan = generate_demo_results()
    return _latest_scan.model_dump()


@app.post("/api/scan/domain/{domain}")
async def scan_domain(domain: str):
    """Scan a real domain for cryptographic configuration."""
    global _latest_scan
    from backend.models import ScanResult

    try:
        import asyncio
        assets = await discover_assets(domain, include_ct=True, include_port_scan=False)
        
        async def scan_single_asset(asset) -> ScanResult:
            try:
                fp = await probe_tls(asset.hostname, asset.port)
                q = classify(fp)
                return ScanResult(asset=asset, fingerprint=fp, q_score=q)
            except Exception as e:
                return ScanResult(asset=asset, error=str(e))

        tasks = [scan_single_asset(asset) for asset in assets[:20]] # Cap at 20 assets
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
        return _latest_scan.model_dump()

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
        return result.model_dump()
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
    return [r.model_dump() for r in _latest_scan.remediation_roadmap]


@app.get("/api/labels")
async def get_labels():
    """Get all PQC-Ready labels issued."""
    if not _latest_scan:
        raise HTTPException(status_code=404, detail="No scan data. Run /api/scan/demo first.")
    return [l.model_dump() for l in _latest_scan.labels]


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
