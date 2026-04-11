"""Q-ARMOR — FastAPI Application (v9.0.0)."""

from __future__ import annotations
import asyncio
import hashlib
import json
import os
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import urlparse
from fastapi import Depends, FastAPI, HTTPException, Request, UploadFile
from fastapi.staticfiles import StaticFiles
from fastapi.responses import HTMLResponse, JSONResponse, StreamingResponse
from fastapi.middleware.cors import CORSMiddleware
from dotenv import load_dotenv
from starlette.middleware.gzip import GZipMiddleware
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
from backend.cyber_rating import TIER_CRITERIA, compute_enterprise_cyber_rating
from backend.pipeline import run_pipeline
from backend.scanner.cbom_generator import generate_cbom, generate_cbom_v2
from backend.scanner.cloud_detector import detect_cloud_provider, group_ips_by_subnet
from backend.scanner.classifier import classify, classify_trimode
from backend.scanner.prober import probe_tls, probe_trimode, probe_batch
from backend.scanner.discoverer import discover_assets
from backend.scanner.negotiation_policy import compute_heatmap
from backend.scanner.assessment import (
    KX_HYBRID,
    KX_PQC_SAFE,
    KX_VULNERABLE,
    RISK_HIGH,
    RISK_LOW,
    RISK_MEDIUM,
    SYM_FAIL,
    SYM_PASS,
    TLS_FAIL,
    TLS_PASS,
    analyze_batch,
    analyze_endpoint,
)
from backend.scanner.nist_matrix import QuantumStatus, classify_kex, classify_protocol, classify_signature, classify_symmetric
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
from backend import scan_history
from backend.auth import (
    AuthConfigurationError,
    get_current_user,
    get_public_auth_config,
    get_user_context,
    require_admin,
)

logger = logging.getLogger("qarmor.app")


def _configure_logging() -> None:
    fmt = "%(asctime)s  %(levelname)-8s  %(name)s  %(message)s"
    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(logging.Formatter(fmt, datefmt="%H:%M:%S"))
    root = logging.getLogger("qarmor")
    if not root.handlers:
        root.setLevel(logging.INFO)
        root.addHandler(handler)


_configure_logging()

load_dotenv()

app = FastAPI(
    title="Q-ARMOR",
    description="Quantum-Aware Mapping & Observation for Risk Remediation",
    version="9.0.0",
)

def _parse_frontend_origins() -> list[str]:
    """Parse deployment frontend origins from env.

    Supports:
    - FRONTEND_URLS="https://app.vercel.app,https://preview.vercel.app"
    - FRONTEND_URL="https://app.vercel.app"
    """
    raw_urls = os.environ.get("FRONTEND_URLS", "").strip()
    if not raw_urls:
        single = os.environ.get("FRONTEND_URL", "").strip()
        raw_urls = single
    origins = [item.strip().rstrip("/") for item in raw_urls.split(",") if item.strip()]
    # Preserve order while removing duplicates.
    return list(dict.fromkeys(origins))


_frontend_origins = _parse_frontend_origins()
_allowed_origins = _frontend_origins if _frontend_origins else ["*"]
_local_full_scan_default = "0"
LOCAL_FULL_SCAN = os.environ.get("QARMOR_LOCAL_FULL_SCAN", _local_full_scan_default) == "1"
LOCAL_API_CRAWL = os.environ.get("QARMOR_LOCAL_API_CRAWL", "0") == "1"
LIVE_SCAN_LIMIT = int(os.environ.get("QARMOR_LIVE_SCAN_LIMIT", "0"))

app.add_middleware(
    CORSMiddleware,
    allow_origins=_allowed_origins,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.add_middleware(
    GZipMiddleware,
    minimum_size=int(os.environ.get("QARMOR_GZIP_MIN_SIZE", "512")),
)

PUBLIC_ROUTES = {
    "/",
    "/auth",
    "/dashboard",
    "/favicon.ico",
    "/api/health",
    "/api/auth/config",
}
PUBLIC_PREFIXES = (
    "/static",
    "/css",
    "/js",
    "/docs",
    "/redoc",
    "/openapi.json",
    "/api/scan/stream",   # SSE endpoint — EventSource cannot send auth headers
)


def _is_public_path(path: str) -> bool:
    normalized = path if path == "/" else path.rstrip("/")
    if normalized in PUBLIC_ROUTES:
        return True
    return any(normalized.startswith(prefix) for prefix in PUBLIC_PREFIXES)


@app.middleware("http")
async def enforce_api_auth(request: Request, call_next):
    path = request.url.path
    if request.method == "OPTIONS" or _is_public_path(path) or not path.startswith("/api/"):
        return await call_next(request)

    try:
        get_current_user(request)
    except HTTPException as exc:
        return JSONResponse(
            status_code=exc.status_code,
            content={"detail": exc.detail},
            headers=exc.headers or None,
        )
    except AuthConfigurationError as exc:
        logger.exception("Authentication configuration error")
        return JSONResponse(status_code=500, content={"detail": str(exc)})

    return await call_next(request)

# Ensure data directory exists for SQLite
Path("data").mkdir(exist_ok=True)

# Mount Phase 8+9 sub-routers
app.include_router(registry_router)
app.include_router(attestation_router)


async def _populate_phase9_demo_cache() -> None:
    """Run the demo Phase 8+9 pipeline and populate _latest_phase9 cache.

    Uses latest classified assets from a previous scan if available,
    otherwise falls back to the DEMO_TRIMODE_FINGERPRINTS.
    """
    global _latest_classified, _latest_phase9
    # Prefer classified assets from the most recent scan (live or demo)
    if _latest_classified:
        current_assets = _latest_classified
    else:
        current_assets = [classify_trimode(fp) for fp in DEMO_TRIMODE_FINGERPRINTS]
        _latest_classified = current_assets
    baseline_fps = get_demo_baseline_fingerprints()
    baseline_assets = [classify_trimode(fp) for fp in baseline_fps]
    regression = detect_regressions_demo(current_assets, baseline_assets)
    label_summary = label_classified_assets(
        current_assets,
        is_demo=True,
        base_url="/api/registry/verify",
    )
    append_all_labels(label_summary)
    revocations = auto_revoke_on_scan(current_assets, baseline_assets)
    cbom = generate_cbom_v2(current_assets, regression, data_mode="demo")
    set_latest_attestation_context(label_summary, cbom)
    cdxa = generate_attestation_v2(label_summary, cbom)
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


@app.on_event("startup")
async def _startup_populate_demo() -> None:
    """Pre-warm the demo pipeline so Phase-9 GET endpoints return data immediately."""
    try:
        await _ensure_latest_pipeline_result(mode="demo")
        await _populate_phase9_demo_cache()
        logger.info("Startup demo pipeline populated — Phase-9 endpoints ready")
    except Exception:
        logger.warning("Startup demo pipeline failed — Phase-9 endpoints will return 404 until triggered manually")

# Serve frontend static files
FRONTEND_DIR = Path(__file__).parent.parent / "frontend"
app.mount("/static", StaticFiles(directory=str(FRONTEND_DIR)), name="static")
app.mount("/css", StaticFiles(directory=str(FRONTEND_DIR / "css")), name="frontend-css")
app.mount("/js", StaticFiles(directory=str(FRONTEND_DIR / "js")), name="frontend-js")

# In-memory cache for latest scan
_latest_scan: ScanSummary | None = None
_latest_trimode: list[TriModeFingerprint] = []
_latest_classified: list[ClassifiedAsset] = []
_latest_phase9: dict = {}
_latest_pipeline_result: dict[str, Any] = {}
_latest_pipeline_context: dict[str, Any] = {"mode": "demo", "domain": None}


def _data_notice(demo_mode: bool) -> str:
    return "SIMULATED DATA" if demo_mode else "LIVE DATA"


def _live_scan_options() -> dict[str, Any]:
    return {
        "include_ct": True,
        "include_port_scan": LOCAL_FULL_SCAN,
        "include_api_crawl": LOCAL_API_CRAWL,
        "limit": LIVE_SCAN_LIMIT,
    }


def _select_live_assets(assets: list[Any], limit: int) -> list[Any]:
    return assets if limit <= 0 else assets[:limit]


def _normalize_pipeline_mode(mode: str | None) -> str:
    normalized = (mode or "demo").strip().lower()
    if normalized not in {"demo", "live"}:
        raise HTTPException(status_code=400, detail="mode must be one of: demo, live")
    return normalized


def _normalize_hostname_input(raw: str, *, allow_port: bool = False) -> tuple[str, int | None]:
    value = (raw or "").strip()
    if not value:
        raise HTTPException(status_code=400, detail="hostname is required")

    candidate = value if "://" in value else f"https://{value}"
    hostname = ""
    port: int | None = None

    try:
        parsed = urlparse(candidate)
        hostname = (parsed.hostname or "").strip().rstrip(".")
        if parsed.port:
            port = parsed.port
    except ValueError:
        hostname = ""

    if not hostname:
        stripped = value
        if "://" in stripped:
            stripped = stripped.split("://", 1)[1]
        stripped = stripped.split("/", 1)[0].split("?", 1)[0].split("#", 1)[0].rstrip(".")
        if allow_port and ":" in stripped and stripped.count(":") == 1:
            maybe_host, maybe_port = stripped.rsplit(":", 1)
            if maybe_port.isdigit():
                hostname = maybe_host.strip("[]")
                port = int(maybe_port)
            else:
                hostname = stripped.strip("[]")
        else:
            hostname = stripped.split(":", 1)[0].strip("[]")

    if not hostname:
        raise HTTPException(status_code=400, detail="Enter a valid hostname or domain")

    return hostname, port


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


def _normalize_asset(asset: dict[str, Any]) -> dict[str, Any]:
    """Flatten live-scan nested format {asset:{hostname}, q_score:{total,status}}
    into the same flat shape that the pipeline produces, so all consumers are consistent."""
    if not isinstance(asset, dict):
        return asset
    # Already flat (pipeline format) — has hostname at top level
    if "hostname" in asset:
        return asset
    # Nested live-scan format
    inner = asset.get("asset") or {}
    q = asset.get("q_score") or {}
    q_total = q.get("total", 0) if isinstance(q, dict) else (q or 0)
    q_status = q.get("status", "UNKNOWN") if isinstance(q, dict) else "UNKNOWN"
    flat = {**asset}
    flat["hostname"] = inner.get("hostname") or inner.get("ip") or ""
    flat["ip"] = inner.get("ip") or ""
    flat["port"] = inner.get("port") or 443
    flat["asset_type"] = inner.get("asset_type") or ""
    flat["worst_case_score"] = q_total
    flat["worst_score"] = q_total
    flat["status"] = q_status
    flat["pqc_status"] = q_status
    flat["q_score"] = q
    tls = (asset.get("fingerprint") or {}).get("tls") or {}
    flat.setdefault("tls_version", tls.get("version") or "")
    flat.setdefault("cipher_suite", tls.get("cipher_suite") or "")
    flat.setdefault("cipher_bits", tls.get("cipher_bits") or 0)
    flat.setdefault("key_exchange", tls.get("key_exchange") or "")
    return flat


def _parse_scan_results(scan: dict[str, Any] | None) -> list[dict[str, Any]]:
    if not scan:
        return []
    raw = scan.get("results_json", "[]")
    if isinstance(raw, list):
        return [_normalize_asset(a) for a in raw]
    if not isinstance(raw, str):
        return []
    try:
        parsed = json.loads(raw)
    except json.JSONDecodeError:
        return []
    if not isinstance(parsed, list):
        return []
    return [_normalize_asset(a) for a in parsed]


def _status_counts_from_assets(assets: list[dict[str, Any]]) -> dict[str, int]:
    counts = {status.value: 0 for status in PQCStatus}
    for asset in assets:
        q_score = asset.get("q_score")
        q_status = q_score.get("status") if isinstance(q_score, dict) else None
        status = str(asset.get("status") or asset.get("pqc_status") or q_status or "UNKNOWN")
        counts[status] = counts.get(status, 0) + 1
    return counts


def _average_asset_score(assets: list[dict[str, Any]]) -> float:
    if not assets:
        return 0.0
    total = 0.0
    for asset in assets:
        q_score = asset.get("q_score")
        q_total = q_score.get("total", 0) if isinstance(q_score, dict) else q_score
        total += float(
            asset.get("worst_case_score")
            or asset.get("worst_score")
            or q_total
            or 0
        )
    return round(total / len(assets), 1)


def _latest_scan_payload_from_assets(
    assets: list[dict[str, Any]],
    *,
    scan_id: Any = None,
    mode: str = "demo",
    domain: str = "",
) -> dict[str, Any]:
    counts = _status_counts_from_assets(assets)
    demo_mode = str(mode).lower() == "demo"
    return {
        "scan_id": scan_id,
        "mode": mode,
        "domain": domain,
        "total_assets": len(assets),
        "average_q_score": _average_asset_score(assets),
        "fully_quantum_safe": counts.get(PQCStatus.FULLY_QUANTUM_SAFE.value, 0),
        "pqc_transition": counts.get(PQCStatus.PQC_TRANSITION.value, 0),
        "quantum_vulnerable": counts.get(PQCStatus.QUANTUM_VULNERABLE.value, 0),
        "critically_vulnerable": counts.get(PQCStatus.CRITICALLY_VULNERABLE.value, 0),
        "unknown": counts.get(PQCStatus.UNKNOWN.value, 0),
        "assets": assets,
        "asset_scores": assets,
        "demo_mode": demo_mode,
        "data_notice": _data_notice(demo_mode),
    }


def _request_user_id(request: Request | None) -> str | None:
    if request is None:
        return None
    try:
        user = get_current_user(request)
    except Exception:
        return None
    user_id = str(user.get("sub") or "").strip()
    return user_id or None


def _save_user_scan_history(
    request: Request | None,
    results: list[dict[str, Any]] | None,
    *,
    mode: str,
    domain: str = "",
    details: dict[str, Any] | None = None,
) -> int | None:
    user_id = _request_user_id(request)
    if not user_id or not results or not scan_history.is_configured():
        return None
    try:
        return scan_history.save_scan_history(
            user_id=user_id,
            results=results,
            mode=mode,
            domain=domain,
            details=details,
        )
    except Exception:
        logger.exception("Failed to persist user scan history")
        return None


def _history_scans_for_request(request: Request | None, limit: int = 0) -> list[dict[str, Any]]:
    user_id = _request_user_id(request)
    if not user_id or not scan_history.is_configured():
        return []
    return scan_history.list_scans(user_id, limit)


def _history_scan_for_request(request: Request | None, scan_id: str) -> dict[str, Any] | None:
    user_id = _request_user_id(request)
    if not user_id or not scan_history.is_configured():
        return None
    return scan_history.load_scan(user_id, scan_id)


def _history_latest_scan_for_request(request: Request | None) -> dict[str, Any] | None:
    user_id = _request_user_id(request)
    if not user_id or not scan_history.is_configured():
        return None
    return scan_history.load_latest_scan(user_id)


def _history_asset_for_request(request: Request | None, asset: str, limit: int = 10) -> list[dict[str, Any]]:
    user_id = _request_user_id(request)
    if not user_id or not scan_history.is_configured():
        return []
    return scan_history.get_asset_history(user_id, asset, limit)


def _compare_scan_summaries(scan_a: dict[str, Any], scan_b: dict[str, Any]) -> dict[str, Any]:
    return {
        "scan_a": {
            "id": scan_a.get("id"),
            "total": scan_a.get("total_assets", 0),
            "avg": scan_a.get("avg_score", 0),
            "fully_safe": scan_a.get("fully_safe", 0),
            "pqc_trans": scan_a.get("pqc_trans", 0),
            "q_vuln": scan_a.get("q_vuln", 0),
            "crit_vuln": scan_a.get("crit_vuln", 0),
            "total_assets": scan_a.get("total_assets", 0),
            "avg_score": scan_a.get("avg_score", 0),
        },
        "scan_b": {
            "id": scan_b.get("id"),
            "total": scan_b.get("total_assets", 0),
            "avg": scan_b.get("avg_score", 0),
            "fully_safe": scan_b.get("fully_safe", 0),
            "pqc_trans": scan_b.get("pqc_trans", 0),
            "q_vuln": scan_b.get("q_vuln", 0),
            "crit_vuln": scan_b.get("crit_vuln", 0),
            "total_assets": scan_b.get("total_assets", 0),
            "avg_score": scan_b.get("avg_score", 0),
        },
        "delta": {
            "total_assets": int(scan_b.get("total_assets", 0) or 0) - int(scan_a.get("total_assets", 0) or 0),
            "avg_score": round(float(scan_b.get("avg_score", 0) or 0) - float(scan_a.get("avg_score", 0) or 0), 1),
            "fully_safe": int(scan_b.get("fully_safe", 0) or 0) - int(scan_a.get("fully_safe", 0) or 0),
            "pqc_trans": int(scan_b.get("pqc_trans", 0) or 0) - int(scan_a.get("pqc_trans", 0) or 0),
            "q_vuln": int(scan_b.get("q_vuln", 0) or 0) - int(scan_a.get("q_vuln", 0) or 0),
            "crit_vuln": int(scan_b.get("crit_vuln", 0) or 0) - int(scan_a.get("crit_vuln", 0) or 0),
        },
    }


def _history_compare_for_request(request: Request | None, scan_a: str, scan_b: str) -> dict[str, Any] | None:
    user_id = _request_user_id(request)
    if not user_id or not scan_history.is_configured():
        return None
    return scan_history.compare_scans(user_id, scan_a, scan_b)


def _normalize_compare_payload(result: dict[str, Any], *, demo_mode: bool | None = None) -> dict[str, Any]:
    if not isinstance(result, dict):
        return result

    new_assets = result.get("new_assets")
    removed_assets = result.get("removed_assets")
    changed_assets = result.get("changed_assets")

    normalized = dict(result)
    def _change_reason(item: dict[str, Any]) -> str | None:
        if item.get("reason"):
            return item.get("reason")
        old_status = item.get("old_status")
        new_status = item.get("new_status")
        if old_status and new_status and old_status != new_status:
            return f"Status changed from {old_status} to {new_status}"
        return None

    normalized["new"] = (
        result.get("new")
        if isinstance(result.get("new"), list)
        else [item.get("asset", item) if isinstance(item, dict) else item for item in (new_assets or [])]
    )
    normalized["removed"] = (
        result.get("removed")
        if isinstance(result.get("removed"), list)
        else [item.get("asset", item) if isinstance(item, dict) else item for item in (removed_assets or [])]
    )
    normalized["changed"] = (
        result.get("changed")
        if isinstance(result.get("changed"), list)
        else [
            {
                "asset": item.get("asset"),
                "old_score": item.get("old_score", item.get("old", item.get("old_worst", 0))),
                "new_score": item.get("new_score", item.get("new", item.get("new_worst", 0))),
                "delta": item.get("delta", 0),
                "old_status": item.get("old_status"),
                "new_status": item.get("new_status"),
                "reason": _change_reason(item),
            }
            for item in (changed_assets or [])
            if isinstance(item, dict)
        ]
    )

    if not isinstance(new_assets, list):
        normalized["new_assets"] = [{"asset": asset} for asset in normalized["new"]]
    if not isinstance(removed_assets, list):
        normalized["removed_assets"] = [{"asset": asset} for asset in normalized["removed"]]
    if not isinstance(changed_assets, list):
        normalized["changed_assets"] = list(normalized["changed"])
    else:
        normalized["changed_assets"] = [
            {
                **item,
                "reason": _change_reason(item),
            }
            if isinstance(item, dict) else item
            for item in changed_assets
        ]

    raw_regressions = result.get("regressions") or [
        item for item in normalized["changed"]
        if isinstance(item, dict) and float(item.get("delta", 0) or 0) <= -5
    ]
    normalized["regressions"] = [
        {
            **item,
            "reason": item.get("reason") or _change_reason(item) or "Score drop ≥ 5 detected",
        }
        if isinstance(item, dict) else item
        for item in raw_regressions
    ]

    if demo_mode is not None:
        normalized["demo_mode"] = demo_mode
        normalized["data_notice"] = _data_notice(demo_mode)
    return normalized


def _infer_cipher_bits(cipher_name: str, fallback: Any = 0) -> int:
    if fallback:
        try:
            return int(fallback)
        except (TypeError, ValueError):
            pass
    upper = str(cipher_name or "").upper()
    if "CHACHA20" in upper:
        return 256
    for bit_size in (512, 384, 256, 192, 168, 128, 112, 64, 56, 40):
        if str(bit_size) in upper:
            return bit_size
    return 0


def _assessment_kex_status(name: str) -> str:
    mapping = {
        QuantumStatus.PQC_SAFE: KX_PQC_SAFE,
        QuantumStatus.HYBRID_PQC: KX_HYBRID,
        QuantumStatus.COMPLIANT: KX_VULNERABLE,
        QuantumStatus.VULNERABLE: KX_VULNERABLE,
        QuantumStatus.WEAKENED: KX_VULNERABLE,
        QuantumStatus.LEGACY_PROTOCOL: KX_VULNERABLE,
    }
    return mapping.get(classify_kex(name or "UNKNOWN"), KX_VULNERABLE)


def _assessment_certificate_status(name: str) -> str:
    if not name or name == "Unknown":
        return KX_VULNERABLE
    sig_status = classify_signature(name)
    if sig_status == QuantumStatus.PQC_SAFE:
        return KX_PQC_SAFE
    if sig_status == QuantumStatus.HYBRID_PQC:
        return KX_HYBRID
    return KX_VULNERABLE


def _assessment_symmetric_status(cipher_name: str, cipher_bits: int) -> str:
    if not cipher_name or cipher_name == "Unknown":
        return SYM_FAIL
    return (
        SYM_PASS
        if classify_symmetric(cipher_name, cipher_bits) in (QuantumStatus.COMPLIANT, QuantumStatus.PQC_SAFE)
        else SYM_FAIL
    )


def _pipeline_asset_to_assessment(asset: dict[str, Any]) -> dict[str, Any]:
    tls_version = str(asset.get("tls_version") or "Unknown")
    tls_status = TLS_PASS if classify_protocol(tls_version) == QuantumStatus.COMPLIANT else TLS_FAIL

    key_exchange = str(asset.get("key_exchange") or "UNKNOWN")
    key_exchange_status = _assessment_kex_status(key_exchange)

    certificate_algorithm = str(asset.get("cert_algorithm") or asset.get("certificate_algorithm") or "Unknown")
    certificate_status = _assessment_certificate_status(certificate_algorithm)

    symmetric_cipher = str(
        asset.get("cipher_suite")
        or asset.get("cipher")
        or asset.get("cipher_algorithm")
        or "Unknown"
    )
    cipher_bits = _infer_cipher_bits(symmetric_cipher, asset.get("cipher_bits"))
    symmetric_cipher_status = _assessment_symmetric_status(symmetric_cipher, cipher_bits)

    q_score = int(
        asset.get("worst_case_score")
        or asset.get("worst_score")
        or asset.get("q_score", 0)
        or 0
    )
    pqc_status = str(asset.get("status") or asset.get("pqc_status") or "UNKNOWN")
    hndl_vulnerable = int(asset.get("negotiation_security_score") or 0) < 0 or key_exchange_status == KX_VULNERABLE

    fail_count = sum(
        [
            tls_status == TLS_FAIL,
            key_exchange_status == KX_VULNERABLE,
            certificate_status == KX_VULNERABLE,
            symmetric_cipher_status == SYM_FAIL,
        ]
    )
    hybrid_count = sum(
        [
            key_exchange_status == KX_HYBRID,
            certificate_status == KX_HYBRID,
        ]
    )
    pqc_safe_count = sum(
        [
            tls_status == TLS_PASS,
            key_exchange_status == KX_PQC_SAFE,
            certificate_status == KX_PQC_SAFE,
            symmetric_cipher_status == SYM_PASS,
        ]
    )

    if tls_status == TLS_FAIL and key_exchange_status == KX_VULNERABLE:
        risk = RISK_HIGH
        risk_summary = "Legacy transport with vulnerable key exchange."
    elif fail_count >= 2 or (hndl_vulnerable and hybrid_count == 0):
        risk = RISK_HIGH
        risk_summary = "High exposure to harvest-now-decrypt-later risk."
    elif pqc_safe_count >= 3 and fail_count == 0:
        risk = RISK_LOW
        risk_summary = "Broad PQC-aligned coverage across transport, key exchange, and certificate posture."
    else:
        risk = RISK_MEDIUM
        risk_summary = "Mixed posture with partial PQC coverage and remediation still required."

    worst_case_q = asset.get("worst_case_q")
    findings = worst_case_q.get("findings", []) if isinstance(worst_case_q, dict) else []

    return {
        "target": str(asset.get("hostname") or "unknown"),
        "port": int(asset.get("port") or 443),
        "assessed_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "tls_status": tls_status,
        "tls_version": tls_version,
        "tls_details": f"Observed protocol: {tls_version}.",
        "key_exchange_status": key_exchange_status,
        "key_exchange_algorithm": key_exchange,
        "key_exchange_details": f"Observed key exchange: {key_exchange}.",
        "certificate_status": certificate_status,
        "certificate_algorithm": certificate_algorithm,
        "certificate_details": f"Observed certificate algorithm: {certificate_algorithm}.",
        "symmetric_cipher_status": symmetric_cipher_status,
        "symmetric_cipher": symmetric_cipher,
        "symmetric_bits": cipher_bits,
        "symmetric_details": f"Observed symmetric cipher: {symmetric_cipher}.",
        "overall_quantum_risk": risk,
        "risk_summary": risk_summary,
        "hndl_vulnerable": hndl_vulnerable,
        "q_score": q_score,
        "pqc_status": pqc_status,
        "findings": findings,
        "nist_references": [],
    }


def _build_pipeline_assessment_batch(assets: list[dict[str, Any]]) -> dict[str, Any]:
    assessments = [_pipeline_asset_to_assessment(asset) for asset in assets]
    total = len(assessments)

    tls_pass = sum(1 for item in assessments if item.get("tls_status") == TLS_PASS)
    kex_vulnerable = sum(1 for item in assessments if item.get("key_exchange_status") == KX_VULNERABLE)
    kex_hybrid = sum(1 for item in assessments if item.get("key_exchange_status") == KX_HYBRID)
    kex_pqc_safe = sum(1 for item in assessments if item.get("key_exchange_status") == KX_PQC_SAFE)
    cert_vulnerable = sum(1 for item in assessments if item.get("certificate_status") == KX_VULNERABLE)
    cert_hybrid = sum(1 for item in assessments if item.get("certificate_status") == KX_HYBRID)
    cert_pqc_safe = sum(1 for item in assessments if item.get("certificate_status") == KX_PQC_SAFE)
    sym_pass = sum(1 for item in assessments if item.get("symmetric_cipher_status") == SYM_PASS)
    risk_high = sum(1 for item in assessments if item.get("overall_quantum_risk") == RISK_HIGH)
    risk_medium = sum(1 for item in assessments if item.get("overall_quantum_risk") == RISK_MEDIUM)
    risk_low = sum(1 for item in assessments if item.get("overall_quantum_risk") == RISK_LOW)
    hndl_vulnerable = sum(1 for item in assessments if item.get("hndl_vulnerable"))
    counts = _status_counts_from_assets(assets)
    avg_score = round(sum(item.get("q_score", 0) for item in assessments) / total, 1) if total else 0.0

    return {
        "assessed_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "total_endpoints": total,
        "assessments": assessments,
        "aggregate": {
            "total_endpoints": total,
            "average_q_score": avg_score,
            "tls_pass": tls_pass,
            "tls_fail": total - tls_pass,
            "tls_pass_pct": round(tls_pass / total * 100, 1) if total else 0,
            "kex_vulnerable": kex_vulnerable,
            "kex_hybrid": kex_hybrid,
            "kex_pqc_safe": kex_pqc_safe,
            "kex_vulnerable_pct": round(kex_vulnerable / total * 100, 1) if total else 0,
            "kex_hybrid_pct": round(kex_hybrid / total * 100, 1) if total else 0,
            "kex_pqc_safe_pct": round(kex_pqc_safe / total * 100, 1) if total else 0,
            "cert_vulnerable": cert_vulnerable,
            "cert_hybrid": cert_hybrid,
            "cert_pqc_safe": cert_pqc_safe,
            "sym_pass": sym_pass,
            "sym_fail": total - sym_pass,
            "sym_pass_pct": round(sym_pass / total * 100, 1) if total else 0,
            "risk_high": risk_high,
            "risk_medium": risk_medium,
            "risk_low": risk_low,
            "risk_high_pct": round(risk_high / total * 100, 1) if total else 0,
            "hndl_vulnerable": hndl_vulnerable,
            "hndl_vulnerable_pct": round(hndl_vulnerable / total * 100, 1) if total else 0,
            "fully_quantum_safe": counts.get(PQCStatus.FULLY_QUANTUM_SAFE.value, 0),
            "pqc_transition": counts.get(PQCStatus.PQC_TRANSITION.value, 0),
            "quantum_vulnerable": counts.get(PQCStatus.QUANTUM_VULNERABLE.value, 0),
            "critically_vulnerable": counts.get(PQCStatus.CRITICALLY_VULNERABLE.value, 0),
        },
    }


def _build_legacy_scan_summary_from_fingerprints(fingerprints: list[TriModeFingerprint]) -> ScanSummary:
    from backend.models import DiscoveredAsset, ScanResult
    from backend.demo_data import _build_remediation_roadmap
    from backend.scanner.label_issuer import issue_label

    results: list[ScanResult] = []
    counts = {status: 0 for status in PQCStatus}
    total_score = 0

    for fp in fingerprints:
        crypto = _trimode_to_crypto(fp)
        classified_asset = classify_trimode(fp)
        q_score = classified_asset.worst_case_q.model_copy(deep=True)
        q_score.status = classified_asset.status
        asset = DiscoveredAsset(
            hostname=fp.hostname,
            ip=fp.ip,
            port=fp.port,
            asset_type=fp.asset_type,
            discovery_method="dns+ct" if fp.port == 443 else "dns+ct+portscan",
        )
        results.append(
            ScanResult(
                asset=asset,
                fingerprint=crypto,
                q_score=q_score,
                scan_duration_ms=fp.scan_duration_ms,
                error=fp.error,
            )
        )
        counts[q_score.status] += 1
        total_score += q_score.total

    labels = [label for result in results if (label := issue_label(result.asset.hostname, result.asset.port, result.q_score))]

    return ScanSummary(
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


def _pipeline_assets_from_scan_summary(scan_summary: ScanSummary) -> list[dict[str, Any]]:
    """Build pipeline-like asset records from legacy scan summary results."""
    summary = json.loads(scan_summary.model_dump_json())
    assets: list[dict[str, Any]] = []

    for item in summary.get("results", []):
        asset = item.get("asset") or {}
        fingerprint = item.get("fingerprint") or {}
        tls = fingerprint.get("tls") or {}
        certificate = fingerprint.get("certificate") or {}
        q_score = item.get("q_score") or {}

        total_score = int(q_score.get("total") or 0)
        status = str(q_score.get("status") or "UNKNOWN")

        assets.append({
            "hostname": str(asset.get("hostname") or ""),
            "ip": str(asset.get("ip") or ""),
            "port": int(asset.get("port") or 443),
            "asset_type": str(asset.get("asset_type") or "web"),
            "status": status,
            "best_case_score": total_score,
            "typical_score": total_score,
            "worst_case_score": total_score,
            "key_exchange": str(tls.get("key_exchange") or ""),
            "tls_version": str(tls.get("version") or ""),
            "cipher_suite": str(tls.get("cipher_suite") or ""),
            "cipher_bits": int(tls.get("cipher_bits") or 0),
            "cert_algorithm": str(certificate.get("signature_algorithm") or "Unknown"),
            "negotiation_tier": "UNKNOWN",
            "negotiation_security_score": 0,
        })

    return assets


def _cache_pipeline_from_scan_summary(scan_summary: ScanSummary, *, mode: str, domain: str) -> None:
    """Keep pipeline cache aligned with legacy scan endpoints for UI consistency."""
    global _latest_pipeline_result, _latest_pipeline_context

    assets = _pipeline_assets_from_scan_summary(scan_summary)
    tier_by_status = {
        "FULLY_QUANTUM_SAFE": "STRONG",
        "PQC_TRANSITION": "MEDIUM",
        "QUANTUM_VULNERABLE": "WEAK",
        "CRITICALLY_VULNERABLE": "CRITICAL",
        "UNKNOWN": "WEAK",
    }

    heatmap = compute_heatmap([
        {
            "hostname": str(asset.get("hostname") or ""),
            "pqc_status": str(asset.get("status") or "UNKNOWN"),
            "negotiation_tier": tier_by_status.get(str(asset.get("status") or "UNKNOWN"), "WEAK"),
        }
        for asset in assets
    ])

    enterprise_cyber_rating = compute_enterprise_cyber_rating([
        {
            "hostname": str(asset.get("hostname") or ""),
            "q_score": int(asset.get("worst_case_score") or 0),
            "pqc_status": str(asset.get("status") or "UNKNOWN"),
        }
        for asset in assets
    ])

    _latest_pipeline_result = {
        "scan_id": None,
        "timestamp": scan_summary.scan_timestamp,
        "mode": mode,
        "assets": assets,
        "negotiation_policies": {},
        "heatmap": heatmap,
        "enterprise_cyber_rating": enterprise_cyber_rating,
        "cbom": {},
        "labels": {},
        "alerts": [],
        "regression_summary": {},
        "attestation": {},
    }
    _latest_pipeline_context = {
        "mode": mode,
        "domain": domain or None,
    }


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
            "pqc_status": str(asset.get("status", "UNKNOWN")),
            "worst_case_score": int(asset.get("worst_case_score", 0)),
            "typical_score": int(asset.get("typical_score", 0)),
            "best_case_score": int(asset.get("best_case_score", 0)),
            "ip_address": str(asset.get("ip") or ""),
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


async def _live_ip_assets(pipeline_result: dict[str, Any]) -> list[dict[str, Any]]:
    detection_date = _pipeline_detection_date(pipeline_result)
    dedup: dict[str, dict[str, Any]] = {}
    ip_to_hostname: dict[str, str] = {}

    for asset in pipeline_result.get("assets", []):
        ip = str(asset.get("ip") or "").strip()
        if not ip:
            continue
        port = int(asset.get("port", 443))
        hostname = str(asset.get("hostname", ""))
        if ip not in dedup:
            parts = ip.split(".")
            subnet = ".".join(parts[:3]) + ".0/24" if len(parts) == 4 else ""
            dedup[ip] = {
                "detection_date": detection_date,
                "ip_address": ip,
                "ports": [port],
                "subnet": subnet,
                "asn": "",
                "netname": "Live Discovery",
                "location": "",
                "company": _company_from_hostname(hostname),
                "cloud_provider": "unknown",
                "cloud_display_name": "Unknown",
                "is_cloud_hosted": False,
                "pool": "self_hosted",
            }
            ip_to_hostname[ip] = hostname
        elif port not in dedup[ip]["ports"]:
            dedup[ip]["ports"].append(port)

    # Enrich with cloud detection (concurrent)
    ips = list(dedup.keys())
    if ips:
        cloud_results = await asyncio.gather(
            *[detect_cloud_provider(ip, ip_to_hostname.get(ip)) for ip in ips],
            return_exceptions=True,
        )
        for ip, cloud_info in zip(ips, cloud_results):
            if isinstance(cloud_info, dict):
                dedup[ip]["cloud_provider"] = cloud_info["provider"]
                dedup[ip]["cloud_display_name"] = cloud_info["display_name"]
                dedup[ip]["is_cloud_hosted"] = cloud_info["is_cloud"]
                dedup[ip]["pool"] = cloud_info["pool"]
                # Use cloud provider as netname when identified
                if cloud_info["is_cloud"]:
                    dedup[ip]["netname"] = cloud_info["display_name"]

    return list(dedup.values())


def _live_software_assets(pipeline_result: dict[str, Any]) -> list[dict[str, Any]]:
    detection_date = _pipeline_detection_date(pipeline_result)
    records: list[dict[str, Any]] = []
    for asset in pipeline_result.get("assets", []):
        host = str(asset.get("hostname", ""))
        if not host:
            continue
        kex = str(asset.get("key_exchange") or "")
        tls_ver = str(asset.get("tls_version") or "")
        cipher = str(asset.get("cipher_suite") or "")
        # Derive a human-readable product name from KEX
        if "ML-KEM" in kex or "MLKEM" in kex:
            product = "PQC TLS Stack (ML-KEM)"
        elif "KYBER" in kex:
            product = "PQC TLS Stack (Kyber)"
        elif "X25519" in kex:
            product = "Modern TLS Stack (X25519)"
        elif "ECDHE" in kex:
            product = "TLS Stack (ECDHE)"
        elif "DHE" in kex or "EDH" in kex:
            product = "TLS Stack (DHE)"
        elif "RSA" in kex:
            product = "Legacy TLS Stack (RSA KEX)"
        else:
            product = "TLS Stack"
        # supported_ciphers may come from fingerprint probe_b
        supported_ciphers = list(asset.get("supported_ciphers") or [])
        records.append({
            "detection_date": detection_date,
            "product": product,
            "version": tls_ver,
            "type": "CryptoProfile",
            "port": int(asset.get("port", 443)),
            "host": host,
            "company_name": _company_from_hostname(host),
            "negotiated_cipher": cipher,
            "key_exchange": kex,
            "supported_ciphers": supported_ciphers,
            "pqc_status": str(asset.get("status", "UNKNOWN")),
        })
    return records


def _live_network_graph(pipeline_result: dict[str, Any], ip_cloud_map: dict[str, dict] | None = None) -> dict[str, Any]:
    nodes: list[dict[str, Any]] = []
    edges: list[dict[str, str]] = []
    ip_nodes: set[str] = set()
    domain_nodes: list[str] = []
    pool_nodes_added: set[str] = set()
    ip_cloud_map = ip_cloud_map or {}

    for asset in pipeline_result.get("assets", []):
        host = str(asset.get("hostname", "")).strip()
        if not host:
            continue

        status = str(asset.get("status", "UNKNOWN"))
        ip = str(asset.get("ip") or "").strip()
        cloud_info = ip_cloud_map.get(ip, {})
        cloud_provider = cloud_info.get("provider", "unknown")
        pool = cloud_info.get("pool", "self_hosted")

        nodes.append({
            "id": host,
            "label": host.split(".")[0] if "." in host else host,
            "type": "domain",
            "pqc_status": status,
            "display_tier": _status_to_display_tier(status),
            "ip_address": ip,
            "cloud_provider": cloud_provider,
            "pool": pool,
            "is_cloud_hosted": cloud_info.get("is_cloud", False),
        })
        domain_nodes.append(host)

        if ip:
            ip_id = f"ip-{ip}"
            if ip_id not in ip_nodes:
                # Add pool group node if not already added
                pool_id = f"pool-{pool}"
                if pool_id not in pool_nodes_added:
                    pool_label = "Cloud-Hosted" if pool == "cloud" else "Self-Hosted"
                    nodes.append({
                        "id": pool_id,
                        "label": pool_label,
                        "type": "pool",
                        "pqc_status": "UNKNOWN",
                        "display_tier": "Pool",
                        "ip_address": "",
                        "cloud_provider": pool,
                        "pool": pool,
                        "is_cloud_hosted": pool == "cloud",
                    })
                    pool_nodes_added.add(pool_id)

                nodes.append({
                    "id": ip_id,
                    "label": ip,
                    "type": "ip",
                    "pqc_status": status,
                    "display_tier": _status_to_display_tier(status),
                    "ip_address": ip,
                    "cloud_provider": cloud_provider,
                    "cloud_display_name": cloud_info.get("display_name", ""),
                    "pool": pool,
                    "is_cloud_hosted": cloud_info.get("is_cloud", False),
                })
                ip_nodes.add(ip_id)
                # Connect IP to its pool node
                edges.append({"source": ip_id, "target": pool_id})

            edges.append({"source": host, "target": ip_id})

    for idx in range(len(domain_nodes) - 1):
        edges.append({"source": domain_nodes[idx], "target": domain_nodes[idx + 1]})

    return {"nodes": nodes, "edges": edges}


async def _derive_asset_discovery_payload(pipeline_result: dict[str, Any]) -> dict[str, Any]:
    demo_mode = pipeline_result.get("mode") == "demo"
    if demo_mode:
        return {
            "domains": get_demo_domain_assets(),
            "ssl": get_demo_ssl_assets(),
            "ip": get_demo_ip_assets(),
            "software": get_demo_software_assets(),
            "network_graph": get_demo_network_graph(),
        }
    # Live mode: run cloud detection, share results between ip assets and graph
    ip_records = await _live_ip_assets(pipeline_result)
    ip_cloud_map = {
        r["ip_address"]: {
            "provider": r["cloud_provider"],
            "display_name": r["cloud_display_name"],
            "is_cloud": r["is_cloud_hosted"],
            "pool": r["pool"],
        }
        for r in ip_records if r.get("ip_address")
    }
    return {
        "domains": _live_domain_assets(pipeline_result),
        "ssl": _live_ssl_assets(pipeline_result),
        "ip": ip_records,
        "software": _live_software_assets(pipeline_result),
        "network_graph": _live_network_graph(pipeline_result, ip_cloud_map=ip_cloud_map),
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
        and _latest_pipeline_result.get("cbom")  # skip shallow cache-from-scan stubs
    ):
        return _latest_pipeline_result

    if (
        requested_mode == "live"
        and not force_refresh
        and _latest_scan
        and _latest_scan.total_assets > 0
    ):
        _cache_pipeline_from_scan_summary(_latest_scan, mode="live", domain=requested_domain or "")
        return _latest_pipeline_result

    pipeline_kwargs: dict[str, Any] = {"mode": requested_mode, "domain": requested_domain}
    if requested_mode == "live":
        scan_opts = _live_scan_options()
        pipeline_kwargs.update({
            "limit": scan_opts["limit"],
            "include_port_scan": scan_opts["include_port_scan"],
            "include_api_crawl": scan_opts["include_api_crawl"],
        })

    result = await run_pipeline(**pipeline_kwargs)
    _latest_pipeline_result = result.model_dump(mode="json")
    _latest_pipeline_context = {"mode": requested_mode, "domain": requested_domain}
    return _latest_pipeline_result


def _compute_home_summary(pipeline_result: dict[str, Any]) -> dict[str, Any]:
    """Assemble the home dashboard summary payload from real scanned asset data."""
    assets = pipeline_result.get("assets", [])
    enterprise = pipeline_result.get("enterprise_cyber_rating", {})
    cbom = pipeline_result.get("cbom", {})
    demo_mode = pipeline_result.get("mode") == "demo"

    total_assets = len(assets)
    fully_safe = sum(1 for a in assets if a.get("status") == "FULLY_QUANTUM_SAFE")
    transition = sum(1 for a in assets if a.get("status") == "PQC_TRANSITION")

    # Real counts derived from actual scanned assets — same logic for demo and live
    hostnames = {a.get("hostname", "") for a in assets if a.get("hostname")}
    ips = {
        a.get("ip_address", "") for a in assets
        if a.get("ip_address") and a.get("ip_address") not in ("", "N/A", "Unknown")
    }
    cloud_count = sum(1 for a in assets if a.get("is_cloud_hosted"))
    ssl_count = sum(1 for a in assets if a.get("tls_version") or a.get("cert_fingerprint") or a.get("certificate_serial"))
    subdomain_count = sum(1 for h in hostnames if h.count(".") >= 2)

    components = cbom.get("components", [])
    vulnerabilities = cbom.get("vulnerabilities", [])

    domain_count = len(hostnames)
    ip_count = len(ips)
    cloud_asset_count = cloud_count
    ssl_cert_count = ssl_count if ssl_count else domain_count
    software_count = len(components)
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
            "iot_device_count": 0,
            "login_form_count": 0,
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


async def _build_report_section(report_type: str, pipeline_result: dict[str, Any]) -> dict[str, Any]:
    """Build a report section for the reporting API."""
    home_summary = _compute_home_summary(pipeline_result)
    assets_payload = await _derive_asset_discovery_payload(pipeline_result)

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
async def serve_landing():
    """Serve the Q-ARMOR landing page."""
    index_file = FRONTEND_DIR / "index.html"
    if not index_file.exists():
        raise HTTPException(status_code=404, detail="Landing page not found")
    return HTMLResponse(content=index_file.read_text())


@app.get("/auth", response_class=HTMLResponse)
async def serve_auth():
    """Serve the authentication page."""
    auth_file = FRONTEND_DIR / "auth.html"
    if not auth_file.exists():
        raise HTTPException(status_code=404, detail="Authentication page not found")
    return HTMLResponse(content=auth_file.read_text())


@app.get("/dashboard", response_class=HTMLResponse)
async def serve_dashboard():
    """Serve the Q-ARMOR dashboard."""
    dashboard_file = FRONTEND_DIR / "dashboard.html"
    if not dashboard_file.exists():
        raise HTTPException(status_code=404, detail="Dashboard not found")
    return HTMLResponse(content=dashboard_file.read_text())


@app.get("/api/health")
async def health_check():
    """Health check endpoint."""
    return {"status": "operational", "service": "Q-ARMOR", "version": "9.0.0"}


@app.get("/api/auth/me")
async def auth_me(request: Request):
    """Return the current authenticated user and their profile role."""
    return JSONResponse(content=get_user_context(request))


@app.get("/api/auth/config")
async def auth_config():
    """Return the public frontend auth configuration for this deployment."""
    return JSONResponse(content=get_public_auth_config())


@app.get("/api/auth/admin-check")
async def auth_admin_check(request: Request, user: dict[str, Any] = Depends(require_admin)):
    """Validate that the current user is an admin."""
    context = get_user_context(request)
    return JSONResponse(content={
        "ok": True,
        "user_id": user.get("sub"),
        "email": context.get("email"),
        "role": context.get("role"),
    })


@app.get("/api/scan/demo")
async def run_demo_scan(request: Request):
    """Run a demo scan with simulated bank assets."""
    global _latest_scan
    _latest_scan = generate_demo_results()
    summary = json.loads(_latest_scan.model_dump_json())
    history_scan_id = _save_user_scan_history(
        request,
        list(summary.get("results", [])),
        mode="demo",
        domain="",
        details=summary,
    )
    if history_scan_id:
        summary["scan_id"] = history_scan_id
    _cache_pipeline_from_scan_summary(_latest_scan, mode="demo", domain="")
    if history_scan_id:
        _latest_scan = ScanSummary.model_validate(summary)
    # Warm the enterprise pipeline cache so /api/assets/* serve real data immediately
    try:
        await _ensure_latest_pipeline_result(mode="demo", force_refresh=True)
    except Exception as _exc:
        logger.warning("Demo pipeline warm-up failed: %s", _exc)
    return _latest_scan.model_dump(mode="json")


@app.post("/api/scan/domain/{domain}")
async def scan_domain(domain: str, request: Request, full_scan: bool = False):
    """Scan a real domain for cryptographic configuration."""
    global _latest_scan, _latest_trimode
    import asyncio

    try:
        domain, _ = _normalize_hostname_input(domain, allow_port=False)
        scan_opts = _live_scan_options()
        if full_scan:
            scan_opts["include_port_scan"] = True
            scan_opts["include_api_crawl"] = True

        # Discovery with timeout — CT logs can be slow
        try:
            assets = await asyncio.wait_for(
                discover_assets(
                    domain,
                    include_ct=scan_opts["include_ct"],
                    include_port_scan=scan_opts["include_port_scan"],
                    include_api_crawl=scan_opts["include_api_crawl"],
                ),
                timeout=90.0 if (LOCAL_FULL_SCAN or full_scan) else 60.0,
            )
        except asyncio.TimeoutError:
            # Fall back to DNS-only if CT takes too long
            logger.warning("CT log timeout for %s, falling back to DNS-only", domain)
            try:
                assets = await asyncio.wait_for(
                    discover_assets(
                        domain,
                        include_ct=False,
                        include_port_scan=scan_opts["include_port_scan"],
                        include_api_crawl=scan_opts["include_api_crawl"],
                    ),
                    timeout=45.0 if (LOCAL_FULL_SCAN or full_scan) else 30.0,
                )
            except asyncio.TimeoutError:
                logger.warning("Extended discovery timeout for %s, falling back to DNS-only root scan", domain)
                assets = await asyncio.wait_for(
                    discover_assets(
                        domain,
                        include_ct=False,
                        include_port_scan=False,
                        include_api_crawl=False,
                    ),
                    timeout=20.0,
                )

        if not assets:
            raise HTTPException(status_code=404, detail=f"No assets discovered for {domain}")

        logger.info("Discovery complete for %s: %d assets found", domain, len(assets))
        live_assets = _select_live_assets(assets, scan_opts["limit"])
        logger.info("Starting probe of %d assets (concurrency=10)", len(live_assets))
        t0_probe = time.monotonic()
        fingerprints = await asyncio.wait_for(
            probe_batch(live_assets, concurrency=10, demo=False),
            timeout=900.0,
        )
        logger.info("Probe complete: %d fingerprints in %.1fs", len(fingerprints), time.monotonic() - t0_probe)
        _latest_trimode = fingerprints
        _latest_scan = _build_legacy_scan_summary_from_fingerprints(fingerprints)
        summary = json.loads(_latest_scan.model_dump_json())
        history_scan_id = _save_user_scan_history(
            request,
            list(summary.get("results", [])),
            mode="live",
            domain=domain,
            details=summary,
        )
        if history_scan_id:
            summary["scan_id"] = history_scan_id
            _latest_scan = ScanSummary.model_validate(summary)
        _cache_pipeline_from_scan_summary(_latest_scan, mode="live", domain=domain)
        # Warm the full enterprise pipeline cache so /api/assets/* serve real data
        try:
            await _ensure_latest_pipeline_result(mode="live", domain=domain, force_refresh=True)
        except Exception as _exc:
            logger.warning("Live pipeline warm-up failed for %s: %s", domain, _exc)
        return _latest_scan.model_dump(mode="json")

    except HTTPException:
        raise
    except Exception as e:
        logger.exception("Domain scan failed for %s", domain)
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/scan/stream/{domain}")
async def scan_stream(domain: str, request: Request, full_scan: bool = False):
    """SSE endpoint: streams per-asset scan progress so the browser can show live updates."""

    async def generate():
        global _latest_scan, _latest_trimode

        try:
            domain_clean, _ = _normalize_hostname_input(domain, allow_port=False)
        except Exception as exc:
            yield f'data: {json.dumps({"type": "error", "message": str(exc)})}\n\n'
            return

        scan_opts = _live_scan_options()
        if full_scan:
            scan_opts["include_port_scan"] = True
            scan_opts["include_api_crawl"] = True

        # Phase 1 — Discovery
        yield f'data: {json.dumps({"type": "status", "phase": "discovery", "message": f"Discovering assets for {domain_clean}...", "pct": 3})}\n\n'

        try:
            try:
                assets = await asyncio.wait_for(
                    discover_assets(
                        domain_clean,
                        include_ct=scan_opts["include_ct"],
                        include_port_scan=scan_opts["include_port_scan"],
                        include_api_crawl=scan_opts.get("include_api_crawl", False),
                    ),
                    timeout=60.0,
                )
            except asyncio.TimeoutError:
                logger.warning("CT log timeout for %s in stream, falling back to DNS-only", domain_clean)
                assets = await asyncio.wait_for(
                    discover_assets(domain_clean, include_ct=False, include_port_scan=False),
                    timeout=20.0,
                )

            if not assets:
                yield f'data: {json.dumps({"type": "error", "message": f"No assets discovered for {domain_clean}"})}\n\n'
                return

            live_assets = _select_live_assets(assets, scan_opts["limit"])
            total = len(live_assets)
            yield f'data: {json.dumps({"type": "discovered", "count": total, "assets": [a.hostname for a in live_assets], "pct": 15})}\n\n'

            # Phase 2 — Parallel probing with per-asset progress via asyncio.Queue
            fingerprints: list = [None] * total
            q: asyncio.Queue = asyncio.Queue()
            sem = asyncio.Semaphore(10)

            async def _probe_and_report(idx: int, asset) -> None:
                async with sem:
                    try:
                        fp = await probe_trimode(
                            hostname=asset.hostname,
                            port=asset.port,
                            asset_type=asset.asset_type,
                            ip=asset.ip,
                        )
                    except Exception as exc:
                        fp = TriModeFingerprint(
                            hostname=asset.hostname,
                            port=asset.port,
                            asset_type=asset.asset_type,
                            ip=asset.ip,
                            error=str(exc),
                            mode="live",
                        )
                    fingerprints[idx] = fp
                    await q.put((idx, asset, fp))

            tasks = [asyncio.create_task(_probe_and_report(i, a)) for i, a in enumerate(live_assets)]

            done_count = 0
            while done_count < total:
                _, asset, fp = await q.get()
                done_count += 1
                try:
                    classified = classify_trimode(fp)
                    status_val = classified.status.value if not fp.error else "ERROR"
                except Exception:
                    status_val = "UNKNOWN"
                pct = 15 + int(done_count / total * 77)  # 15 → 92
                yield f'data: {json.dumps({"type": "asset_scanned", "asset": fp.hostname, "port": fp.port, "done": done_count, "total": total, "pct": pct, "status": status_val})}\n\n'

            await asyncio.gather(*tasks, return_exceptions=True)

            # Phase 3 — Classify + build summary
            yield f'data: {json.dumps({"type": "status", "phase": "classifying", "message": "Building assessment...", "pct": 95})}\n\n'

            summary_obj = _build_legacy_scan_summary_from_fingerprints(fingerprints)
            _latest_scan = summary_obj
            _latest_trimode = fingerprints
            summary = json.loads(summary_obj.model_dump_json())

            history_id = _save_user_scan_history(
                request,
                list(summary.get("results", [])),
                mode="live",
                domain=domain_clean,
                details=summary,
            )
            if history_id:
                summary["scan_id"] = history_id
                _latest_scan = ScanSummary.model_validate(summary)

            _cache_pipeline_from_scan_summary(_latest_scan, mode="live", domain=domain_clean)
            asyncio.create_task(
                _ensure_latest_pipeline_result(mode="live", domain=domain_clean, force_refresh=True)
            )

            yield f'data: {json.dumps({"type": "complete", "data": summary, "pct": 100})}\n\n'

        except Exception as exc:
            logger.exception("Streaming scan failed for %s", domain)
            yield f'data: {json.dumps({"type": "error", "message": str(exc)})}\n\n'

    return StreamingResponse(
        generate(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "X-Accel-Buffering": "no",
            "Connection": "keep-alive",
        },
    )


@app.get("/api/scan/single/{hostname}")
async def scan_single(hostname: str, port: int = 443):
    """Scan a single hostname:port for cryptographic configuration."""
    try:
        hostname, embedded_port = _normalize_hostname_input(hostname, allow_port=True)
        if embedded_port:
            port = embedded_port
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
async def get_assessment(mode: str | None = None, domain: str | None = None, refresh: bool = False):
    """Run Phase 2 PQC assessment on the latest scan data."""
    if mode is not None or domain or refresh:
        requested_mode = _normalize_pipeline_mode(mode)
        requested_domain = ""
        if requested_mode == "live":
            requested_domain = _normalize_hostname_input(domain or (_latest_pipeline_context.get("domain") or ""), allow_port=False)[0]
        pipeline_result = await _ensure_latest_pipeline_result(
            mode=requested_mode,
            domain=requested_domain or None,
            force_refresh=refresh,
        )
        return JSONResponse(content=_build_pipeline_assessment_batch(list(pipeline_result.get("assets", []))))

    if not _latest_scan:
        if _latest_pipeline_result:
            return JSONResponse(content=_build_pipeline_assessment_batch(list(_latest_pipeline_result.get("assets", []))))
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
async def get_remediation_plan(mode: str | None = None, domain: str | None = None, refresh: bool = False):
    """Get the full Phase 2 remediation plan for the latest scan."""
    if mode is not None or domain or refresh:
        requested_mode = _normalize_pipeline_mode(mode)
        requested_domain = ""
        if requested_mode == "live":
            requested_domain = _normalize_hostname_input(domain or (_latest_pipeline_context.get("domain") or ""), allow_port=False)[0]
        pipeline_result = await _ensure_latest_pipeline_result(
            mode=requested_mode,
            domain=requested_domain or None,
            force_refresh=refresh,
        )
        batch = _build_pipeline_assessment_batch(list(pipeline_result.get("assets", [])))
        rems = generate_batch_remediation(batch)
        return JSONResponse(content=rems)

    if not _latest_scan:
        if _latest_pipeline_result:
            batch = _build_pipeline_assessment_batch(list(_latest_pipeline_result.get("assets", [])))
            rems = generate_batch_remediation(batch)
            return JSONResponse(content=rems)
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
        scan_opts = _live_scan_options()
        assets = await discover_assets(
            domain,
            demo=False,
            include_ct=True,
            include_port_scan=scan_opts["include_port_scan"],
            include_api_crawl=scan_opts["include_api_crawl"],
        )
        if not assets:
            raise HTTPException(status_code=404, detail=f"No assets discovered for {domain}")

        fingerprints = await probe_batch(_select_live_assets(assets, scan_opts["limit"]), concurrency=3, demo=False)
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
async def classify_demo(request: Request):
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
    history_scan_id = _save_user_scan_history(
        request,
        classified,
        mode="demo",
        domain="bank.com",
        details={
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
        },
    )

    return JSONResponse(content={
        "mode": "demo",
        "scan_id": history_scan_id or scan_id,
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
async def classify_live(domain: str, request: Request):
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

        fingerprints = await probe_batch(assets[:10], concurrency=3, demo=False)

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
        history_scan_id = _save_user_scan_history(
            request,
            classified,
            mode="live",
            domain=domain,
            details={
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
            },
        )

        return JSONResponse(content={
            "mode": "live",
            "domain": domain,
            "scan_id": history_scan_id or scan_id,
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


# ── Domains Endpoint ─────────────────────────────────────────────────────────

@app.get("/api/domains")
async def list_scanned_domains(request: Request):
    """Return unique non-empty domains from scan history, newest first."""
    seen: set[str] = set()
    domains: list[str] = []

    history_scans = _history_scans_for_request(request, limit=0)
    source = history_scans if history_scans else db.list_scans(limit=0)
    for scan in source:
        d = (scan.get("domain") or "").strip()
        if d and d not in seen:
            seen.add(d)
            domains.append(d)

    # Also include unique hostnames from single-host probes
    try:
        with db._connect() as conn:
            rows = conn.execute(
                "SELECT DISTINCT hostname FROM asset_scores ORDER BY id DESC"
            ).fetchall()
            for row in rows:
                h = (row["hostname"] or "").strip()
                if h and h not in seen:
                    seen.add(h)
                    domains.append(h)
    except Exception:
        pass

    return JSONResponse(content={"domains": domains})


# ── Phase 7: Database Endpoints ──────────────────────────────────────────────

@app.get("/api/db/scans")
async def db_list_scans(request: Request, limit: int = 0):
    """List recent scans from the database."""
    history_scans = _history_scans_for_request(request, limit)
    if history_scans:
        return JSONResponse(content=history_scans)
    return JSONResponse(content=db.list_scans(limit))


@app.get("/api/scans")
@app.get("/scans")
async def api_list_scans(request: Request, limit: int = 0):
    """Return recent scans for scan selection and comparison."""
    get_current_user(request)
    history_scans = _history_scans_for_request(request, limit)
    if history_scans:
        return JSONResponse(content=[
            {
                "id": scan.get("id"),
                "created_at": scan.get("scan_date"),
                "overall_score": scan.get("avg_score", 0),
                "mode": scan.get("mode", "live"),
                "domain": scan.get("domain", ""),
                "total_assets": scan.get("total_assets", 0),
            }
            for scan in history_scans
        ])

    sqlite_scans = db.list_scans(limit)
    return JSONResponse(content=[
        {
            "id": scan.get("id"),
            "created_at": scan.get("scan_date"),
            "overall_score": scan.get("avg_score", 0),
            "mode": scan.get("mode", "live"),
            "domain": scan.get("domain", ""),
            "total_assets": scan.get("total_assets", 0),
        }
        for scan in sqlite_scans
    ])


@app.get("/api/db/scans/{scan_id}")
async def db_get_scan(scan_id: str, request: Request):
    """Load a specific scan by ID."""
    history_scan = _history_scan_for_request(request, scan_id)
    if history_scan:
        return JSONResponse(content=history_scan)
    try:
        sqlite_scan_id = int(scan_id)
    except (TypeError, ValueError):
        sqlite_scan_id = None
    scan = db.load_scan(sqlite_scan_id) if sqlite_scan_id is not None else None
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    return JSONResponse(content=scan)


@app.get("/api/db/scans/latest")
async def db_latest_scan(request: Request):
    """Load the most recent scan."""
    history_scan = _history_latest_scan_for_request(request)
    if history_scan:
        return JSONResponse(content=history_scan)
    scan = db.load_latest_scan()
    if not scan:
        raise HTTPException(status_code=404, detail="No scans in database")
    return JSONResponse(content=scan)


@app.get("/api/scan/latest")
async def api_scan_latest(request: Request, mode: str | None = None, domain: str | None = None, refresh: bool = False):
    """Return the latest stored scan with parsed asset data."""
    if mode is not None or domain or refresh:
        requested_mode = _normalize_pipeline_mode(mode)
        requested_domain = ""
        if requested_mode == "live":
            requested_domain = _normalize_hostname_input(domain or (_latest_pipeline_context.get("domain") or ""), allow_port=False)[0]
        pipeline_result = await _ensure_latest_pipeline_result(
            mode=requested_mode,
            domain=requested_domain or None,
            force_refresh=refresh,
        )
        return JSONResponse(content=_latest_scan_payload_from_assets(
            list(pipeline_result.get("assets", [])),
            scan_id=pipeline_result.get("scan_id"),
            mode=pipeline_result.get("mode", requested_mode),
            domain=requested_domain or "",
        ))

    if _latest_scan:
        summary = json.loads(_latest_scan.model_dump_json())
        raw_results = summary.get("results", []) if isinstance(summary.get("results"), list) else []
        assets = [_normalize_asset(a) for a in raw_results]
        payload = _latest_scan_payload_from_assets(
            assets,
            scan_id=summary.get("scan_id"),
            mode=summary.get("mode", "live"),
            domain=summary.get("domain", ""),
        )
        return JSONResponse(content={
            **summary,
            **payload,
            "results": assets,
            "assets": assets,
            "asset_scores": assets,
        })

    history_scan = _history_latest_scan_for_request(request)
    if history_scan:
        assets = _parse_scan_results(history_scan)
        payload = _latest_scan_payload_from_assets(
            assets,
            scan_id=history_scan.get("id"),
            mode=history_scan.get("mode", "live"),
            domain=history_scan.get("domain", ""),
        )
        payload["average_q_score"] = history_scan.get("avg_score", payload["average_q_score"])
        return JSONResponse(content={**history_scan, **payload})

    latest_scan = db.load_latest_scan()
    if latest_scan:
        assets = _parse_scan_results(latest_scan)
        payload = _latest_scan_payload_from_assets(
            assets,
            scan_id=latest_scan.get("id"),
            mode=latest_scan.get("mode", "demo"),
            domain=latest_scan.get("domain", ""),
        )
        payload["average_q_score"] = latest_scan.get("avg_score", payload["average_q_score"])
        return JSONResponse(content={**latest_scan, **payload})

    if _latest_pipeline_result:
        assets = [_normalize_asset(a) for a in _latest_pipeline_result.get("assets", [])]
        return JSONResponse(content=_latest_scan_payload_from_assets(
            assets,
            scan_id=_latest_pipeline_result.get("scan_id"),
            mode=_latest_pipeline_result.get("mode", "demo"),
            domain=_latest_pipeline_context.get("domain", ""),
        ))

    raise HTTPException(status_code=404, detail="No scan data available")


@app.get("/api/history")
async def api_history(request: Request, limit: int = 0):
    """Return recent scans enriched with parsed assets for charting."""
    history_scans = _history_scans_for_request(request, limit)
    if history_scans:
        ordered = list(reversed(history_scans))
        detailed = []
        for scan in ordered:
            full_scan = _history_scan_for_request(request, str(scan["id"])) or scan
            assets = _parse_scan_results(full_scan)
            detailed.append({
                **full_scan,
                "assets": assets,
                "asset_scores": assets,
                "enterprise_score": int(round(float(full_scan.get("avg_score", 0) or 0) * 10)),
                "label": f"Scan #{full_scan.get('id', '?')}",
            })

        latest_mode = str(detailed[-1].get("mode", "live")).lower() if detailed else "live"
        demo_mode = latest_mode == "demo"
        return JSONResponse(content={
            "scans": detailed,
            "demo_mode": demo_mode,
            "data_notice": _data_notice(demo_mode),
        })

    scans = db.list_scans(limit)
    if scans:
        ordered = list(reversed(scans))
        detailed = []
        for scan in ordered:
            full_scan = db.load_scan(scan["id"]) or scan
            assets = _parse_scan_results(full_scan)
            detailed.append({
                **full_scan,
                "assets": assets,
                "asset_scores": assets,
                "enterprise_score": int(round(float(full_scan.get("avg_score", 0) or 0) * 10)),
                "label": f"Scan #{full_scan.get('id', '?')}",
            })

        latest_mode = str(detailed[-1].get("mode", "demo")).lower() if detailed else "demo"
        demo_mode = latest_mode == "demo"
        return JSONResponse(content={
            "scans": detailed,
            "demo_mode": demo_mode,
            "data_notice": _data_notice(demo_mode),
        })

    summaries = get_historical_scan_summaries()[-limit:]
    scans_payload = []
    for summary in summaries:
        payload = summary.model_dump(mode="json")
        scans_payload.append({
            **payload,
            "label": f"Week {payload.get('week', len(scans_payload) + 1)}",
            "enterprise_score": int(round(float(payload.get("quantum_safety_score", 0) or 0) * 10)),
            "assets": [],
            "asset_scores": [],
        })

    return JSONResponse(content={
        "scans": scans_payload,
        "demo_mode": True,
        "data_notice": _data_notice(True),
    })


@app.get("/api/compare/latest")
async def api_compare_latest(request: Request):
    """Compare the two most recent scans."""
    history_scans = _history_scans_for_request(request, limit=2)
    if len(history_scans) >= 2:
        latest = history_scans[0]
        previous = history_scans[1]
        result = _history_compare_for_request(request, str(previous["id"]), str(latest["id"])) or {}
        if "error" in result:
            raise HTTPException(status_code=404, detail=result["error"])
        demo_mode = str(latest.get("mode", "live")).lower() == "demo"
        return JSONResponse(content=_normalize_compare_payload(result, demo_mode=demo_mode))

    scans = db.list_scans(limit=2)
    if len(scans) < 2:
        raise HTTPException(status_code=404, detail="Need at least two scans to compare")

    latest = scans[0]
    previous = scans[1]
    result = db.compare_scans(previous["id"], latest["id"])
    if "error" in result:
        raise HTTPException(status_code=404, detail=result["error"])

    demo_mode = str(latest.get("mode", "demo")).lower() == "demo"
    return JSONResponse(content=_normalize_compare_payload(result, demo_mode=demo_mode))


@app.get("/compare")
@app.get("/api/compare")
async def api_compare(scan_a: str, scan_b: str, request: Request):
    """Compare any two stored scans."""
    get_current_user(request)
    history_result = _history_compare_for_request(request, scan_a, scan_b)
    if history_result:
        if "error" in history_result:
            raise HTTPException(status_code=404, detail=history_result["error"])
        demo_mode = str(history_result.get("scan_b", {}).get("mode", "live")).lower() == "demo"
        return JSONResponse(content=_normalize_compare_payload(history_result, demo_mode=demo_mode))

    try:
        sqlite_scan_a = int(scan_a)
        sqlite_scan_b = int(scan_b)
    except (TypeError, ValueError):
        raise HTTPException(status_code=404, detail="Scan not found")

    result = db.compare_scans(sqlite_scan_a, sqlite_scan_b)
    if "error" in result:
        raise HTTPException(status_code=404, detail=result["error"])
    demo_mode = str(result.get("scan_b", {}).get("mode", "demo")).lower() == "demo"
    return JSONResponse(content=_normalize_compare_payload(result, demo_mode=demo_mode))


@app.get("/api/db/compare/{scan_a}/{scan_b}")
async def db_compare_scans(scan_a: str, scan_b: str, request: Request):
    """Compare two scans and return delta analysis."""
    history_result = _history_compare_for_request(request, scan_a, scan_b)
    if history_result:
        if "error" in history_result:
            raise HTTPException(status_code=404, detail=history_result["error"])
        return JSONResponse(content=history_result)
    try:
        sqlite_scan_a = int(scan_a)
        sqlite_scan_b = int(scan_b)
    except (TypeError, ValueError):
        raise HTTPException(status_code=404, detail="Scan not found")
    result = db.compare_scans(sqlite_scan_a, sqlite_scan_b)
    if "error" in result:
        raise HTTPException(status_code=404, detail=result["error"])
    return JSONResponse(content=_normalize_compare_payload(result))


@app.get("/api/db/asset/{hostname}/history")
async def db_asset_history(hostname: str, request: Request, limit: int = 10):
    """Get score history for a specific asset."""
    history = _history_asset_for_request(request, hostname, limit)
    if history:
        return JSONResponse(content=history)
    return JSONResponse(content=db.get_asset_history(hostname, limit))


@app.delete("/api/db/scans/{scan_id}")
async def db_delete_scan(scan_id: str, request: Request):
    """Delete a stored scan and its related asset rows."""
    user_id = _request_user_id(request)
    if user_id and scan_history.is_configured():
        deleted = scan_history.delete_scan(user_id, scan_id)
        if not deleted:
            raise HTTPException(status_code=404, detail="Scan not found")
        return JSONResponse(content={"status": "deleted", "scan_id": scan_id})

    try:
        sqlite_scan_id = int(scan_id)
    except (TypeError, ValueError):
        raise HTTPException(status_code=404, detail="Scan not found")

    scan = db.load_scan(sqlite_scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    with db._connect() as conn:
        conn.execute("DELETE FROM scans WHERE id=?", (sqlite_scan_id,))
    return JSONResponse(content={"status": "deleted", "scan_id": scan_id})


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
async def db_revoke_label(label_id: str, _: dict[str, Any] = Depends(require_admin)):
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
async def phase9_demo_pipeline(request: Request):
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
    await _populate_phase9_demo_cache()
    _save_user_scan_history(
        request,
        [a.model_dump(mode="json") for a in _latest_classified],
        mode="demo",
        domain="bank.com",
        details=_latest_phase9,
    )

    return JSONResponse(content=_latest_phase9)


@app.post("/api/phase9/live/{domain}")
async def phase9_live_pipeline(domain: str, request: Request):
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
        scan_opts = _live_scan_options()
        # Step 1: Discover assets
        try:
            assets = await asyncio.wait_for(
                discover_assets(
                    domain,
                    include_ct=True,
                    include_port_scan=scan_opts["include_port_scan"],
                    include_api_crawl=scan_opts["include_api_crawl"],
                ),
                timeout=30.0 if LOCAL_FULL_SCAN else 20.0,
            )
        except asyncio.TimeoutError:
            try:
                assets = await asyncio.wait_for(
                    discover_assets(
                        domain,
                        include_ct=False,
                        include_port_scan=scan_opts["include_port_scan"],
                        include_api_crawl=scan_opts["include_api_crawl"],
                    ),
                    timeout=15.0 if LOCAL_FULL_SCAN else 10.0,
                )
            except asyncio.TimeoutError:
                assets = await asyncio.wait_for(
                    discover_assets(
                        domain,
                        include_ct=False,
                        include_port_scan=False,
                        include_api_crawl=False,
                    ),
                    timeout=8.0,
                )
        if not assets:
            raise HTTPException(status_code=404, detail=f"No assets discovered for {domain}")

        # Step 2: Tri-mode probe
        fingerprints = await probe_batch(_select_live_assets(assets, scan_opts["limit"]), concurrency=3, demo=False)

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
        history_scan_id = _save_user_scan_history(
            request,
            classified_dicts,
            mode="live",
            domain=domain,
            details=_latest_phase9,
        )
        if history_scan_id:
            _latest_phase9["scan_id"] = history_scan_id

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


@app.post("/api/reports/save")
async def save_report(file: UploadFile):
    """Persist an exported report (CBOM/CDXA) to the data/reports directory."""
    reports_dir = Path("data/reports")
    reports_dir.mkdir(parents=True, exist_ok=True)
    safe_name = Path(file.filename or "report.json").name
    dest = reports_dir / safe_name
    dest.write_bytes(await file.read())
    return JSONResponse(content={"saved": str(dest)})


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
    assets_payload = await _derive_asset_discovery_payload(pipeline_result)
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
    assets_payload = await _derive_asset_discovery_payload(pipeline_result)
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
    assets_payload = await _derive_asset_discovery_payload(pipeline_result)
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
    assets_payload = await _derive_asset_discovery_payload(pipeline_result)
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
    assets_payload = await _derive_asset_discovery_payload(pipeline_result)
    graph = assets_payload["network_graph"]
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


@app.get("/api/cbom/latest")
async def api_cbom_latest(mode: str = "demo", domain: str | None = None):
    """Return the latest CBOM generated by the unified pipeline."""
    pipeline_result = await _ensure_latest_pipeline_result(mode=mode, domain=domain)
    demo_mode = pipeline_result.get("mode") == "demo"
    cbom = dict(pipeline_result.get("cbom", {}))
    if not cbom:
        if _latest_phase9.get("cbom"):
            cbom = dict(_latest_phase9.get("cbom", {}))
        elif _latest_classified:
            cbom = generate_cbom_v2(_latest_classified, regression=None, data_mode="demo" if demo_mode else "live")
        elif _latest_scan:
            cbom = generate_cbom(_latest_scan)
    cbom["demo_mode"] = demo_mode
    cbom["data_notice"] = _data_notice(demo_mode)
    return JSONResponse(content=cbom)


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


@app.get("/api/dashboard/init")
async def api_dashboard_init(mode: str = "demo", domain: str | None = None, refresh: bool = False):
    """Combined endpoint: returns all dashboard data in a single response (9 calls → 1)."""
    pipeline_result = await _ensure_latest_pipeline_result(mode=mode, domain=domain, force_refresh=refresh)
    demo_mode = pipeline_result.get("mode") == "demo"
    notice = _data_notice(demo_mode)

    assets_payload = await _derive_asset_discovery_payload(pipeline_result)

    rating = dict(pipeline_result.get("enterprise_cyber_rating", {}))
    rating["tier_criteria"] = TIER_CRITERIA
    rating["demo_mode"] = demo_mode
    rating["data_notice"] = notice

    heatmap = dict(pipeline_result.get("heatmap", {}))
    heatmap["demo_mode"] = demo_mode
    heatmap["data_notice"] = notice

    graph = assets_payload["network_graph"]
    graph["demo_mode"] = demo_mode
    graph["data_notice"] = notice

    def _wrap(items):
        return {"items": items, "demo_mode": demo_mode, "data_notice": notice}

    return JSONResponse(content={
        "home": _compute_home_summary(pipeline_result),
        "domains": _wrap(assets_payload["domains"]),
        "ssl": _wrap(assets_payload["ssl"]),
        "ip": _wrap(assets_payload["ip"]),
        "software": _wrap(assets_payload["software"]),
        "graph": graph,
        "cyber": rating,
        "heatmap": heatmap,
        "negotiation": {
            "policies": pipeline_result.get("negotiation_policies", {}),
            "demo_mode": demo_mode,
            "data_notice": notice,
        },
    })


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
    report_data = await _build_report_section(report_type, pipeline_result)

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
