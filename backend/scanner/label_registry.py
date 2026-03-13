"""Phase 9 — Label Registry: Append-Only Label Log with Auto-Revoke.

Operations
──────────
  append  (ISSUED)  — persist a PQCLabelV9 to the labels table
  revoke  (REVOKED) — mark a label as revoked with a reason
  verify  (VALID / REVOKED / EXPIRED) — check label status
  list    (filtered) — list all labels with optional filters

Auto-Revoke on Scan
────────────────────
  After classification, the registry auto-revokes labels when:
    1. worst_case_score dropped ≥ 5 from previous → reason: ALGORITHM_REGRESSION
    2. Certificate expired → reason: CERTIFICATE_EXPIRY

FastAPI Router
──────────────
  GET  /api/registry/verify/{label_id}
  GET  /api/registry/list
  POST /api/registry/revoke
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Any

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

from backend.models import LabelSummary, PQCLabelV9
from backend.scanner import database as db

logger = logging.getLogger("qarmor.registry")

# ═══════════════════════════════════════════════════════════════════════════
# Registry operations
# ═══════════════════════════════════════════════════════════════════════════


def append_label(label: PQCLabelV9) -> bool:
    """Persist a newly issued label (ISSUED state) to the database."""
    return db.save_label(
        label_id=label.label_id,
        hostname=label.hostname,
        port=label.port,
        tier=label.tier,
        label_text=label.certification_title,
        issued_at=label.issued_at,
        valid_until=label.valid_until,
        reason=f"Issued: {label.certification_title}",
    )


def append_all_labels(summary: LabelSummary) -> int:
    """Persist all labels from a LabelSummary.  Returns count of saved labels."""
    saved = 0
    for label in summary.labels:
        if append_label(label):
            saved += 1
    return saved


def revoke_label(label_id: str, reason: str = "") -> bool:
    """Revoke a label by ID with an optional reason."""
    ok = db.revoke_label(label_id)
    if ok:
        logger.info("Label %s revoked: %s", label_id, reason)
    return ok


def verify_label(label_id: str) -> dict[str, Any]:
    """Verify a label's current status.

    Returns
    -------
    dict
        ``status``: VALID | REVOKED | EXPIRED | NOT_FOUND
        Plus full label details.
    """
    record = db.verify_label(label_id)
    if not record:
        return {"status": "NOT_FOUND", "label_id": label_id}

    if record.get("revoked"):
        return {
            "status": "REVOKED",
            "label_id": label_id,
            "revoked_at": record.get("revoked_at", ""),
            "details": record,
        }

    # Check expiry
    valid_until = record.get("valid_until", "")
    if valid_until:
        try:
            expiry = datetime.fromisoformat(valid_until.replace("Z", "+00:00"))
            if datetime.now(timezone.utc) > expiry:
                return {
                    "status": "EXPIRED",
                    "label_id": label_id,
                    "valid_until": valid_until,
                    "details": record,
                }
        except (ValueError, TypeError):
            pass

    return {
        "status": "VALID",
        "label_id": label_id,
        "tier": record.get("tier", 3),
        "hostname": record.get("hostname", ""),
        "valid_until": valid_until,
        "details": record,
    }


def list_labels(
    include_revoked: bool = False,
    tier: int | None = None,
    hostname: str | None = None,
) -> list[dict[str, Any]]:
    """List labels with optional filters."""
    all_labels = db.list_labels(include_revoked=include_revoked)

    if tier is not None:
        all_labels = [l for l in all_labels if l.get("tier") == tier]

    if hostname:
        all_labels = [l for l in all_labels if hostname.lower() in l.get("hostname", "").lower()]

    return all_labels


# ═══════════════════════════════════════════════════════════════════════════
# Auto-Revoke on Scan
# ═══════════════════════════════════════════════════════════════════════════

def auto_revoke_on_scan(
    current_assets: list[Any],
    previous_assets: list[Any] | None = None,
) -> list[dict[str, str]]:
    """Auto-revoke labels based on detected regressions.

    Checks:
      1. worst_case_score drop ≥ 5 → ALGORITHM_REGRESSION
      2. Certificate expired → CERTIFICATE_EXPIRY

    Accepts both Pydantic model objects and plain dicts.
    Returns list of {label_id, hostname, reason} for revoked labels.
    """
    def _to_dict(obj: Any) -> dict:
        if isinstance(obj, dict):
            return obj
        if hasattr(obj, "model_dump"):
            return obj.model_dump(mode="json")
        return dict(obj)

    revocations: list[dict[str, str]] = []

    # Build current asset map (normalise to dicts)
    curr_dicts = [_to_dict(a) for a in current_assets]
    current_map = {a.get("hostname", ""): a for a in curr_dicts if a.get("hostname")}

    # Build previous asset map
    prev_map: dict[str, dict] = {}
    if previous_assets:
        prev_dicts = [_to_dict(a) for a in previous_assets]
        prev_map = {a.get("hostname", ""): a for a in prev_dicts if a.get("hostname")}

    # Get active labels from DB
    active_labels = db.list_labels(include_revoked=False)

    for label_record in active_labels:
        hostname = label_record.get("hostname", "")
        label_id = label_record.get("label_id", "")

        if hostname not in current_map:
            continue  # Asset not in current scan → skip

        curr = current_map[hostname]

        # Check 1: Score regression
        if hostname in prev_map:
            prev = prev_map[hostname]
            curr_worst = curr.get("worst_case_score", curr.get("worst_score", 0))
            prev_worst = prev.get("worst_case_score", prev.get("worst_score", 0))
            drop = prev_worst - curr_worst
            if drop >= 5:
                if revoke_label(label_id, reason="ALGORITHM_REGRESSION"):
                    revocations.append({
                        "label_id": label_id,
                        "hostname": hostname,
                        "reason": f"ALGORITHM_REGRESSION: Q-Score dropped by {drop} points",
                    })
                    continue

        # Check 2: Certificate expiry
        cert = curr.get("certificate", {})
        if isinstance(cert, dict) and cert.get("is_expired"):
            if revoke_label(label_id, reason="CERTIFICATE_EXPIRY"):
                revocations.append({
                    "label_id": label_id,
                    "hostname": hostname,
                    "reason": "CERTIFICATE_EXPIRY: Asset certificate has expired",
                })

    if revocations:
        logger.info("Auto-revoked %d labels", len(revocations))

    return revocations


# ═══════════════════════════════════════════════════════════════════════════
# FastAPI Router
# ═══════════════════════════════════════════════════════════════════════════

registry_router = APIRouter(prefix="/api/registry", tags=["Label Registry"])


@registry_router.get("/verify/{label_id}")
async def api_verify_label(label_id: str):
    """Verify a PQC label by its ID."""
    result = verify_label(label_id)
    if result["status"] == "NOT_FOUND":
        raise HTTPException(status_code=404, detail=f"Label {label_id} not found")
    return result


@registry_router.get("/list")
async def api_list_labels(
    include_revoked: bool = False,
    tier: int | None = None,
    hostname: str | None = None,
):
    """List all labels with optional filters."""
    return list_labels(
        include_revoked=include_revoked,
        tier=tier,
        hostname=hostname,
    )


class RevokeRequest(BaseModel):
    label_id: str
    reason: str = ""


@registry_router.post("/revoke")
async def api_revoke_label(req: RevokeRequest):
    """Revoke a label by ID."""
    record = db.verify_label(req.label_id)
    if not record:
        raise HTTPException(status_code=404, detail=f"Label {req.label_id} not found")
    ok = revoke_label(req.label_id, reason=req.reason)
    if not ok:
        raise HTTPException(status_code=500, detail="Revocation failed")
    return {"status": "revoked", "label_id": req.label_id, "reason": req.reason}
