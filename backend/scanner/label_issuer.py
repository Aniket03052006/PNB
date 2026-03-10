"""Module 5: PQC Label Issuer — Verifiable credential labels for compliant assets."""

from __future__ import annotations
import uuid
from datetime import datetime, timedelta, timezone
from backend.models import PQCLabel, QScore, PQCStatus


def issue_label(hostname: str, port: int, q_score: QScore) -> PQCLabel | None:
    """Issue a PQC-Ready label if the asset meets compliance thresholds."""
    if q_score.status not in (PQCStatus.FULLY_QUANTUM_SAFE, PQCStatus.PQC_TRANSITION):
        return None

    now = datetime.now(timezone.utc)
    valid_months = 6 if q_score.status == PQCStatus.FULLY_QUANTUM_SAFE else 3

    algorithms = []
    standards = []

    if q_score.status == PQCStatus.FULLY_QUANTUM_SAFE:
        algorithms = ["ML-KEM-768", "ML-DSA-65"]
        standards = ["NIST FIPS 203", "NIST FIPS 204"]
    else:
        algorithms = ["X25519+ML-KEM-768 (Hybrid)"]
        standards = ["NIST FIPS 203 (Transition)"]

    label_id = f"QARMOR-{now.strftime('%Y')}-{uuid.uuid4().hex[:8].upper()}"

    return PQCLabel(
        label_id=label_id,
        asset=f"{hostname}:{port}",
        issued_at=now.strftime("%Y-%m-%d"),
        valid_until=(now + timedelta(days=valid_months * 30)).strftime("%Y-%m-%d"),
        algorithms=algorithms,
        standards=standards,
        status="ACTIVE",
    )
