"""Phase 9 — CycloneDX Attestation v2 (CDXA) with LabelSummary + CBOM.

Generates machine-verifiable attestation documents that formalize NIST FIPS
203/204/205 compliance claims.  Built from:
  • Phase 9 LabelSummary (tier counts, quantum_safety_score, executive_summary)
  • Phase 8 CBOM v2 (CycloneDX 1.7)

Features
────────
  • Declarations with FIPS 203/204/205 compliance claims:
      COMPLIANT / PARTIALLY_COMPLIANT / NON_COMPLIANT
      based on Tier 1 + Tier 2 percentages
  • Ed25519 digital signing (auto-generate keypair at .keys/)
  • SHA-256 content hash of attestation body
  • 90-day validity window
  • Demo mode: ``data_mode: "demo"`` + note in declarations
  • FastAPI router: /api/attestation/generate, /download, /verify

All values derived from LabelSummary and CBOM — nothing hardcoded.
"""

from __future__ import annotations

import base64
import hashlib
import json
import logging
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization

from fastapi import APIRouter, HTTPException
from fastapi.responses import JSONResponse

from backend.models import LabelSummary

logger = logging.getLogger("qarmor.attestor")

# ── Constants ────────────────────────────────────────────────────────────────

ATTESTATION_SPEC = "CycloneDX Attestation"
ATTESTATION_SPEC_VERSION = "1.7"
ATTESTATION_VERSION = "2.0.0"
VALIDITY_DAYS = 90

NIST_FIPS_203 = {
    "id": "NIST-FIPS-203",
    "title": "Module-Lattice-Based Key-Encapsulation Mechanism Standard (ML-KEM)",
    "published": "2024-08-13",
    "url": "https://csrc.nist.gov/pubs/fips/203/final",
    "category": "Key Encapsulation",
}
NIST_FIPS_204 = {
    "id": "NIST-FIPS-204",
    "title": "Module-Lattice-Based Digital Signature Standard (ML-DSA)",
    "published": "2024-08-13",
    "url": "https://csrc.nist.gov/pubs/fips/204/final",
    "category": "Digital Signatures",
}
NIST_FIPS_205 = {
    "id": "NIST-FIPS-205",
    "title": "Stateless Hash-Based Digital Signature Standard (SLH-DSA)",
    "published": "2024-08-13",
    "url": "https://csrc.nist.gov/pubs/fips/205/final",
    "category": "Hash-Based Signatures",
}

KEYS_DIR = Path(__file__).resolve().parent.parent.parent / ".keys"
PRIVATE_KEY_PATH = KEYS_DIR / "signing_key.pem"
PUBLIC_KEY_PATH = KEYS_DIR / "signing_key.pub"


# ═══════════════════════════════════════════════════════════════════════════
# Key Management
# ═══════════════════════════════════════════════════════════════════════════

def _ensure_keypair() -> tuple[Ed25519PrivateKey, bytes]:
    """Load or auto-generate the Ed25519 signing keypair."""
    KEYS_DIR.mkdir(parents=True, exist_ok=True)

    # Also check old key paths for backward compat
    old_priv = KEYS_DIR / "attestor_ed25519.pem"
    old_pub = KEYS_DIR / "attestor_ed25519_pub.pem"

    for priv_path, pub_path in [(PRIVATE_KEY_PATH, PUBLIC_KEY_PATH), (old_priv, old_pub)]:
        if priv_path.exists():
            priv_pem = priv_path.read_bytes()
            private_key = serialization.load_pem_private_key(priv_pem, password=None)
            pub_pem = pub_path.read_bytes() if pub_path.exists() else private_key.public_key().public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo,
            )
            return private_key, pub_pem  # type: ignore[return-value]

    # Generate new
    private_key = Ed25519PrivateKey.generate()
    priv_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    pub_pem = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    PRIVATE_KEY_PATH.write_bytes(priv_pem)
    PUBLIC_KEY_PATH.write_bytes(pub_pem)
    logger.info("Generated new Ed25519 signing keypair at %s", KEYS_DIR)
    return private_key, pub_pem


def _sign_payload(private_key: Ed25519PrivateKey, payload: bytes) -> str:
    """Sign payload bytes with Ed25519 and return base64-encoded signature."""
    return base64.b64encode(private_key.sign(payload)).decode("ascii")


# ═══════════════════════════════════════════════════════════════════════════
# Compliance Claims Builder
# ═══════════════════════════════════════════════════════════════════════════

def _build_declarations(label_summary: LabelSummary) -> dict[str, Any]:
    """Build FIPS 203/204/205 compliance declarations from LabelSummary."""
    total = label_summary.total_assets
    t1 = label_summary.tier_1_count
    t2 = label_summary.tier_2_count
    t1_t2_pct = label_summary.tier_1_pct + label_summary.tier_2_pct

    # FIPS 203 (ML-KEM): Tier 1 + Tier 2 both use ML-KEM via KEX
    if t1_t2_pct >= 80:
        fips203_status = "COMPLIANT"
    elif t1_t2_pct >= 40:
        fips203_status = "PARTIALLY_COMPLIANT"
    else:
        fips203_status = "NON_COMPLIANT"

    # FIPS 204 (ML-DSA): Only Tier 1 uses PQC certificates
    t1_pct = label_summary.tier_1_pct
    if t1_pct >= 80:
        fips204_status = "COMPLIANT"
    elif t1_pct >= 20:
        fips204_status = "PARTIALLY_COMPLIANT"
    else:
        fips204_status = "NON_COMPLIANT"

    # FIPS 205 (SLH-DSA): Extra credit — check if any Tier 1 uses SLH-DSA
    has_slh_dsa = any(
        any("SLH-DSA" in std.upper() or "SLHDSA" in std.upper()
            for std in label.nist_standards)
        for label in label_summary.labels
        if label.tier == 1
    )
    fips205_status = "COMPLIANT" if has_slh_dsa else "NOT_APPLICABLE"

    declarations: dict[str, Any] = {
        "assessmentBasis": {
            "totalAssets": total,
            "tier1Assets": t1,
            "tier2Assets": t2,
            "tier3Assets": label_summary.tier_3_count,
            "quantumSafetyScore": label_summary.quantum_safety_score,
        },
        "claims": [
            {
                **NIST_FIPS_203,
                "complianceStatus": fips203_status,
                "coverage": f"{t1_t2_pct:.1f}%",
                "evidence": f"{t1 + t2}/{total} endpoints use ML-KEM key exchange (pure or hybrid)",
            },
            {
                **NIST_FIPS_204,
                "complianceStatus": fips204_status,
                "coverage": f"{t1_pct:.1f}%",
                "evidence": f"{t1}/{total} endpoints use ML-DSA certificate chain",
            },
            {
                **NIST_FIPS_205,
                "complianceStatus": fips205_status,
                "coverage": "N/A" if fips205_status == "NOT_APPLICABLE" else f"Detected in Tier 1",
                "evidence": "SLH-DSA detected in Tier 1 certificates" if has_slh_dsa
                           else "No SLH-DSA certificates detected",
            },
        ],
        "overallStatus": (
            "COMPLIANT" if fips203_status == "COMPLIANT" and fips204_status == "COMPLIANT"
            else "PARTIALLY_COMPLIANT" if fips203_status != "NON_COMPLIANT"
            else "NON_COMPLIANT"
        ),
    }

    if label_summary.data_mode == "demo":
        declarations["dataMode"] = "demo"
        declarations["note"] = "This attestation is based on simulated demo data and is not legally binding."

    return declarations


# ═══════════════════════════════════════════════════════════════════════════
# Attestation Generator
# ═══════════════════════════════════════════════════════════════════════════

def generate_attestation_v2(
    label_summary: LabelSummary,
    cbom: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Generate a signed CycloneDX Attestation (CDXA) document.

    Parameters
    ----------
    label_summary : LabelSummary
        Phase 9 label summary with tier counts and executive summary.
    cbom : dict | None
        Phase 8 CycloneDX 1.7 CBOM to link as evidence.

    Returns
    -------
    dict
        Complete CDXA document with digital signature.
    """
    private_key, pub_pem = _ensure_keypair()
    now = datetime.now(timezone.utc)

    # Declarations
    declarations = _build_declarations(label_summary)

    # CBOM evidence reference
    cbom_ref: dict[str, Any] = {}
    if cbom:
        cbom_hash = hashlib.sha256(
            json.dumps(cbom, sort_keys=True, default=str).encode()
        ).hexdigest()
        cbom_ref = {
            "type": "CycloneDX-CBOM",
            "specVersion": cbom.get("specVersion", "1.7"),
            "serialNumber": cbom.get("serialNumber", ""),
            "sha256": cbom_hash,
            "componentsCount": len(cbom.get("components", [])),
        }
    else:
        cbom_ref = {
            "type": "CycloneDX-CBOM",
            "note": "CBOM not provided — generate via /api/cbom/v2",
        }

    # Per-label claim details
    label_claims = []
    for label in label_summary.labels:
        claim = {
            "labelId": label.label_id,
            "hostname": label.hostname,
            "port": label.port,
            "tier": label.tier,
            "certificationTitle": label.certification_title,
            "badgeColor": label.badge_color,
            "nistStandards": label.nist_standards,
            "algorithmsInUse": label.algorithms_in_use,
            "isSimulated": label.is_simulated,
        }
        if label.primary_gap:
            claim["primaryGap"] = label.primary_gap
            claim["fixInDays"] = label.fix_in_days
        label_claims.append(claim)

    # Build attestation body
    attestation_body: dict[str, Any] = {
        "attestationFormat": ATTESTATION_SPEC,
        "specVersion": ATTESTATION_SPEC_VERSION,
        "version": ATTESTATION_VERSION,
        "serialNumber": f"urn:uuid:{uuid.uuid4()}",
        "timestamp": now.isoformat().replace("+00:00", "Z"),
        "validity": {
            "notBefore": now.isoformat().replace("+00:00", "Z"),
            "notAfter": (now + timedelta(days=VALIDITY_DAYS)).isoformat().replace("+00:00", "Z"),
            "renewalPolicy": f"Re-attest after each scan or within {VALIDITY_DAYS} days",
        },
        "attestor": {
            "name": "Q-ARMOR Attestation Engine",
            "version": "9.0.0",
            "organization": "Q-ARMOR Project — PNB Cybersecurity Hackathon 2025-26",
        },
        "subject": {
            "description": "PQC Compliance Attestation for scanned cryptographic endpoints",
            "totalAssets": label_summary.total_assets,
            "quantumSafetyScore": label_summary.quantum_safety_score,
            "executiveSummary": label_summary.executive_summary,
            "dataMode": label_summary.data_mode,
        },
        "declarations": declarations,
        "certificationSummary": {
            "tier1_fullyQuantumSafe": label_summary.tier_1_count,
            "tier1_pct": label_summary.tier_1_pct,
            "tier2_pqcReady": label_summary.tier_2_count,
            "tier2_pct": label_summary.tier_2_pct,
            "tier3_nonCompliant": label_summary.tier_3_count,
            "tier3_pct": label_summary.tier_3_pct,
        },
        "nistStandards": [NIST_FIPS_203, NIST_FIPS_204, NIST_FIPS_205],
        "labelClaims": label_claims,
        "evidence": {
            "cbom": cbom_ref,
            "classificationSource": "Q-ARMOR Phase 7 Tri-Mode Classifier",
            "labelingSource": "Q-ARMOR Phase 9 Certification Engine",
            "regressionSource": "Q-ARMOR Phase 8 Regression Detector",
        },
    }

    # Sign
    body_bytes = json.dumps(attestation_body, sort_keys=True, default=str).encode("utf-8")
    body_hash = hashlib.sha256(body_bytes).hexdigest()
    signature = _sign_payload(private_key, body_bytes)

    cdxa: dict[str, Any] = {
        "$schema": "https://cyclonedx.org/schema/ext/attestation-1.7.json",
        "attestation": attestation_body,
        "signature": {
            "algorithm": "Ed25519",
            "publicKey": pub_pem.decode("ascii"),
            "value": signature,
            "contentHash": {
                "algorithm": "SHA-256",
                "value": body_hash,
            },
        },
        "metadata": {
            "generator": "Q-ARMOR v9.0.0",
            "generatedAt": now.isoformat().replace("+00:00", "Z"),
            "format": "CDXA (CycloneDX Attestation)",
        },
    }

    return cdxa


# ═══════════════════════════════════════════════════════════════════════════
# Verification
# ═══════════════════════════════════════════════════════════════════════════

def verify_attestation(cdxa: dict[str, Any]) -> dict[str, Any]:
    """Verify the digital signature of a CDXA document."""
    try:
        sig_info = cdxa.get("signature", {})
        pub_pem = sig_info.get("publicKey", "").encode("ascii")
        sig_b64 = sig_info.get("value", "")
        body = cdxa.get("attestation", {})

        if not pub_pem or not sig_b64:
            return {"valid": False, "details": "Missing signature or public key"}

        from cryptography.hazmat.primitives.serialization import load_pem_public_key
        public_key = load_pem_public_key(pub_pem)

        body_bytes = json.dumps(body, sort_keys=True, default=str).encode("utf-8")
        sig_bytes = base64.b64decode(sig_b64)
        public_key.verify(sig_bytes, body_bytes)  # type: ignore[union-attr]

        body_hash = hashlib.sha256(body_bytes).hexdigest()
        expected_hash = sig_info.get("contentHash", {}).get("value", "")

        return {
            "valid": True,
            "signatureAlgorithm": sig_info.get("algorithm", "Ed25519"),
            "hashMatch": body_hash == expected_hash,
            "attestor": body.get("attestor", {}),
            "timestamp": body.get("timestamp", ""),
            "validity": body.get("validity", {}),
            "overallCompliance": body.get("declarations", {}).get("overallStatus", "UNKNOWN"),
            "quantumSafetyScore": body.get("subject", {}).get("quantumSafetyScore", 0),
        }

    except Exception as exc:
        return {"valid": False, "details": f"Signature verification failed: {exc}"}


def get_attestation_summary(cdxa: dict[str, Any]) -> dict[str, Any]:
    """Extract a human-readable summary from a CDXA document."""
    body = cdxa.get("attestation", {})
    declarations = body.get("declarations", {})
    cert_summary = body.get("certificationSummary", {})
    validity = body.get("validity", {})
    subject = body.get("subject", {})

    return {
        "serialNumber": body.get("serialNumber", ""),
        "timestamp": body.get("timestamp", ""),
        "overallCompliance": declarations.get("overallStatus", "UNKNOWN"),
        "quantumSafetyScore": subject.get("quantumSafetyScore", 0),
        "totalAssets": subject.get("totalAssets", 0),
        "executiveSummary": subject.get("executiveSummary", ""),
        "tier1": cert_summary.get("tier1_fullyQuantumSafe", 0),
        "tier2": cert_summary.get("tier2_pqcReady", 0),
        "tier3": cert_summary.get("tier3_nonCompliant", 0),
        "validUntil": validity.get("notAfter", ""),
        "signed": "signature" in cdxa,
        "dataMode": subject.get("dataMode", "live"),
    }


# ═══════════════════════════════════════════════════════════════════════════
# Legacy compat — keep old generate_attestation for Phases 1-5 endpoints
# ═══════════════════════════════════════════════════════════════════════════

def generate_attestation(
    assessment_results: list[dict[str, Any]],
    cbom_data: dict[str, Any] | None = None,
    output_file: str | None = None,
) -> dict[str, Any]:
    """Legacy CDXA from Phase 2 assessment dicts (backward compat)."""
    from backend.scanner.labeler import evaluate_and_label, summarize_labels

    private_key, pub_pem = _ensure_keypair()
    now = datetime.now(timezone.utc)

    labels = evaluate_and_label(assessment_results)
    label_summary = summarize_labels(labels)

    # Build compliance claims the old way
    claims = []
    for label in labels:
        tier = label.get("tier", 3)
        if tier == 1:
            status = "COMPLIANT"
        elif tier == 2:
            status = "PARTIAL"
        else:
            status = "NON_COMPLIANT"
        claims.append({
            "id": f"claim-{uuid.uuid4().hex[:12]}",
            "target": label.get("target", ""),
            "port": label.get("port", 443),
            "label": label.get("label", ""),
            "tier": tier,
            "compliance_status": status,
        })

    total = len(claims)
    compliant = sum(1 for c in claims if c["compliance_status"] == "COMPLIANT")
    partial = sum(1 for c in claims if c["compliance_status"] == "PARTIAL")
    non_compliant = sum(1 for c in claims if c["compliance_status"] == "NON_COMPLIANT")

    cbom_ref: dict[str, Any] = {}
    if cbom_data:
        cbom_hash = hashlib.sha256(json.dumps(cbom_data, sort_keys=True, default=str).encode()).hexdigest()
        cbom_ref = {"type": "CycloneDX-CBOM", "sha256": cbom_hash, "components_count": len(cbom_data.get("components", []))}
    else:
        cbom_ref = {"type": "CycloneDX-CBOM", "note": "CBOM not provided"}

    body: dict[str, Any] = {
        "attestationFormat": "CycloneDX Attestation",
        "specVersion": "1.6",
        "version": "1.0.0",
        "serialNumber": f"urn:uuid:{uuid.uuid4()}",
        "timestamp": now.isoformat(),
        "validity": {
            "notBefore": now.isoformat(),
            "notAfter": (now + timedelta(days=90)).isoformat(),
        },
        "attestor": {"name": "Q-ARMOR Attestation Engine", "version": "9.0.0"},
        "complianceSummary": {
            "totalEndpoints": total,
            "compliant": compliant,
            "partial": partial,
            "nonCompliant": non_compliant,
            "overallStatus": "COMPLIANT" if non_compliant == 0 and partial == 0 else "PARTIAL" if non_compliant == 0 else "NON_COMPLIANT",
        },
        "certificationLabels": {"fullyQuantumSafe": label_summary["fully_quantum_safe"], "pqcReady": label_summary["pqc_ready"], "nonCompliant": label_summary["non_compliant"]},
        "nistStandards": [NIST_FIPS_203, NIST_FIPS_204, NIST_FIPS_205],
        "claims": claims,
        "evidence": {"cbom": cbom_ref},
    }

    body_bytes = json.dumps(body, sort_keys=True, default=str).encode("utf-8")
    body_hash = hashlib.sha256(body_bytes).hexdigest()
    signature = _sign_payload(private_key, body_bytes)

    cdxa: dict[str, Any] = {
        "$schema": "https://cyclonedx.org/schema/ext/attestation-1.6.json",
        "attestation": body,
        "signature": {"algorithm": "Ed25519", "publicKey": pub_pem.decode("ascii"), "value": signature, "contentHash": {"algorithm": "SHA-256", "value": body_hash}},
        "metadata": {"generator": "Q-ARMOR v9.0.0", "generatedAt": now.isoformat(), "format": "CDXA"},
    }

    if output_file:
        out_path = Path(output_file)
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text(json.dumps(cdxa, indent=2, default=str), encoding="utf-8")

    return cdxa


# ═══════════════════════════════════════════════════════════════════════════
# FastAPI Router
# ═══════════════════════════════════════════════════════════════════════════

attestation_router = APIRouter(prefix="/api/attestation/v2", tags=["Attestation v2"])

# In-memory cache for latest attestation
_latest_cdxa: dict[str, Any] = {}
_latest_label_summary: LabelSummary | None = None


def set_latest_attestation_context(label_summary: LabelSummary, cbom: dict[str, Any] | None = None):
    """Called by app.py after a scan to cache the context for attestation."""
    global _latest_label_summary
    _latest_label_summary = label_summary


@attestation_router.get("/generate")
async def api_generate_attestation():
    """Generate a fresh CDXA from the latest scan's LabelSummary."""
    global _latest_cdxa
    if not _latest_label_summary:
        raise HTTPException(status_code=404, detail="No scan data. Run /api/classify/demo or /api/phase9/demo first.")
    _latest_cdxa = generate_attestation_v2(_latest_label_summary)
    return JSONResponse(content=_latest_cdxa)


@attestation_router.get("/download")
async def api_download_attestation():
    """Generate and download the CDXA as a JSON file."""
    if not _latest_label_summary:
        raise HTTPException(status_code=404, detail="No scan data.")
    cdxa = generate_attestation_v2(_latest_label_summary)
    return JSONResponse(
        content=cdxa,
        headers={"Content-Disposition": "attachment; filename=qarmor-attestation-cdxa-v2.json"},
    )


@attestation_router.get("/verify")
async def api_verify_attestation():
    """Generate a fresh attestation and verify its signature."""
    if not _latest_label_summary:
        raise HTTPException(status_code=404, detail="No scan data.")
    cdxa = generate_attestation_v2(_latest_label_summary)
    verification = verify_attestation(cdxa)
    return JSONResponse(content=verification)
