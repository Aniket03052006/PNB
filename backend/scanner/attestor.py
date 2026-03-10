"""Module 10: CycloneDX Attestation (CDXA) Generator — Compliance-as-Code.

Generates machine-verifiable attestation documents that formalize NIST FIPS
203/204 compliance claims, digitally signed with a local private key and
linked to the CBOM as evidence.

CycloneDX Attestation Format (CDXA):
    - Attestation envelope with compliance claims
    - Digital signature using Ed25519 (Edwards-curve)
    - Evidence links to Phase 3 CBOM + Phase 4 labels
    - NIST FIPS 203 / FIPS 204 compliance mapping
"""

from __future__ import annotations

import base64
import hashlib
import json
import uuid
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import Any, Dict, List, Optional

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
)
from cryptography.hazmat.primitives import serialization

from backend.scanner.labeler import (
    LABEL_FULLY_QUANTUM_SAFE,
    LABEL_PQC_READY,
    LABEL_NON_COMPLIANT,
    TIER_FULLY_QUANTUM_SAFE,
    TIER_PQC_READY,
    TIER_NON_COMPLIANT,
    evaluate_and_label,
    summarize_labels,
)


# ── Constants ────────────────────────────────────────────────────────────────

ATTESTATION_VERSION = "1.0.0"
ATTESTATION_SPEC = "CycloneDX Attestation"
ATTESTATION_SPEC_VERSION = "1.6"

# NIST FIPS standards referenced
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

# Key file paths
KEYS_DIR = Path(__file__).parent.parent.parent / ".keys"
PRIVATE_KEY_PATH = KEYS_DIR / "attestor_ed25519.pem"
PUBLIC_KEY_PATH = KEYS_DIR / "attestor_ed25519_pub.pem"


# ── Key Management ───────────────────────────────────────────────────────────

def _ensure_keypair() -> tuple[Ed25519PrivateKey, bytes]:
    """Load or generate the Ed25519 signing keypair.

    Returns
    -------
    tuple
        (private_key, public_key_pem_bytes)
    """
    KEYS_DIR.mkdir(parents=True, exist_ok=True)

    if PRIVATE_KEY_PATH.exists():
        priv_pem = PRIVATE_KEY_PATH.read_bytes()
        private_key = serialization.load_pem_private_key(priv_pem, password=None)
        pub_pem = PUBLIC_KEY_PATH.read_bytes()
        return private_key, pub_pem  # type: ignore[return-value]

    # Generate new Ed25519 keypair
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

    return private_key, pub_pem


def _sign_payload(private_key: Ed25519PrivateKey, payload: bytes) -> str:
    """Sign payload bytes with Ed25519 and return base64-encoded signature."""
    signature = private_key.sign(payload)
    return base64.b64encode(signature).decode("ascii")


# ── Compliance Claims Builder ────────────────────────────────────────────────

def _build_compliance_claims(
    labels: List[Dict[str, Any]],
    assessment_results: List[Dict[str, Any]],
) -> List[Dict[str, Any]]:
    """Build per-endpoint NIST compliance claims from labels + assessments.

    An endpoint earns compliance claims if it has a PQC-relevant label:
      - Tier 1 (Fully Quantum Safe): FIPS 203 + FIPS 204 compliant
      - Tier 2 (PQC Ready): FIPS 203 partial (hybrid KEX)
      - Tier 3 (Non-Compliant): No compliance claim; gets a violation record
    """
    claims: List[Dict[str, Any]] = []

    # Build lookup: target:port → assessment
    assess_map: Dict[str, Dict] = {}
    for a in assessment_results:
        key = f"{a.get('target', 'unknown')}:{a.get('port', 443)}"
        assess_map[key] = a

    for label in labels:
        target = label.get("target", "unknown")
        port = label.get("port", 443)
        key = f"{target}:{port}"
        tier = label.get("tier", TIER_NON_COMPLIANT)
        assessment = assess_map.get(key, {})

        claim: Dict[str, Any] = {
            "id": f"claim-{uuid.uuid4().hex[:12]}",
            "target": target,
            "port": port,
            "label": label.get("label", LABEL_NON_COMPLIANT),
            "tier": tier,
            "tier_icon": label.get("tier_icon", ""),
            "key_exchange": label.get("key_exchange", ""),
            "certificate": label.get("certificate", ""),
            "tls_version": label.get("tls_version", ""),
            "q_score": label.get("q_score", 0),
            "hndl_vulnerable": assessment.get("hndl_vulnerable", True),
        }

        if tier == TIER_FULLY_QUANTUM_SAFE:
            claim["compliance_status"] = "COMPLIANT"
            claim["nist_standards"] = [
                {
                    **NIST_FIPS_203,
                    "compliance": "FULL",
                    "evidence": f"Pure PQC key exchange ({label.get('key_exchange', 'ML-KEM')})",
                },
                {
                    **NIST_FIPS_204,
                    "compliance": "FULL",
                    "evidence": f"PQC certificate chain ({label.get('certificate', 'ML-DSA')})",
                },
            ]
            claim["recommendation"] = "Maintain current PQC configuration. Monitor NIST updates."

        elif tier == TIER_PQC_READY:
            claim["compliance_status"] = "PARTIAL"
            claim["nist_standards"] = [
                {
                    **NIST_FIPS_203,
                    "compliance": "PARTIAL",
                    "evidence": f"Hybrid key exchange ({label.get('key_exchange', 'X25519+ML-KEM-768')})",
                },
                {
                    **NIST_FIPS_204,
                    "compliance": "PENDING",
                    "evidence": "Classical certificate chain — PQC certificate migration pending",
                },
            ]
            claim["recommendation"] = (
                "Migrate certificate chain to ML-DSA (FIPS 204) to achieve Fully Quantum Safe status."
            )

        else:  # Non-Compliant
            claim["compliance_status"] = "NON_COMPLIANT"
            claim["nist_standards"] = [
                {
                    **NIST_FIPS_203,
                    "compliance": "NONE",
                    "evidence": f"Classical key exchange ({label.get('key_exchange', 'RSA/ECDHE')})",
                },
                {
                    **NIST_FIPS_204,
                    "compliance": "NONE",
                    "evidence": f"Classical certificate ({label.get('certificate', 'RSA/ECDSA')})",
                },
            ]
            claim["recommendation"] = (
                "Urgent: Enable hybrid PQC key exchange (X25519+ML-KEM-768) and plan "
                "certificate migration to ML-DSA. See NIST SP 1800-38C for migration guidance."
            )

        claims.append(claim)

    return claims


# ── Attestation Generator ───────────────────────────────────────────────────

def generate_attestation(
    assessment_results: List[Dict[str, Any]],
    cbom_data: Optional[Dict[str, Any]] = None,
    output_file: Optional[str] = None,
) -> Dict[str, Any]:
    """Generate a signed CycloneDX Attestation (CDXA) document.

    Parameters
    ----------
    assessment_results : list[dict]
        Per-endpoint assessment dicts from ``analyze_batch()["assessments"]``.
    cbom_data : dict, optional
        Phase 3 CBOM JSON to link as evidence. If None, a reference placeholder
        is generated.
    output_file : str, optional
        If provided, write the attestation JSON to this file path.

    Returns
    -------
    dict
        The complete CDXA document with digital signature.
    """
    private_key, pub_pem = _ensure_keypair()
    now = datetime.now(timezone.utc)

    # Phase 4 labels
    labels = evaluate_and_label(assessment_results)
    label_summary = summarize_labels(labels)

    # Compliance claims
    claims = _build_compliance_claims(labels, assessment_results)

    # Compliance aggregate
    compliant_count = sum(1 for c in claims if c["compliance_status"] == "COMPLIANT")
    partial_count = sum(1 for c in claims if c["compliance_status"] == "PARTIAL")
    non_compliant_count = sum(1 for c in claims if c["compliance_status"] == "NON_COMPLIANT")
    total = len(claims)

    # CBOM evidence reference
    cbom_ref: Dict[str, Any] = {}
    if cbom_data:
        cbom_hash = hashlib.sha256(
            json.dumps(cbom_data, sort_keys=True, default=str).encode()
        ).hexdigest()
        cbom_ref = {
            "type": "CycloneDX-CBOM",
            "specVersion": cbom_data.get("specVersion", "1.6"),
            "serialNumber": cbom_data.get("serialNumber", ""),
            "sha256": cbom_hash,
            "components_count": len(cbom_data.get("components", [])),
        }
    else:
        cbom_ref = {
            "type": "CycloneDX-CBOM",
            "specVersion": "1.6",
            "note": "CBOM not provided — generate via /api/cbom/phase3",
        }

    # Build attestation body (unsigned)
    attestation_body: Dict[str, Any] = {
        "attestationFormat": ATTESTATION_SPEC,
        "specVersion": ATTESTATION_SPEC_VERSION,
        "version": ATTESTATION_VERSION,
        "serialNumber": f"urn:uuid:{uuid.uuid4()}",
        "timestamp": now.isoformat(),
        "validity": {
            "notBefore": now.isoformat(),
            "notAfter": (now + timedelta(days=90)).isoformat(),
            "renewalPolicy": "Re-attest after each scan or within 90 days",
        },
        "attestor": {
            "name": "Q-ARMOR Attestation Engine",
            "version": "5.0.0",
            "organization": "Q-ARMOR Project — PNB Cybersecurity Hackathon 2025-26",
        },
        "subject": {
            "description": "PQC Compliance Attestation for scanned cryptographic endpoints",
            "totalEndpoints": total,
            "assessmentDate": now.isoformat(),
        },
        "complianceSummary": {
            "totalEndpoints": total,
            "compliant": compliant_count,
            "compliant_pct": f"{round(compliant_count / total * 100, 1)}%" if total else "0%",
            "partial": partial_count,
            "partial_pct": f"{round(partial_count / total * 100, 1)}%" if total else "0%",
            "nonCompliant": non_compliant_count,
            "nonCompliant_pct": f"{round(non_compliant_count / total * 100, 1)}%" if total else "0%",
            "overallStatus": (
                "COMPLIANT" if non_compliant_count == 0 and partial_count == 0
                else "PARTIAL" if non_compliant_count == 0
                else "NON_COMPLIANT"
            ),
        },
        "certificationLabels": {
            "fullyQuantumSafe": label_summary["fully_quantum_safe"],
            "pqcReady": label_summary["pqc_ready"],
            "nonCompliant": label_summary["non_compliant"],
        },
        "nistStandards": [NIST_FIPS_203, NIST_FIPS_204, NIST_FIPS_205],
        "claims": claims,
        "evidence": {
            "cbom": cbom_ref,
            "assessmentSource": "Q-ARMOR Phase 2 NIST PQC Assessment Engine",
            "labelingSource": "Q-ARMOR Phase 4 3-Tier Certification Engine",
        },
    }

    # Sign the attestation body
    body_bytes = json.dumps(attestation_body, sort_keys=True, default=str).encode("utf-8")
    body_hash = hashlib.sha256(body_bytes).hexdigest()
    signature = _sign_payload(private_key, body_bytes)

    # Wrap in signed envelope
    cdxa: Dict[str, Any] = {
        "$schema": "https://cyclonedx.org/schema/ext/attestation-1.6.json",
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
            "generator": "Q-ARMOR v5.0.0",
            "generatedAt": now.isoformat(),
            "format": "CDXA (CycloneDX Attestation)",
        },
    }

    if output_file:
        out_path = Path(output_file)
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text(json.dumps(cdxa, indent=2, default=str), encoding="utf-8")

    return cdxa


# ── Verification ─────────────────────────────────────────────────────────────

def verify_attestation(cdxa: Dict[str, Any]) -> Dict[str, Any]:
    """Verify the digital signature of a CDXA document.

    Parameters
    ----------
    cdxa : dict
        The complete CDXA document.

    Returns
    -------
    dict
        Verification result with ``valid`` (bool) and ``details``.
    """
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

        # Also verify hash
        body_hash = hashlib.sha256(body_bytes).hexdigest()
        expected_hash = sig_info.get("contentHash", {}).get("value", "")

        return {
            "valid": True,
            "signatureAlgorithm": sig_info.get("algorithm", "Ed25519"),
            "hashMatch": body_hash == expected_hash,
            "attestor": body.get("attestor", {}),
            "timestamp": body.get("timestamp", ""),
            "validity": body.get("validity", {}),
            "complianceSummary": body.get("complianceSummary", {}),
        }

    except Exception as exc:
        return {"valid": False, "details": f"Signature verification failed: {exc}"}


# ── Convenience ──────────────────────────────────────────────────────────────

def get_attestation_summary(cdxa: Dict[str, Any]) -> Dict[str, Any]:
    """Extract a human-readable summary from a CDXA document."""
    body = cdxa.get("attestation", {})
    summary = body.get("complianceSummary", {})
    labels = body.get("certificationLabels", {})
    validity = body.get("validity", {})

    return {
        "serialNumber": body.get("serialNumber", ""),
        "timestamp": body.get("timestamp", ""),
        "overallStatus": summary.get("overallStatus", "UNKNOWN"),
        "totalEndpoints": summary.get("totalEndpoints", 0),
        "compliant": summary.get("compliant", 0),
        "partial": summary.get("partial", 0),
        "nonCompliant": summary.get("nonCompliant", 0),
        "fullyQuantumSafe": labels.get("fullyQuantumSafe", 0),
        "pqcReady": labels.get("pqcReady", 0),
        "validUntil": validity.get("notAfter", ""),
        "signed": "signature" in cdxa,
    }
