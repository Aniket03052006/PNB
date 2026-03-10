"""Module 4: CBOM Generator — CycloneDX 1.6 JSON output for Cryptographic Bill of Materials."""

from __future__ import annotations
import uuid
from datetime import datetime, timezone
from backend.models import ScanResult, ScanSummary


def generate_cbom(summary: ScanSummary) -> dict:
    """Generate a full CycloneDX 1.6 CBOM from scan results."""
    bom_ref = str(uuid.uuid4())

    components = []
    for result in summary.results:
        asset = result.asset
        fp = result.fingerprint
        q = result.q_score

        component = {
            "type": "cryptographic-asset",
            "bom-ref": f"crypto-{asset.hostname}-{asset.port}",
            "name": f"{asset.hostname}:{asset.port}",
            "version": "",
            "description": f"Cryptographic configuration for {asset.hostname} ({asset.asset_type.value})",
            "cryptoProperties": {
                "assetType": "protocol",
                "protocolProperties": {
                    "type": "tls",
                    "version": fp.tls.version,
                    "cipherSuites": [
                        {
                            "name": fp.tls.cipher_suite,
                            "algorithms": [fp.tls.cipher_algorithm],
                            "identifiers": [
                                {"type": "iana", "value": fp.tls.cipher_suite}
                            ],
                        }
                    ] if fp.tls.cipher_suite else [],
                },
                "algorithmProperties": {
                    "keyExchange": fp.tls.key_exchange,
                    "authentication": fp.tls.authentication,
                    "keySize": fp.tls.cipher_bits,
                },
            },
            "certificates": [],
            "properties": [
                {"name": "qarmor:qScore", "value": str(q.total)},
                {"name": "qarmor:status", "value": q.status.value},
                {"name": "qarmor:hasPqcKex", "value": str(fp.has_pqc_kex).lower()},
                {"name": "qarmor:hasPqcSig", "value": str(fp.has_pqc_signature).lower()},
                {"name": "qarmor:hasHybridMode", "value": str(fp.has_hybrid_mode).lower()},
                {"name": "qarmor:hasForwardSecrecy", "value": str(fp.has_forward_secrecy).lower()},
            ],
        }

        # Certificate entry
        cert = fp.certificate
        if cert.subject:
            component["certificates"].append({
                "subjectName": cert.subject,
                "issuerName": cert.issuer,
                "serialNumber": cert.serial_number,
                "signatureAlgorithm": cert.signature_algorithm,
                "publicKeyAlgorithm": cert.public_key_type,
                "publicKeySize": cert.public_key_bits,
                "notValidBefore": cert.not_before,
                "notValidAfter": cert.not_after,
                "subjectAlternativeNames": cert.san_entries,
                "properties": [
                    {"name": "qarmor:isExpired", "value": str(cert.is_expired).lower()},
                    {"name": "qarmor:daysUntilExpiry", "value": str(cert.days_until_expiry)},
                ],
            })

        # PQC assessment (Q-ARMOR extension)
        component["pqcAssessment"] = {
            "qScore": q.total,
            "status": q.status.value,
            "findings": q.findings,
            "recommendations": q.recommendations,
        }

        components.append(component)

    cbom = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "serialNumber": f"urn:uuid:{bom_ref}",
        "version": 1,
        "metadata": {
            "timestamp": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
            "tools": {
                "components": [
                    {
                        "type": "application",
                        "name": "Q-ARMOR",
                        "version": "1.0.0",
                        "description": "Quantum-Aware Mapping & Observation for Risk Remediation",
                    }
                ]
            },
            "component": {
                "type": "application",
                "name": "Q-ARMOR Cryptographic Scan",
                "version": "1.0.0",
            },
        },
        "components": components,
        "compositions": [
            {
                "aggregate": "complete",
                "assemblies": [c["bom-ref"] for c in components],
            }
        ],
        "properties": [
            {"name": "qarmor:totalAssets", "value": str(summary.total_assets)},
            {"name": "qarmor:averageQScore", "value": f"{summary.average_q_score:.1f}"},
            {"name": "qarmor:fullyQuantumSafe", "value": str(summary.fully_quantum_safe)},
            {"name": "qarmor:pqcTransition", "value": str(summary.pqc_transition)},
            {"name": "qarmor:quantumVulnerable", "value": str(summary.quantum_vulnerable)},
            {"name": "qarmor:criticallyVulnerable", "value": str(summary.critically_vulnerable)},
        ],
    }

    return cbom


def generate_simple_report(summary: ScanSummary) -> list[dict]:
    """Generate a simplified flat JSON report for quick audit (CERT-IN style)."""
    report = []
    for result in summary.results:
        asset = result.asset
        fp = result.fingerprint
        q = result.q_score
        
        report.append({
            "asset": f"{asset.hostname}:{asset.port}",
            "tls_version": fp.tls.version,
            "cipher_suite": fp.tls.cipher_suite,
            "key_exchange": fp.tls.key_exchange,
            "certificate_algorithm": fp.certificate.public_key_type,
            "q_score": q.total,
            "status": q.status.value
        })
    return report
