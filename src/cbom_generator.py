#!/usr/bin/env python3
"""
Phase 3 — CBOM Generation Engine
=================================
Generates a **CycloneDX 1.6 Cryptographic Bill of Materials (CBOM)** JSON
document from Phase 1 scan data and Phase 2 assessment results.

The CBOM is built natively with Python dicts + the built-in ``json`` module
(zero external dependencies) and conforms to the official CycloneDX 1.6
specification which introduced ``cryptographic-asset`` component types and
the ``cryptoProperties`` extension.

Public API
──────────
  generate_cbom(scan_data, assessment_results, output_file)  →  dict
      Build the full CycloneDX 1.6 CBOM and optionally write it to disk.

  generate_cbom_from_summary(scan_summary, output_file)  →  dict
      Convenience wrapper that takes a ScanSummary, runs Phase 2 assessment
      internally, and delegates to ``generate_cbom``.

References
──────────
  • OWASP CycloneDX 1.6 Specification:
        https://cyclonedx.org/docs/1.6/json/
  • CycloneDX Cryptographic Bill of Materials (CBOM):
        https://cyclonedx.org/capabilities/cbom/
  • NIST FIPS 203 (ML-KEM), FIPS 204 (ML-DSA), FIPS 205 (SLH-DSA)

Author : Q-ARMOR Team — PNB Cybersecurity Hackathon 2025-26
"""

from __future__ import annotations

import json
import uuid
import hashlib
import logging
from copy import deepcopy
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

logger = logging.getLogger("qarmor.cbom")

# ────────────────────────────────────────────────────────────────────────────
# Constants
# ────────────────────────────────────────────────────────────────────────────
TOOL_NAME = "Q-ARMOR"
TOOL_VERSION = "2.0.0"
TOOL_VENDOR = "Q-ARMOR Team — PNB Cybersecurity Hackathon 2025-26"
SPEC_VERSION = "1.6"
BOM_FORMAT = "CycloneDX"

# CycloneDX 1.6 cryptoProperties.assetType values
ASSET_TYPE_PROTOCOL = "protocol"
ASSET_TYPE_ALGORITHM = "algorithm"
ASSET_TYPE_CERTIFICATE = "certificate"
ASSET_TYPE_RELATED_CRYPTO = "related-crypto-material"

# KEX primitive classification
_PQC_KEM_KEYWORDS = {"ML-KEM", "MLKEM", "KYBER", "CRYSTALS-KYBER", "SIKE", "BIKE", "HQC", "FrodoKEM"}
_HYBRID_KEM_KEYWORDS = {"X25519MLKEM", "X25519+MLKEM", "SecP256r1MLKEM"}
_CLASSICAL_KEX_KEYWORDS = {"RSA", "DHE", "ECDHE", "DH", "X25519", "X448", "SecP"}

# Signature primitive classification
_PQC_SIG_KEYWORDS = {"ML-DSA", "MLDSA", "DILITHIUM", "SPHINCS", "SLH-DSA", "FALCON"}
_CLASSICAL_SIG_KEYWORDS = {"RSA", "ECDSA", "DSA", "Ed25519", "Ed448"}

# Cipher strength classification
_WEAK_CIPHERS = {"3DES", "DES", "RC4", "RC2", "IDEA"}
_POST_QUANTUM_SAFE_BITS = 256  # AES-256 is quantum-safe against Grover


# ────────────────────────────────────────────────────────────────────────────
# Utility: Deterministic bom-ref generation
# ────────────────────────────────────────────────────────────────────────────
def _bom_ref(*parts: str) -> str:
    """Generate a deterministic, unique bom-ref from component parts."""
    seed = ":".join(str(p) for p in parts)
    short = hashlib.sha256(seed.encode()).hexdigest()[:16]
    return f"cbom-{short}"


def _uuid() -> str:
    """Fresh UUID-4 as a URN for the BOM serial number."""
    return f"urn:uuid:{uuid.uuid4()}"


def _iso_now() -> str:
    """Current UTC timestamp in ISO-8601 format."""
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


# ────────────────────────────────────────────────────────────────────────────
# Primitive Detection Helpers
# ────────────────────────────────────────────────────────────────────────────
def _classify_kex_primitive(kex: str) -> str:
    """Return CycloneDX 1.6 ``primitive`` for a key-exchange algorithm.

    Maps to: ``kem`` | ``key-agreement`` | ``unknown``
    """
    upper = kex.upper()
    # Pure PQC KEM
    for tag in _PQC_KEM_KEYWORDS:
        if tag.upper() in upper:
            return "kem"
    # Hybrid: Classical + PQC
    for tag in _HYBRID_KEM_KEYWORDS:
        if tag.upper() in upper:
            return "kem"
    # Classical DH-family
    for tag in _CLASSICAL_KEX_KEYWORDS:
        if tag.upper() in upper:
            return "key-agreement"
    return "unknown"


def _classify_sig_primitive(sig: str) -> str:
    """Return CycloneDX primitive for a signature algorithm."""
    upper = sig.upper()
    for tag in _PQC_SIG_KEYWORDS:
        if tag.upper() in upper:
            return "signature"
    for tag in _CLASSICAL_SIG_KEYWORDS:
        if tag.upper() in upper:
            return "signature"
    if "SHA" in upper or "MD5" in upper:
        return "hash"
    return "unknown"


def _quantum_status_label(kex: str, sig: str) -> str:
    """High-level quantum-safety label for display in CBOM properties."""
    upper_kex = kex.upper()
    upper_sig = sig.upper()

    kex_pqc = any(t.upper() in upper_kex for t in _PQC_KEM_KEYWORDS)
    kex_hybrid = any(t.upper() in upper_kex for t in _HYBRID_KEM_KEYWORDS)
    sig_pqc = any(t.upper() in upper_sig for t in _PQC_SIG_KEYWORDS)

    if kex_pqc and sig_pqc:
        return "FULLY_QUANTUM_SAFE"
    if kex_pqc or kex_hybrid:
        return "PQC_TRANSITION"
    return "QUANTUM_VULNERABLE"


# ────────────────────────────────────────────────────────────────────────────
# Component Builders (CycloneDX 1.6 Schema)
# ────────────────────────────────────────────────────────────────────────────

def _build_application_component(
    hostname: str,
    port: int,
    asset_type: str = "web",
    q_score: int = 0,
    status: str = "UNKNOWN",
) -> dict:
    """Build the top-level *application* component for a scanned target.

    CycloneDX type: ``application``
    """
    ref = _bom_ref("app", hostname, str(port))
    return {
        "type": "application",
        "bom-ref": ref,
        "name": hostname,
        "version": "",
        "description": f"Public-facing {asset_type} service at {hostname}:{port}",
        "properties": [
            {"name": "qarmor:port", "value": str(port)},
            {"name": "qarmor:assetType", "value": asset_type},
            {"name": "qarmor:qScore", "value": str(q_score)},
            {"name": "qarmor:pqcStatus", "value": status},
        ],
    }


def _build_protocol_component(
    hostname: str,
    port: int,
    tls_version: str,
    cipher_suite: str = "",
    cipher_algorithm: str = "",
    cipher_bits: int = 0,
) -> dict:
    """Build a ``cryptographic-asset`` of assetType ``protocol``.

    Represents the TLS protocol configuration for a target.
    """
    ref = _bom_ref("proto", hostname, str(port), tls_version)
    cipher_suites = []
    if cipher_suite:
        cipher_suites.append({
            "name": cipher_suite,
            "algorithms": [cipher_algorithm] if cipher_algorithm else [],
            "identifiers": [{"type": "iana", "value": cipher_suite}],
        })

    return {
        "type": "cryptographic-asset",
        "bom-ref": ref,
        "name": f"TLS ({tls_version})",
        "version": tls_version or "unknown",
        "description": f"TLS protocol configuration for {hostname}:{port}",
        "cryptoProperties": {
            "assetType": ASSET_TYPE_PROTOCOL,
            "protocolProperties": {
                "type": "tls",
                "version": tls_version or "unknown",
                "cipherSuites": cipher_suites,
            },
        },
        "properties": [
            {"name": "qarmor:cipherAlgorithm", "value": cipher_algorithm or "unknown"},
            {"name": "qarmor:cipherBits", "value": str(cipher_bits)},
        ],
    }


def _build_kex_component(
    hostname: str,
    port: int,
    kex_algorithm: str,
    authentication: str = "",
    assessment: Optional[Dict[str, Any]] = None,
) -> dict:
    """Build a ``cryptographic-asset`` of assetType ``algorithm`` for KEX.

    Includes ``algorithmProperties`` with the primitive type (kem / key-agreement),
    the algorithm name, and the Phase 2 quantum-security status.
    """
    ref = _bom_ref("kex", hostname, str(port), kex_algorithm)
    primitive = _classify_kex_primitive(kex_algorithm)

    # Extract assessment status if available
    kex_status = "UNKNOWN"
    kex_details = ""
    if assessment:
        kex_status = assessment.get("key_exchange_status", "UNKNOWN")
        kex_details = assessment.get("key_exchange_details", "")

    component: Dict[str, Any] = {
        "type": "cryptographic-asset",
        "bom-ref": ref,
        "name": kex_algorithm or "UNKNOWN",
        "version": "",
        "description": f"Key exchange algorithm for {hostname}:{port}",
        "cryptoProperties": {
            "assetType": ASSET_TYPE_ALGORITHM,
            "algorithmProperties": {
                "primitive": primitive,
                "parameterSetIdentifier": kex_algorithm,
                "executionEnvironment": "server-side",
                "implementationPlatform": "tls",
                "certificationLevel": [],
                "cryptoFunctions": ["keygen", "encapsulate", "decapsulate"]
                    if primitive == "kem"
                    else ["keygen", "keyderive"],
            },
        },
        "properties": [
            {"name": "qarmor:quantumStatus", "value": kex_status},
            {"name": "qarmor:authentication", "value": authentication or "unknown"},
        ],
    }

    if kex_details:
        component["properties"].append(
            {"name": "qarmor:kexAssessmentDetails", "value": kex_details}
        )

    # NIST standard references for PQC algorithms
    upper_kex = (kex_algorithm or "").upper()
    nist_refs = []
    if "ML-KEM" in upper_kex or "MLKEM" in upper_kex:
        nist_refs.append({
            "id": "FIPS-203",
            "source": {"name": "NIST", "url": "https://csrc.nist.gov/pubs/fips/203/final"},
            "description": "ML-KEM (Module-Lattice Key Encapsulation Mechanism)",
        })
    if "X25519" in upper_kex and ("MLKEM" in upper_kex or "ML-KEM" in upper_kex):
        nist_refs.append({
            "id": "draft-ietf-tls-hybrid-design",
            "source": {"name": "IETF", "url": "https://datatracker.ietf.org/doc/draft-ietf-tls-hybrid-design/"},
            "description": "Hybrid key exchange for TLS 1.3",
        })
    if nist_refs:
        component["evidence"] = {"occurrences": nist_refs}

    return component


def _build_certificate_component(
    hostname: str,
    port: int,
    cert_data: Dict[str, Any],
    assessment: Optional[Dict[str, Any]] = None,
) -> dict:
    """Build a ``cryptographic-asset`` of assetType ``certificate``.

    Includes the full certificate metadata plus a reference to the
    signature algorithm.
    """
    subject = cert_data.get("subject", "")
    sig_algo = cert_data.get("signature_algorithm", "")
    pk_type = cert_data.get("public_key_type", "")
    pk_bits = cert_data.get("public_key_bits", 0)

    ref = _bom_ref("cert", hostname, str(port), subject)
    sig_algo_ref = _bom_ref("sigalgo", hostname, str(port), sig_algo)

    cert_status = "UNKNOWN"
    cert_details = ""
    if assessment:
        cert_status = assessment.get("certificate_status", "UNKNOWN")
        cert_details = assessment.get("certificate_details", "")

    component: Dict[str, Any] = {
        "type": "cryptographic-asset",
        "bom-ref": ref,
        "name": subject or f"Certificate for {hostname}",
        "version": "",
        "description": f"X.509 certificate for {hostname}:{port}",
        "cryptoProperties": {
            "assetType": ASSET_TYPE_CERTIFICATE,
            "certificateProperties": {
                "subjectName": subject,
                "issuerName": cert_data.get("issuer", ""),
                "notValidBefore": cert_data.get("not_before", ""),
                "notValidAfter": cert_data.get("not_after", ""),
                "signatureAlgorithmRef": sig_algo_ref,
                "subjectPublicKeyRef": _bom_ref("pubkey", hostname, str(port), pk_type),
                "certificateFormat": "X.509",
                "certificateExtension": "pem",
            },
        },
        "properties": [
            {"name": "qarmor:signatureAlgorithm", "value": sig_algo},
            {"name": "qarmor:publicKeyType", "value": pk_type},
            {"name": "qarmor:publicKeyBits", "value": str(pk_bits)},
            {"name": "qarmor:serialNumber", "value": cert_data.get("serial_number", "")},
            {"name": "qarmor:isExpired", "value": str(cert_data.get("is_expired", False)).lower()},
            {"name": "qarmor:daysUntilExpiry", "value": str(cert_data.get("days_until_expiry", 0))},
            {"name": "qarmor:quantumStatus", "value": cert_status},
        ],
    }

    if cert_data.get("san_entries"):
        component["properties"].append({
            "name": "qarmor:subjectAlternativeNames",
            "value": ", ".join(cert_data["san_entries"]),
        })

    if cert_details:
        component["properties"].append(
            {"name": "qarmor:certAssessmentDetails", "value": cert_details}
        )

    return component


def _build_signature_algorithm_component(
    hostname: str,
    port: int,
    sig_algo: str,
) -> dict:
    """Build a ``cryptographic-asset`` of assetType ``algorithm`` for the
    certificate's signature algorithm (e.g. sha256WithRSAEncryption, ML-DSA-65)."""
    ref = _bom_ref("sigalgo", hostname, str(port), sig_algo)
    primitive = _classify_sig_primitive(sig_algo)

    return {
        "type": "cryptographic-asset",
        "bom-ref": ref,
        "name": sig_algo or "UNKNOWN",
        "version": "",
        "description": f"Certificate signature algorithm for {hostname}:{port}",
        "cryptoProperties": {
            "assetType": ASSET_TYPE_ALGORITHM,
            "algorithmProperties": {
                "primitive": primitive,
                "parameterSetIdentifier": sig_algo,
                "executionEnvironment": "server-side",
                "implementationPlatform": "x509",
                "cryptoFunctions": ["sign", "verify"],
            },
        },
    }


def _build_symmetric_algorithm_component(
    hostname: str,
    port: int,
    cipher_algorithm: str,
    cipher_bits: int,
) -> dict:
    """Build a ``cryptographic-asset`` for the symmetric cipher (e.g. AES-256-GCM)."""
    ref = _bom_ref("sym", hostname, str(port), cipher_algorithm, str(cipher_bits))
    mode = ""
    name_display = cipher_algorithm or "UNKNOWN"
    if cipher_algorithm:
        name_display = f"{cipher_algorithm}-{cipher_bits}" if cipher_bits else cipher_algorithm
        if "GCM" in cipher_algorithm.upper() or cipher_bits:
            mode = "gcm" if "GCM" not in cipher_algorithm.upper() else "gcm"

    return {
        "type": "cryptographic-asset",
        "bom-ref": ref,
        "name": name_display,
        "version": "",
        "description": f"Symmetric cipher for {hostname}:{port}",
        "cryptoProperties": {
            "assetType": ASSET_TYPE_ALGORITHM,
            "algorithmProperties": {
                "primitive": "block-cipher" if cipher_algorithm not in ("CHACHA20",) else "stream-cipher",
                "parameterSetIdentifier": f"{cipher_algorithm}-{cipher_bits}" if cipher_bits else cipher_algorithm,
                "executionEnvironment": "server-side",
                "implementationPlatform": "tls",
                "cryptoFunctions": ["encrypt", "decrypt"],
            },
        },
        "properties": [
            {"name": "qarmor:keyLength", "value": str(cipher_bits)},
            {
                "name": "qarmor:postQuantumSafe",
                "value": str(
                    cipher_bits >= _POST_QUANTUM_SAFE_BITS
                    and cipher_algorithm.upper() not in _WEAK_CIPHERS
                ).lower(),
            },
        ],
    }


# ────────────────────────────────────────────────────────────────────────────
# Dependency Graph Builder
# ────────────────────────────────────────────────────────────────────────────

def _build_dependency_graph(
    app_ref: str,
    proto_ref: str,
    kex_ref: str,
    cert_ref: str,
    sig_ref: str,
    sym_ref: str,
) -> List[dict]:
    """CycloneDX ``dependencies`` array.

    Models the cryptographic supply chain:

    Application
      └── TLS Protocol
            ├── Key Exchange Algorithm
            ├── Symmetric Cipher
            └── Certificate
                  └── Signature Algorithm
    """
    return [
        {
            "ref": app_ref,
            "dependsOn": [proto_ref],
        },
        {
            "ref": proto_ref,
            "dependsOn": [kex_ref, cert_ref, sym_ref],
        },
        {
            "ref": cert_ref,
            "dependsOn": [sig_ref],
        },
        # Leaf nodes — no dependencies
        {"ref": kex_ref, "dependsOn": []},
        {"ref": sig_ref, "dependsOn": []},
        {"ref": sym_ref, "dependsOn": []},
    ]


# ────────────────────────────────────────────────────────────────────────────
# ★ Main CBOM Generator
# ────────────────────────────────────────────────────────────────────────────

def generate_cbom(
    scan_data: List[Dict[str, Any]],
    assessment_results: Optional[List[Dict[str, Any]]] = None,
    output_file: Optional[str] = "cbom.json",
) -> dict:
    """Generate a CycloneDX 1.6 CBOM from Phase 1 scan data + Phase 2 assessments.

    Parameters
    ----------
    scan_data : list[dict]
        List of endpoint scan dictionaries.  Each must contain at minimum::

            {
                "hostname": str,
                "port": int,
                "asset_type": str,          # "web" | "api" | "vpn" | ...
                "tls_version": str,         # "TLSv1.3" | "TLSv1.2" | ...
                "cipher_suite": str,
                "cipher_algorithm": str,    # "AES" | "CHACHA20" | "3DES"
                "cipher_bits": int,
                "key_exchange": str,        # "ECDHE" | "ML-KEM-768" | ...
                "authentication": str,      # "RSA" | "ECDSA" | "ML-DSA-65"
                "q_score": int,
                "status": str,              # "FULLY_QUANTUM_SAFE" | ...
                "certificate": {
                    "subject": str,
                    "issuer": str,
                    "serial_number": str,
                    "not_before": str,
                    "not_after": str,
                    "signature_algorithm": str,
                    "public_key_type": str,
                    "public_key_bits": int,
                    "san_entries": list[str],
                    "is_expired": bool,
                    "days_until_expiry": int,
                },
            }

    assessment_results : list[dict] | None
        Optional list of Phase 2 assessment dictionaries (one per endpoint,
        keyed by ``target``).  When provided, the CBOM will include per-component
        quantum-security annotations.

    output_file : str | None
        Path to write the pretty-printed JSON.  Set to ``None`` to skip writing
        and just return the dict.

    Returns
    -------
    dict
        The complete CycloneDX 1.6 CBOM document.
    """
    # Index assessments by (hostname, port)
    assess_map: Dict[str, Dict[str, Any]] = {}
    if assessment_results:
        for a in assessment_results:
            key = f"{a.get('target', '')}:{a.get('port', 443)}"
            assess_map[key] = a

    # ── Metadata ─────────────────────────────────────────────────────────
    bom_serial = _uuid()
    timestamp = _iso_now()

    metadata = {
        "timestamp": timestamp,
        "tools": {
            "components": [
                {
                    "type": "application",
                    "author": TOOL_VENDOR,
                    "name": TOOL_NAME,
                    "version": TOOL_VERSION,
                    "description": (
                        "Quantum-Aware Mapping & Observation for Risk Remediation — "
                        "Automated CBOM generator for banking infrastructure."
                    ),
                }
            ]
        },
        "component": {
            "type": "application",
            "name": "Q-ARMOR Cryptographic Scan",
            "version": TOOL_VERSION,
            "description": (
                f"CBOM inventory of {len(scan_data)} public-facing endpoints "
                f"scanned on {timestamp[:10]}."
            ),
        },
        "lifecycles": [
            {"phase": "operations", "description": "Runtime cryptographic audit of deployment infrastructure"}
        ],
    }

    # ── Build components & dependencies for each endpoint ────────────────
    all_components: List[dict] = []
    all_dependencies: List[dict] = []
    all_compositions_assemblies: List[str] = []

    # per-BOM aggregate stats
    stats = {
        "total_endpoints": len(scan_data),
        "pqc_safe": 0,
        "pqc_transition": 0,
        "vulnerable": 0,
        "critically_vulnerable": 0,
    }

    for ep in scan_data:
        hostname = ep.get("hostname", "unknown")
        port = ep.get("port", 443)
        asset_type = ep.get("asset_type", "web")
        tls_version = ep.get("tls_version", "")
        cipher_suite = ep.get("cipher_suite", "")
        cipher_algorithm = ep.get("cipher_algorithm", "")
        cipher_bits = ep.get("cipher_bits", 0)
        kex = ep.get("key_exchange", "")
        auth = ep.get("authentication", "")
        q_score = ep.get("q_score", 0)
        status = ep.get("status", "UNKNOWN")
        cert_data = ep.get("certificate", {})

        # Phase 2 assessment for this endpoint
        assess_key = f"{hostname}:{port}"
        assessment = assess_map.get(assess_key)

        # Update aggregate stats
        status_upper = status.upper()
        if "FULLY" in status_upper or status_upper == "PQC_SAFE":
            stats["pqc_safe"] += 1
        elif "TRANSITION" in status_upper or "HYBRID" in status_upper:
            stats["pqc_transition"] += 1
        elif "CRITICALLY" in status_upper:
            stats["critically_vulnerable"] += 1
        elif "VULNERABLE" in status_upper:
            stats["vulnerable"] += 1

        # 1. Application component
        app_comp = _build_application_component(
            hostname, port, asset_type, q_score, status,
        )

        # 2. Protocol component
        proto_comp = _build_protocol_component(
            hostname, port, tls_version, cipher_suite, cipher_algorithm, cipher_bits,
        )

        # 3. Key Exchange algorithm component
        kex_comp = _build_kex_component(
            hostname, port, kex, auth, assessment,
        )

        # 4. Certificate component
        cert_comp = _build_certificate_component(
            hostname, port, cert_data, assessment,
        )

        # 5. Signature Algorithm component (sub-dependency of certificate)
        sig_algo = cert_data.get("signature_algorithm", "")
        sig_comp = _build_signature_algorithm_component(hostname, port, sig_algo)

        # 6. Symmetric Cipher component
        sym_comp = _build_symmetric_algorithm_component(
            hostname, port, cipher_algorithm, cipher_bits,
        )

        # Collect components
        endpoint_components = [app_comp, proto_comp, kex_comp, cert_comp, sig_comp, sym_comp]
        all_components.extend(endpoint_components)
        all_compositions_assemblies.append(app_comp["bom-ref"])

        # 7. Dependency graph
        deps = _build_dependency_graph(
            app_comp["bom-ref"],
            proto_comp["bom-ref"],
            kex_comp["bom-ref"],
            cert_comp["bom-ref"],
            sig_comp["bom-ref"],
            sym_comp["bom-ref"],
        )
        all_dependencies.extend(deps)

    # ── Assemble final CycloneDX document ────────────────────────────────
    cbom: Dict[str, Any] = {
        "$schema": "http://cyclonedx.org/schema/bom-1.6.schema.json",
        "bomFormat": BOM_FORMAT,
        "specVersion": SPEC_VERSION,
        "serialNumber": bom_serial,
        "version": 1,
        "metadata": metadata,
        "components": all_components,
        "dependencies": all_dependencies,
        "compositions": [
            {
                "aggregate": "complete",
                "assemblies": all_compositions_assemblies,
            }
        ],
        "properties": [
            {"name": "qarmor:totalEndpoints", "value": str(stats["total_endpoints"])},
            {"name": "qarmor:pqcSafe", "value": str(stats["pqc_safe"])},
            {"name": "qarmor:pqcTransition", "value": str(stats["pqc_transition"])},
            {"name": "qarmor:quantumVulnerable", "value": str(stats["vulnerable"])},
            {"name": "qarmor:criticallyVulnerable", "value": str(stats["critically_vulnerable"])},
            {"name": "qarmor:generatedBy", "value": TOOL_NAME},
            {"name": "qarmor:specVersion", "value": SPEC_VERSION},
        ],
    }

    # ── Write to disk ────────────────────────────────────────────────────
    if output_file:
        out_path = Path(output_file)
        out_path.parent.mkdir(parents=True, exist_ok=True)
        with open(out_path, "w", encoding="utf-8") as fh:
            json.dump(cbom, fh, indent=4, ensure_ascii=False)
        logger.info("CBOM written to %s (%d components, %d dependencies)",
                     out_path, len(all_components), len(all_dependencies))

    return cbom


# ────────────────────────────────────────────────────────────────────────────
# Convenience: ScanSummary → CBOM (bridge for backend integration)
# ────────────────────────────────────────────────────────────────────────────

def _scan_summary_to_dicts(summary_dict: dict) -> List[Dict[str, Any]]:
    """Convert the flat ScanSummary / results list into the generic dict
    format expected by ``generate_cbom``."""
    scan_data: List[Dict[str, Any]] = []
    for r in summary_dict.get("results", []):
        asset = r.get("asset", {})
        fp = r.get("fingerprint", {})
        tls = fp.get("tls", {})
        cert = fp.get("certificate", {})
        qs = r.get("q_score", {})

        scan_data.append({
            "hostname": asset.get("hostname", "unknown"),
            "port": asset.get("port", 443),
            "asset_type": asset.get("asset_type", "web"),
            "tls_version": tls.get("version", ""),
            "cipher_suite": tls.get("cipher_suite", ""),
            "cipher_algorithm": tls.get("cipher_algorithm", ""),
            "cipher_bits": tls.get("cipher_bits", 0),
            "key_exchange": tls.get("key_exchange", ""),
            "authentication": tls.get("authentication", ""),
            "q_score": qs.get("total", 0),
            "status": qs.get("status", "UNKNOWN"),
            "certificate": {
                "subject": cert.get("subject", ""),
                "issuer": cert.get("issuer", ""),
                "serial_number": cert.get("serial_number", ""),
                "not_before": cert.get("not_before", ""),
                "not_after": cert.get("not_after", ""),
                "signature_algorithm": cert.get("signature_algorithm", ""),
                "public_key_type": cert.get("public_key_type", ""),
                "public_key_bits": cert.get("public_key_bits", 0),
                "san_entries": cert.get("san_entries", []),
                "is_expired": cert.get("is_expired", False),
                "days_until_expiry": cert.get("days_until_expiry", 0),
            },
        })
    return scan_data


def generate_cbom_from_summary(
    summary_dict: dict,
    assessment_list: Optional[List[Dict[str, Any]]] = None,
    output_file: Optional[str] = "cbom.json",
) -> dict:
    """Generate CBOM from a ScanSummary dict (as returned by ``/api/summary``
    or ``ScanSummary.model_dump()``).

    This is the bridge used by the backend API and CLI.
    """
    scan_data = _scan_summary_to_dicts(summary_dict)
    return generate_cbom(scan_data, assessment_list, output_file)


# ────────────────────────────────────────────────────────────────────────────
# ★ Standalone Runner with Mock Data
# ────────────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    # ── Mock Phase 1 scan data (simulated PNB banking endpoints) ─────────
    MOCK_SCAN_DATA: List[Dict[str, Any]] = [
        # ── 1. Fully Quantum-Safe endpoint ──
        {
            "hostname": "pqc-gateway.demobank.com",
            "port": 443,
            "asset_type": "api",
            "tls_version": "TLSv1.3",
            "cipher_suite": "TLS_AES_256_GCM_SHA384",
            "cipher_algorithm": "AES",
            "cipher_bits": 256,
            "key_exchange": "ML-KEM-768",
            "authentication": "ML-DSA-65",
            "q_score": 98,
            "status": "FULLY_QUANTUM_SAFE",
            "certificate": {
                "subject": "CN=pqc-gateway.demobank.com",
                "issuer": "CN=DigiCert PQC Root CA",
                "serial_number": "0xA1B2C3D4",
                "not_before": "Dec 10 00:00:00 2025 GMT",
                "not_after": "Mar 10 23:59:59 2028 GMT",
                "signature_algorithm": "ML-DSA-65",
                "public_key_type": "ML-DSA",
                "public_key_bits": 2048,
                "san_entries": ["pqc-gateway.demobank.com"],
                "is_expired": False,
                "days_until_expiry": 730,
            },
        },
        # ── 2. Hybrid PQC Transition endpoint ──
        {
            "hostname": "api.demobank.com",
            "port": 443,
            "asset_type": "api",
            "tls_version": "TLSv1.3",
            "cipher_suite": "TLS_AES_256_GCM_SHA384",
            "cipher_algorithm": "AES",
            "cipher_bits": 256,
            "key_exchange": "X25519MLKEM768",
            "authentication": "ECDSA",
            "q_score": 75,
            "status": "PQC_TRANSITION",
            "certificate": {
                "subject": "CN=api.demobank.com",
                "issuer": "CN=Let's Encrypt R3",
                "serial_number": "0xE5F60718",
                "not_before": "Jan 10 00:00:00 2026 GMT",
                "not_after": "May 10 23:59:59 2026 GMT",
                "signature_algorithm": "sha256WithRSAEncryption",
                "public_key_type": "EC",
                "public_key_bits": 256,
                "san_entries": ["api.demobank.com", "api-v2.demobank.com"],
                "is_expired": False,
                "days_until_expiry": 60,
            },
        },
        # ── 3. Quantum-Vulnerable endpoint (TLS 1.2 + ECDHE) ──
        {
            "hostname": "netbanking.demobank.com",
            "port": 443,
            "asset_type": "web",
            "tls_version": "TLSv1.2",
            "cipher_suite": "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
            "cipher_algorithm": "AES",
            "cipher_bits": 256,
            "key_exchange": "ECDHE",
            "authentication": "RSA",
            "q_score": 52,
            "status": "QUANTUM_VULNERABLE",
            "certificate": {
                "subject": "CN=netbanking.demobank.com",
                "issuer": "CN=GeoTrust RSA CA 2018",
                "serial_number": "0xB9C8D7E6",
                "not_before": "Jun 15 00:00:00 2025 GMT",
                "not_after": "Apr 10 23:59:59 2026 GMT",
                "signature_algorithm": "sha256WithRSAEncryption",
                "public_key_type": "RSA",
                "public_key_bits": 2048,
                "san_entries": ["netbanking.demobank.com", "www.netbanking.demobank.com"],
                "is_expired": False,
                "days_until_expiry": 300,
            },
        },
        # ── 4. Critically Vulnerable endpoint (TLS 1.0 + 3DES + RSA-1024) ──
        {
            "hostname": "old-staging.demobank.com",
            "port": 8443,
            "asset_type": "web",
            "tls_version": "TLSv1.0",
            "cipher_suite": "TLS_RSA_WITH_3DES_EDE_CBC_SHA",
            "cipher_algorithm": "3DES",
            "cipher_bits": 112,
            "key_exchange": "RSA",
            "authentication": "RSA",
            "q_score": 8,
            "status": "CRITICALLY_VULNERABLE",
            "certificate": {
                "subject": "CN=old-staging.demobank.com",
                "issuer": "CN=Internal Self-Signed",
                "serial_number": "0x00000001",
                "not_before": "Jan 01 00:00:00 2020 GMT",
                "not_after": "Feb 08 23:59:59 2026 GMT",
                "signature_algorithm": "sha1WithRSAEncryption",
                "public_key_type": "RSA",
                "public_key_bits": 1024,
                "san_entries": ["old-staging.demobank.com"],
                "is_expired": True,
                "days_until_expiry": -30,
            },
        },
        # ── 5. VPN gateway (TLS 1.1 + weak KEX) ──
        {
            "hostname": "legacy-vpn.demobank.com",
            "port": 1194,
            "asset_type": "vpn",
            "tls_version": "TLSv1.1",
            "cipher_suite": "TLS_RSA_WITH_AES_128_CBC_SHA",
            "cipher_algorithm": "AES",
            "cipher_bits": 128,
            "key_exchange": "RSA",
            "authentication": "RSA",
            "q_score": 12,
            "status": "CRITICALLY_VULNERABLE",
            "certificate": {
                "subject": "CN=legacy-vpn.demobank.com",
                "issuer": "CN=Internal CA",
                "serial_number": "0x1A2B3C4D",
                "not_before": "Mar 01 00:00:00 2025 GMT",
                "not_after": "Mar 25 23:59:59 2026 GMT",
                "signature_algorithm": "sha1WithRSAEncryption",
                "public_key_type": "RSA",
                "public_key_bits": 1024,
                "san_entries": ["legacy-vpn.demobank.com"],
                "is_expired": False,
                "days_until_expiry": 15,
            },
        },
    ]

    # ── Mock Phase 2 assessment results ──────────────────────────────────
    MOCK_ASSESSMENT_RESULTS: List[Dict[str, Any]] = [
        {
            "target": "pqc-gateway.demobank.com",
            "port": 443,
            "tls_status": "PASS",
            "key_exchange_status": "PQC_SAFE",
            "key_exchange_details": (
                "ML-KEM-768 is a NIST-approved post-quantum KEM (FIPS 203). "
                "Key exchange is safe against both classical and quantum adversaries."
            ),
            "certificate_status": "PQC_SAFE",
            "certificate_details": (
                "ML-DSA-65 is a NIST-approved PQC digital signature (FIPS 204). "
                "Certificate is safe against quantum adversaries."
            ),
            "symmetric_cipher_status": "PASS",
            "overall_quantum_risk": "LOW",
            "hndl_vulnerable": False,
        },
        {
            "target": "api.demobank.com",
            "port": 443,
            "tls_status": "PASS",
            "key_exchange_status": "HYBRID",
            "key_exchange_details": (
                "X25519MLKEM768 is a hybrid classical+PQC key exchange. "
                "Provides transitional quantum safety."
            ),
            "certificate_status": "VULNERABLE",
            "certificate_details": (
                "sha256WithRSAEncryption is a classical signature vulnerable "
                "to Shor's algorithm."
            ),
            "symmetric_cipher_status": "PASS",
            "overall_quantum_risk": "MEDIUM",
            "hndl_vulnerable": False,
        },
        {
            "target": "netbanking.demobank.com",
            "port": 443,
            "tls_status": "FAIL",
            "key_exchange_status": "VULNERABLE",
            "key_exchange_details": (
                "ECDHE is a classical key exchange vulnerable to Shor's algorithm. "
                "Susceptible to HNDL attacks."
            ),
            "certificate_status": "VULNERABLE",
            "certificate_details": "RSA-2048 is quantum-vulnerable.",
            "symmetric_cipher_status": "PASS",
            "overall_quantum_risk": "HIGH",
            "hndl_vulnerable": True,
        },
        {
            "target": "old-staging.demobank.com",
            "port": 8443,
            "tls_status": "FAIL",
            "key_exchange_status": "VULNERABLE",
            "key_exchange_details": "RSA key exchange — no forward secrecy, quantum vulnerable.",
            "certificate_status": "VULNERABLE",
            "certificate_details": "RSA-1024 with SHA-1 — critically weak, expired.",
            "symmetric_cipher_status": "FAIL",
            "overall_quantum_risk": "HIGH",
            "hndl_vulnerable": True,
        },
        {
            "target": "legacy-vpn.demobank.com",
            "port": 1194,
            "tls_status": "FAIL",
            "key_exchange_status": "VULNERABLE",
            "key_exchange_details": "RSA key exchange — no forward secrecy, quantum vulnerable.",
            "certificate_status": "VULNERABLE",
            "certificate_details": "RSA-1024 with SHA-1 — weak.",
            "symmetric_cipher_status": "FAIL",
            "overall_quantum_risk": "HIGH",
            "hndl_vulnerable": True,
        },
    ]

    # ── Generate ─────────────────────────────────────────────────────────
    print("=" * 72)
    print("  Q-ARMOR Phase 3 — CBOM Generation Engine")
    print("  CycloneDX 1.6 Cryptographic Bill of Materials")
    print("=" * 72)
    print()

    cbom = generate_cbom(
        scan_data=MOCK_SCAN_DATA,
        assessment_results=MOCK_ASSESSMENT_RESULTS,
        output_file="cbom.json",
    )

    print(f"  bomFormat    : {cbom['bomFormat']}")
    print(f"  specVersion  : {cbom['specVersion']}")
    print(f"  serialNumber : {cbom['serialNumber']}")
    print(f"  components   : {len(cbom['components'])}")
    print(f"  dependencies : {len(cbom['dependencies'])}")
    print()

    # Summary by component type
    app_count = sum(1 for c in cbom["components"] if c["type"] == "application")
    crypto_count = sum(1 for c in cbom["components"] if c["type"] == "cryptographic-asset")
    print(f"  → Application components      : {app_count}")
    print(f"  → Cryptographic-asset components: {crypto_count}")
    print()

    # List each endpoint and its dependency tree
    for ep in MOCK_SCAN_DATA:
        h = ep["hostname"]
        p = ep["port"]
        s = ep["status"]
        q = ep["q_score"]
        print(f"  [{s:<26}] {h}:{p}  (Q-Score: {q})")
        print(f"      ├── TLS {ep['tls_version']}  ({ep['cipher_suite']})")
        print(f"      ├── KEX {ep['key_exchange']}  (auth: {ep['authentication']})")
        print(f"      ├── Cert {ep['certificate']['signature_algorithm']} / {ep['certificate']['public_key_type']}-{ep['certificate']['public_key_bits']}")
        print(f"      └── Sym {ep['cipher_algorithm']}-{ep['cipher_bits']}")
        print()

    print(f"  ✓ CBOM written to: cbom.json")
    print(f"  ✓ {len(cbom['components'])} components, {len(cbom['dependencies'])} dependency edges")
    print("=" * 72)
