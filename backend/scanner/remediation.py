"""
Phase 2 — Actionable Remediation Logic.

Generates prioritised, actionable remediation recommendations for
endpoints that are not PQC-ready.  Each recommendation maps directly
to a specific assessment dimension (TLS version, key exchange,
certificate, symmetric cipher) with concrete steps and timelines.

Public API
──────────
  generate_remediation(assessment)  →  list[dict]
  generate_batch_remediation(batch_assessment) → dict
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List

logger = logging.getLogger("qarmor.remediation")


# ───────────────────────────────────────────────────────────────────────────
# Priority Constants
# ───────────────────────────────────────────────────────────────────────────

P1_CRITICAL = "P1_CRITICAL"
P2_HIGH = "P2_HIGH"
P3_MEDIUM = "P3_MEDIUM"
P4_LOW = "P4_LOW"

_PRIORITY_ORDER = {P1_CRITICAL: 0, P2_HIGH: 1, P3_MEDIUM: 2, P4_LOW: 3}


# ───────────────────────────────────────────────────────────────────────────
# Single-Endpoint Remediation
# ───────────────────────────────────────────────────────────────────────────

def generate_remediation(assessment: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Generate actionable remediation steps for a single endpoint assessment.

    Parameters
    ----------
    assessment : dict
        The output of ``analyze_endpoint()`` from the assessment engine.

    Returns
    -------
    list[dict]
        Ordered list of remediation actions, each containing:

        - ``priority``     : str   (P1_CRITICAL … P4_LOW)
        - ``timeframe``    : str   (e.g. "0–30 days")
        - ``category``     : str   (tls | key_exchange | certificate | symmetric)
        - ``title``        : str   (short headline)
        - ``description``  : str   (detailed recommendation)
        - ``actions``      : list[str]  (concrete steps)
        - ``references``   : list[str]  (NIST standards, RFCs)
        - ``impact``       : str   (what happens if not fixed)
    """
    remediations: List[Dict[str, Any]] = []

    target = assessment.get("target", "unknown")
    port = assessment.get("port", 443)
    endpoint = f"{target}:{port}"

    # ── 1.  TLS Protocol Remediation ─────────────────────────────────────
    if assessment.get("tls_status") == "FAIL":
        tls_ver = assessment.get("tls_version", "Unknown")
        remediations.append({
            "priority": P1_CRITICAL,
            "timeframe": "0–30 days",
            "category": "tls",
            "title": f"Upgrade TLS — {endpoint}",
            "description": (
                f"Upgrade web server configuration to enforce TLS 1.3 minimum. "
                f"Currently negotiating {tls_ver}, which is deprecated and "
                f"cannot support PQC extensions. Legacy protocols cannot "
                f"negotiate post-quantum key exchange groups."
            ),
            "actions": [
                f"Disable {tls_ver} on the server immediately.",
                "Disable SSLv3, TLS 1.0, and TLS 1.1 in the server configuration.",
                "Configure TLS 1.3 as the minimum accepted version.",
                "Update server software (OpenSSL ≥ 1.1.1, Nginx ≥ 1.13, Apache ≥ 2.4.36).",
                "Test with: openssl s_client -connect {target}:{port} -tls1_3",
                "Verify no legacy fallback: openssl s_client -connect {target}:{port} -tls1",
                "Update load balancer / reverse proxy TLS termination settings.",
            ],
            "references": [
                "RFC 8996 — Deprecating TLS 1.0 and TLS 1.1",
                "RFC 8446 — TLS 1.3 Protocol Specification",
                "NIST SP 800-52 Rev. 2 — Guidelines for TLS Implementations",
            ],
            "impact": (
                "Without TLS 1.3, this endpoint cannot negotiate PQC hybrid key exchange. "
                "All traffic remains fully vulnerable to Harvest-Now-Decrypt-Later attacks. "
                "Legacy TLS versions also have known protocol-level vulnerabilities "
                "(POODLE, BEAST, LUCKY13)."
            ),
        })

    # ── 2.  Key Exchange Remediation ─────────────────────────────────────
    kex_status = assessment.get("key_exchange_status", "VULNERABLE")
    kex_algo = assessment.get("key_exchange_algorithm", "Unknown")

    if kex_status == "VULNERABLE":
        remediations.append({
            "priority": P1_CRITICAL,
            "timeframe": "0–60 days",
            "category": "key_exchange",
            "title": f"Enable PQC Key Exchange — {endpoint}",
            "description": (
                f"Data-in-transit is vulnerable to Harvest-Now-Decrypt-Later attacks. "
                f"The current key exchange ({kex_algo}) uses classical cryptography "
                f"that will be broken by Shor's algorithm on a quantum computer. "
                f"Upgrade key exchange to a Hybrid PQC group (e.g., X25519+MLKEM768)."
            ),
            "actions": [
                "Ensure TLS 1.3 is enabled (prerequisite for PQC groups).",
                "Upgrade OpenSSL to version 3.5+ (includes ML-KEM support).",
                "For Nginx: set ssl_ecdh_curve to 'X25519MLKEM768:X25519:P-256'.",
                "For Apache: set SSLOpenSSLConfCmd Groups 'X25519MLKEM768:X25519:P-256'.",
                "For Cloudflare: enable PQC in dashboard → SSL/TLS → Edge Certificates.",
                "For AWS ALB/CloudFront: PQC hybrid is enabled by default with s2n-tls.",
                "Test with: openssl s_client -connect {target}:{port} -groups X25519MLKEM768",
                "Verify: look for 'Server Temp Key: X25519MLKEM768' in output.",
            ],
            "references": [
                "NIST FIPS 203 — ML-KEM (Module-Lattice Key Encapsulation Mechanism)",
                "IETF draft-ietf-tls-hybrid-design — Hybrid Key Exchange in TLS 1.3",
                "CNSA 2.0 — NSA Cybersecurity Advisory on PQC Migration",
            ],
            "impact": (
                "An adversary can record this endpoint's encrypted traffic today. When a "
                "Cryptographically Relevant Quantum Computer (CRQC) is available (estimated "
                "2030–2035), all recorded sessions can be decrypted, exposing sensitive "
                "banking data, API keys, customer PII, and financial transactions."
            ),
        })
    elif kex_status == "HYBRID":
        remediations.append({
            "priority": P4_LOW,
            "timeframe": "180–365 days",
            "category": "key_exchange",
            "title": f"Migrate to Pure PQC KEX — {endpoint}",
            "description": (
                f"Key exchange ({kex_algo}) uses hybrid classical+PQC mode — good transitional "
                f"protection. Plan migration to pure ML-KEM when ecosystem support matures."
            ),
            "actions": [
                "Monitor NIST and IETF for finalization of pure PQC TLS groups.",
                "Test pure ML-KEM-768 key exchange when server/client support is available.",
                "Update key exchange preference order to prioritize pure PQC over hybrid.",
                "Validate that all client libraries support the pure PQC groups.",
            ],
            "references": [
                "NIST FIPS 203 — ML-KEM",
            ],
            "impact": (
                "Hybrid mode provides quantum safety but carries overhead of dual key exchange. "
                "Pure PQC migration is a performance optimization, not a security urgency."
            ),
        })

    # ── 3.  Certificate Remediation ──────────────────────────────────────
    cert_status = assessment.get("certificate_status", "VULNERABLE")
    cert_algo = assessment.get("certificate_algorithm", "Unknown")

    if cert_status == "VULNERABLE":
        remediations.append({
            "priority": P2_HIGH,
            "timeframe": "60–180 days",
            "category": "certificate",
            "title": f"Migrate to PQC Certificate — {endpoint}",
            "description": (
                f"Authentication is currently classical ({cert_algo}). "
                f"Plan migration to ML-DSA (FIPS 204) hybrid certificates "
                f"as CA support becomes available. A quantum computer could "
                f"forge certificates signed with {cert_algo}."
            ),
            "actions": [
                "Contact your Certificate Authority about ML-DSA certificate availability.",
                "Request a hybrid certificate (classical + ML-DSA) when offered.",
                "If using RSA: ensure minimum RSA-2048 until PQC certificates are available.",
                "If using ECDSA: continue with P-384 minimum until PQC migration.",
                "Monitor Let's Encrypt, DigiCert, and Google Trust Services for PQC CA support.",
                "Test with draft ML-DSA certificates in staging environments.",
                "Plan for larger certificate sizes (ML-DSA signatures are ~2.5KB vs ~256B for ECDSA).",
            ],
            "references": [
                "NIST FIPS 204 — ML-DSA (Module-Lattice Digital Signature Algorithm)",
                "NIST FIPS 205 — SLH-DSA (Stateless Hash-Based Digital Signature Algorithm)",
                "IETF draft-ietf-lamps-dilithium-certificates — X.509 ML-DSA Certificates",
            ],
            "impact": (
                "While certificate forgery requires a real-time quantum attack (not HNDL), "
                "the migration timeline for certificates is longer due to CA ecosystem "
                "dependencies. Start planning now to avoid being caught unprepared."
            ),
        })

    # ── 4.  Symmetric Cipher Remediation ─────────────────────────────────
    if assessment.get("symmetric_cipher_status") == "FAIL":
        cipher = assessment.get("symmetric_cipher", "Unknown")
        bits = assessment.get("symmetric_bits", 0)

        if bits > 0 and bits < 256 and "AES" in cipher.upper():
            # AES-128 case (weakened)
            remediations.append({
                "priority": P3_MEDIUM,
                "timeframe": "30–90 days",
                "category": "symmetric",
                "title": f"Upgrade to AES-256 — {endpoint}",
                "description": (
                    f"Currently using {cipher} with {bits}-bit key. Grover's algorithm "
                    f"reduces effective security to {bits // 2} bits. CNSA 2.0 mandates "
                    f"AES-256 minimum for post-quantum compliance."
                ),
                "actions": [
                    "Configure server to prefer AES-256-GCM or ChaCha20-Poly1305.",
                    "For TLS 1.3: prefer TLS_AES_256_GCM_SHA384 cipher suite.",
                    "For TLS 1.2: prefer ECDHE-RSA-AES256-GCM-SHA384.",
                    "Disable AES-128 cipher suites in server configuration.",
                    "Test performance impact (AES-256 is ~40% slower but negligible on modern CPUs with AES-NI).",
                ],
                "references": [
                    "CNSA 2.0 Suite — NSA guidance mandating AES-256",
                    "NIST SP 800-131A Rev. 2 — Transitioning Cryptographic Algorithms",
                ],
                "impact": (
                    "AES-128 provides only 64-bit effective security against a quantum "
                    "adversary using Grover's algorithm. While not immediately broken, "
                    "it falls below the 128-bit minimum security threshold."
                ),
            })
        else:
            # Broken cipher (3DES, RC4, NULL, etc.)
            remediations.append({
                "priority": P1_CRITICAL,
                "timeframe": "0–14 days",
                "category": "symmetric",
                "title": f"Replace Broken Cipher — {endpoint}",
                "description": (
                    f"Cipher {cipher} ({bits}-bit) is classically broken or severely "
                    f"weak. Immediately replace with AES-256-GCM or ChaCha20-Poly1305."
                ),
                "actions": [
                    "Immediately disable 3DES, RC4, and NULL cipher suites.",
                    "Configure AES-256-GCM as the primary cipher.",
                    "Enable ChaCha20-Poly1305 as an alternative.",
                    "Re-test: openssl s_client -connect {target}:{port} -cipher 'HIGH:!aNULL:!MD5:!3DES:!RC4'",
                ],
                "references": [
                    "RFC 7465 — Prohibiting RC4 Cipher Suites",
                    "NIST SP 800-131A — Deprecating 3DES",
                ],
                "impact": (
                    "These ciphers are already classically broken. "
                    "Data confidentiality is compromised even without a quantum computer."
                ),
            })

    # ── 5.  HNDL-Specific Warning ────────────────────────────────────────
    if assessment.get("hndl_vulnerable") and kex_status == "VULNERABLE":
        # Already covered by key exchange remediation, add extra emphasis
        if not any(r.get("category") == "hndl_advisory" for r in remediations):
            remediations.append({
                "priority": P2_HIGH,
                "timeframe": "Ongoing",
                "category": "hndl_advisory",
                "title": f"HNDL Advisory — {endpoint}",
                "description": (
                    "This endpoint is actively vulnerable to Harvest-Now, Decrypt-Later attacks. "
                    "All encrypted traffic can be recorded by adversaries for future quantum "
                    "decryption. Financial data, authentication tokens, and PII are at risk."
                ),
                "actions": [
                    "Prioritize PQC key exchange migration (see key exchange remediation above).",
                    "Assess data sensitivity classification for traffic transiting this endpoint.",
                    "Consider network segmentation to limit exposure of highest-sensitivity flows.",
                    "Implement additional application-layer encryption for critical data.",
                    "Document HNDL risk in your organization's quantum threat register.",
                ],
                "references": [
                    "NIST IR 8413 — Status Report on Quantum Computing and PQC",
                    "NSA CNSA 2.0 — Commercial National Security Algorithm Suite 2.0",
                    "CISA Quantum Readiness — Post-Quantum Cryptography Initiative",
                ],
                "impact": (
                    "Nation-state adversaries are believed to be actively harvesting "
                    "encrypted traffic for future quantum decryption. Financial institutions "
                    "are primary targets. The window for retroactive decryption depends on "
                    "CRQC development timelines (estimated 2030–2035)."
                ),
            })

    # Sort by priority
    remediations.sort(key=lambda r: _PRIORITY_ORDER.get(r.get("priority", P4_LOW), 99))

    return remediations


# ───────────────────────────────────────────────────────────────────────────
# Batch Remediation
# ───────────────────────────────────────────────────────────────────────────

def generate_batch_remediation(batch_assessment: Dict[str, Any]) -> Dict[str, Any]:
    """Generate consolidated remediation for all assessed endpoints.

    Parameters
    ----------
    batch_assessment : dict
        The output of ``analyze_batch()`` from the assessment engine.

    Returns
    -------
    dict
        - ``total_remediations``   : int
        - ``by_priority``          : dict  (count per priority)
        - ``by_category``          : dict  (count per category)
        - ``critical_actions``     : list[dict]  (P1 items)
        - ``strategic_roadmap``    : list[dict]  (all, grouped by phase)
        - ``per_endpoint``         : dict  {target: list[dict]}
    """
    all_remediations: Dict[str, List[Dict[str, Any]]] = {}
    all_flat: List[Dict[str, Any]] = []

    for a in batch_assessment.get("assessments", []):
        target = a.get("target", "unknown")
        port = a.get("port", 443)
        endpoint = f"{target}:{port}"

        rems = generate_remediation(a)
        all_remediations[endpoint] = rems
        all_flat.extend(rems)

    # Count by priority
    by_priority = {}
    for r in all_flat:
        p = r.get("priority", P4_LOW)
        by_priority[p] = by_priority.get(p, 0) + 1

    # Count by category
    by_category = {}
    for r in all_flat:
        c = r.get("category", "other")
        by_category[c] = by_category.get(c, 0) + 1

    # Critical actions (P1)
    critical = [r for r in all_flat if r.get("priority") == P1_CRITICAL]

    # Strategic roadmap by timeframe
    phases = [
        {"phase": "Immediate (0–30 days)", "actions": [], "priority": P1_CRITICAL},
        {"phase": "Short-Term (30–90 days)", "actions": [], "priority": P2_HIGH},
        {"phase": "Medium-Term (90–180 days)", "actions": [], "priority": P3_MEDIUM},
        {"phase": "Strategic (180–365 days)", "actions": [], "priority": P4_LOW},
    ]

    for r in all_flat:
        p = r.get("priority", P4_LOW)
        if p == P1_CRITICAL:
            phases[0]["actions"].append(r)
        elif p == P2_HIGH:
            phases[1]["actions"].append(r)
        elif p == P3_MEDIUM:
            phases[2]["actions"].append(r)
        else:
            phases[3]["actions"].append(r)

    # Deduplicate roadmap titles within each phase
    for phase in phases:
        seen_titles = set()
        deduped = []
        for action in phase["actions"]:
            title = action.get("title", "")
            if title not in seen_titles:
                seen_titles.add(title)
                deduped.append(action)
        phase["actions"] = deduped

    return {
        "total_remediations": len(all_flat),
        "by_priority": by_priority,
        "by_category": by_category,
        "critical_actions": critical,
        "strategic_roadmap": [p for p in phases if p["actions"]],
        "per_endpoint": all_remediations,
    }
