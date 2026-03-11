"""Phase 7 — Crypto-Agility Assessment Engine.

Evaluates how easily an asset can migrate to PQC algorithms.
Five indicators, each worth 3 points → max agility score = 15.

Indicators
──────────
1. TLS Termination Centralisation  (CDN / reverse proxy)     … 3 pts
2. Software Currency               (TLS library freshness)    … 3 pts
3. Certificate Lifecycle Automation (ACME CA issuer)          … 3 pts
4. Protocol Flexibility             (TLS 1.3 in Probe B)     … 3 pts
5. Algorithm Diversity Readiness    (multiple SAN hostnames)  … 3 pts

Usage
─────
    from backend.scanner.agility_assessor import assess_agility
    score, details = assess_agility(trimode_fingerprint)
"""

from __future__ import annotations

import logging
from typing import Tuple

from backend.models import TriModeFingerprint

logger = logging.getLogger("qarmor.agility")

# Known CDN / reverse-proxy providers detected from certificate issuers
_CDN_ISSUERS = frozenset({
    "cloudflare", "akamai", "fastly", "incapsula", "imperva",
    "aws", "amazon", "google trust", "google internet",
    "azure", "microsoft", "edgecast", "stackpath", "sucuri",
    "letsencrypt", "let's encrypt",
})

# ACME-capable CA issuers (automate certificate renewal)
_ACME_CAS = frozenset({
    "let's encrypt", "letsencrypt", "zerossl", "buypass",
    "google trust", "pebble", "step ca", "smallstep",
    "digicert", "sectigo",
})


def assess_agility(fp: TriModeFingerprint) -> Tuple[int, list[dict]]:
    """Compute a crypto-agility score for a single asset.

    Returns
    -------
    (score, details)
        score   : int 0-15
        details : list of dicts with keys {indicator, points, max, reason}
    """
    details: list[dict] = []
    total = 0

    # ── 1. TLS Termination Centralisation (CDN check) ──────────────────
    issuer_lower = (fp.certificate.issuer or "").lower()
    cdn_detected = any(cdn in issuer_lower for cdn in _CDN_ISSUERS)
    pts = 3 if cdn_detected else 0
    total += pts
    details.append({
        "indicator": "TLS Termination Centralisation",
        "points": pts,
        "max": 3,
        "reason": f"CDN/reverse-proxy detected ({issuer_lower.split('cn=')[-1][:40]})" if cdn_detected
                  else "No CDN detected — TLS terminates at origin",
    })

    # ── 2. Software Currency (TLS library version within 18mo) ─────────
    # Heuristic: if server negotiates TLS 1.3 in Probe A, the library is
    # reasonably modern.  If only TLS 1.2, it's likely older than 18 months.
    probe_a_tls = (fp.probe_a.tls_version or "")
    modern_library = "1.3" in probe_a_tls
    pts = 3 if modern_library else 0
    total += pts
    details.append({
        "indicator": "Software Currency",
        "points": pts,
        "max": 3,
        "reason": "TLS 1.3 negotiated — library is current" if modern_library
                  else f"TLS library appears outdated ({probe_a_tls or 'unknown'})",
    })

    # ── 3. Certificate Lifecycle Automation (ACME CA) ──────────────────
    acme_detected = any(ca in issuer_lower for ca in _ACME_CAS)
    pts = 3 if acme_detected else 0
    total += pts
    details.append({
        "indicator": "Certificate Lifecycle Automation",
        "points": pts,
        "max": 3,
        "reason": "ACME-capable CA detected — automated renewal possible" if acme_detected
                  else "Non-ACME CA — manual certificate renewal likely required",
    })

    # ── 4. Protocol Flexibility (TLS 1.3 in Probe B) ──────────────────
    probe_b_tls = (fp.probe_b.tls_version or "")
    tls13_in_b = "1.3" in probe_b_tls
    pts = 3 if tls13_in_b else 0
    total += pts
    details.append({
        "indicator": "Protocol Flexibility",
        "points": pts,
        "max": 3,
        "reason": "TLS 1.3 negotiated in classical Probe B — ready for PQC groups" if tls13_in_b
                  else f"Probe B negotiated {probe_b_tls or 'unknown'} — limited PQC extensibility",
    })

    # ── 5. Algorithm Diversity Readiness (SAN diversity) ───────────────
    san_count = len(fp.certificate.san_entries) if fp.certificate.san_entries else 0
    diverse_san = san_count >= 2
    pts = 3 if diverse_san else 0
    total += pts
    details.append({
        "indicator": "Algorithm Diversity Readiness",
        "points": pts,
        "max": 3,
        "reason": f"{san_count} SAN entries — multi-hostname cert supports staged rollout" if diverse_san
                  else "Single SAN — limited rollout flexibility",
    })

    return total, details
