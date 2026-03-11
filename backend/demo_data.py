"""Phase 6 Demo Data — 21 TriModeFingerprint objects + backward-compatible helpers.

Core philosophy: These fingerprints are the ONLY hardcoded values.  All downstream
processing (scoring, labeling, CBOM generation) runs on real classifier logic.
Scores, statuses, and recommendations are *computed*, never invented.

Target distribution after real classification:
  2  FULLY_QUANTUM_SAFE
  4  PQC_TRANSITION
  11 QUANTUM_VULNERABLE
  3  CRITICALLY_VULNERABLE
  1  UNKNOWN

Module-level constants.  Imports in < 200 ms.  Zero network calls.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any

from backend.models import (
    AssetType,
    CertificateInfo,
    CryptoFingerprint,
    DiscoveredAsset,
    HistoricalScanSummary,
    PQCStatus,
    ProbeProfile,
    RemediationAction,
    RemediationPriority,
    ScanResult,
    ScanSummary,
    TLSInfo,
    TriModeFingerprint,
)
from backend.scanner.classifier import classify
from backend.scanner.label_issuer import issue_label

# ── Helpers ──────────────────────────────────────────────────────────────────

_NOW = datetime.now(timezone.utc)


def _cert(
    subject: str,
    issuer: str,
    sig_algo: str,
    pk_type: str,
    pk_bits: int,
    days_until: int = 365,
    serial_override: str | None = None,
) -> CertificateInfo:
    """Build a demo CertificateInfo."""
    return CertificateInfo(
        subject=f"CN={subject}",
        issuer=f"CN={issuer}",
        serial_number=serial_override or f"0x{abs(hash(subject)) & 0xFFFFFFFFFFFF:012X}",
        not_before=(_NOW - timedelta(days=90)).strftime("%b %d %H:%M:%S %Y GMT"),
        not_after=(_NOW + timedelta(days=days_until)).strftime("%b %d %H:%M:%S %Y GMT"),
        signature_algorithm=sig_algo,
        public_key_type=pk_type,
        public_key_bits=pk_bits,
        san_entries=[subject],
        is_expired=days_until < 0,
        days_until_expiry=days_until,
    )


def _ip(hostname: str) -> str:
    """Deterministic demo IP from hostname."""
    return f"203.0.113.{hash(hostname) % 254 + 1}"


# ── 21 TriModeFingerprint objects ────────────────────────────────────────────

# NOTE: Probe A = PQC-capable client hello (best the server can do)
#       Probe B = TLS 1.3 classical client hello (typical behaviour)
#       Probe C = TLS 1.2 downgrade attempt (worst case)

# ─── 2 x FULLY_QUANTUM_SAFE ────────────────────────────────────────────────

_netbanking = TriModeFingerprint(
    hostname="netbanking.bank.com", port=443, asset_type=AssetType.WEB, ip=_ip("netbanking.bank.com"), mode="demo",
    probe_a=ProbeProfile(
        mode="A", tls_version="TLSv1.3", cipher_suite="TLS_AES_256_GCM_SHA384", cipher_bits=256,
        key_exchange="ML-KEM-768", key_exchange_group="ML-KEM-768",
        authentication="ML-DSA-65", signature_algorithm="ML-DSA-65",
        public_key_type="ML-DSA", public_key_bits=2048,
    ),
    probe_b=ProbeProfile(
        mode="B", tls_version="TLSv1.3", cipher_suite="TLS_AES_256_GCM_SHA384", cipher_bits=256,
        key_exchange="ML-KEM-768", key_exchange_group="ML-KEM-768",
        authentication="ML-DSA-65", signature_algorithm="ML-DSA-65",
        public_key_type="ML-DSA", public_key_bits=2048,
    ),
    probe_c=ProbeProfile(
        mode="C", tls_version="TLSv1.3", cipher_suite="TLS_AES_256_GCM_SHA384", cipher_bits=256,
        key_exchange="ML-KEM-768", key_exchange_group="ML-KEM-768",
        authentication="ML-DSA-65", signature_algorithm="ML-DSA-65",
        public_key_type="ML-DSA", public_key_bits=2048,
    ),
    certificate=_cert("netbanking.bank.com", "DigiCert PQC Root CA", "ML-DSA-65", "ML-DSA", 2048, 730),
)

_auth = TriModeFingerprint(
    hostname="auth.bank.com", port=443, asset_type=AssetType.WEB, ip=_ip("auth.bank.com"), mode="demo",
    probe_a=ProbeProfile(
        mode="A", tls_version="TLSv1.3", cipher_suite="TLS_AES_256_GCM_SHA384", cipher_bits=256,
        key_exchange="ML-KEM-768", key_exchange_group="ML-KEM-768",
        authentication="ML-DSA-65", signature_algorithm="ML-DSA-65",
        public_key_type="ML-DSA", public_key_bits=2048,
    ),
    probe_b=ProbeProfile(
        mode="B", tls_version="TLSv1.3", cipher_suite="TLS_AES_256_GCM_SHA384", cipher_bits=256,
        key_exchange="ML-KEM-768", key_exchange_group="ML-KEM-768",
        authentication="ML-DSA-65", signature_algorithm="ML-DSA-65",
        public_key_type="ML-DSA", public_key_bits=2048,
    ),
    probe_c=ProbeProfile(
        mode="C", tls_version="TLSv1.3", cipher_suite="TLS_AES_256_GCM_SHA384", cipher_bits=256,
        key_exchange="ML-KEM-768", key_exchange_group="ML-KEM-768",
        authentication="ML-DSA-65", signature_algorithm="ML-DSA-65",
        public_key_type="ML-DSA", public_key_bits=2048,
    ),
    certificate=_cert("auth.bank.com", "GlobalSign PQC CA", "ML-DSA-65", "ML-DSA", 2048, 540),
)


# ─── 4 x PQC_TRANSITION ────────────────────────────────────────────────────

def _pqc_transition_fp(hostname: str, asset_type: AssetType = AssetType.WEB) -> TriModeFingerprint:
    """X25519MLKEM768 in A, X25519 in B, TLS 1.2 downgrade in C, ECDSA-P256 cert."""
    return TriModeFingerprint(
        hostname=hostname, port=443, asset_type=asset_type, ip=_ip(hostname), mode="demo",
        probe_a=ProbeProfile(
            mode="A", tls_version="TLSv1.3", cipher_suite="TLS_AES_256_GCM_SHA384", cipher_bits=256,
            key_exchange="X25519MLKEM768", key_exchange_group="X25519MLKEM768",
            authentication="ECDSA", signature_algorithm="ecdsa-with-SHA256",
            public_key_type="EC", public_key_bits=256,
        ),
        probe_b=ProbeProfile(
            mode="B", tls_version="TLSv1.3", cipher_suite="TLS_AES_256_GCM_SHA384", cipher_bits=256,
            key_exchange="X25519", key_exchange_group="X25519",
            authentication="ECDSA", signature_algorithm="ecdsa-with-SHA256",
            public_key_type="EC", public_key_bits=256,
        ),
        probe_c=ProbeProfile(
            mode="C", tls_version="TLSv1.2", cipher_suite="TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384", cipher_bits=256,
            key_exchange="ECDHE", key_exchange_group="P-256",
            authentication="ECDSA", signature_algorithm="ecdsa-with-SHA256",
            public_key_type="EC", public_key_bits=256,
        ),
        certificate=_cert(hostname, "DigiCert ECC Extended Validation CA", "ecdsa-with-SHA256", "EC", 256, 180),
    )


_api = _pqc_transition_fp("api.bank.com", AssetType.API)
_mobileapi = _pqc_transition_fp("mobileapi.bank.com", AssetType.API)
_upi = _pqc_transition_fp("upi.bank.com", AssetType.API)
_cards = _pqc_transition_fp("cards.bank.com", AssetType.WEB)


# ─── 11 x QUANTUM_VULNERABLE ───────────────────────────────────────────────

# 6 with ECDHE KEX + RSA-2048 + TLS 1.2 across all probes
def _qv_ecdhe(hostname: str, asset_type: AssetType = AssetType.WEB) -> TriModeFingerprint:
    return TriModeFingerprint(
        hostname=hostname, port=443, asset_type=asset_type, ip=_ip(hostname), mode="demo",
        probe_a=ProbeProfile(
            mode="A", tls_version="TLSv1.2", cipher_suite="TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384", cipher_bits=256,
            key_exchange="ECDHE", key_exchange_group="P-256",
            authentication="RSA", signature_algorithm="sha256WithRSAEncryption",
            public_key_type="RSA", public_key_bits=2048,
        ),
        probe_b=ProbeProfile(
            mode="B", tls_version="TLSv1.2", cipher_suite="TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384", cipher_bits=256,
            key_exchange="ECDHE", key_exchange_group="P-256",
            authentication="RSA", signature_algorithm="sha256WithRSAEncryption",
            public_key_type="RSA", public_key_bits=2048,
        ),
        probe_c=ProbeProfile(
            mode="C", tls_version="TLSv1.2", cipher_suite="TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256", cipher_bits=128,
            key_exchange="ECDHE", key_exchange_group="P-256",
            authentication="RSA", signature_algorithm="sha256WithRSAEncryption",
            public_key_type="RSA", public_key_bits=2048,
        ),
        certificate=_cert(hostname, "GeoTrust RSA CA 2018", "sha256WithRSAEncryption", "RSA", 2048, 300),
    )


_swift = _qv_ecdhe("swift.bank.com", AssetType.API)
_imps = _qv_ecdhe("imps.bank.com", AssetType.API)
_neft = _qv_ecdhe("neft.bank.com", AssetType.API)
_fx = _qv_ecdhe("fx.bank.com", AssetType.WEB)
_trade = _qv_ecdhe("trade.bank.com", AssetType.WEB)
_custody = _qv_ecdhe("custody.bank.com", AssetType.WEB)


# 5 with RSA KEX + RSA-2048, TLS 1.3 in A+B, TLS 1.2 accepted in C
def _qv_rsa(hostname: str, asset_type: AssetType = AssetType.WEB) -> TriModeFingerprint:
    return TriModeFingerprint(
        hostname=hostname, port=443, asset_type=asset_type, ip=_ip(hostname), mode="demo",
        probe_a=ProbeProfile(
            mode="A", tls_version="TLSv1.3", cipher_suite="TLS_AES_256_GCM_SHA384", cipher_bits=256,
            key_exchange="RSA", key_exchange_group=None,
            authentication="RSA", signature_algorithm="sha256WithRSAEncryption",
            public_key_type="RSA", public_key_bits=2048,
        ),
        probe_b=ProbeProfile(
            mode="B", tls_version="TLSv1.3", cipher_suite="TLS_AES_256_GCM_SHA384", cipher_bits=256,
            key_exchange="RSA", key_exchange_group=None,
            authentication="RSA", signature_algorithm="sha256WithRSAEncryption",
            public_key_type="RSA", public_key_bits=2048,
        ),
        probe_c=ProbeProfile(
            mode="C", tls_version="TLSv1.2", cipher_suite="TLS_RSA_WITH_AES_256_GCM_SHA384", cipher_bits=256,
            key_exchange="RSA", key_exchange_group=None,
            authentication="RSA", signature_algorithm="sha256WithRSAEncryption",
            public_key_type="RSA", public_key_bits=2048,
        ),
        certificate=_cert(hostname, "DigiCert Global Root G2", "sha256WithRSAEncryption", "RSA", 2048, 400),
    )


_loans = _qv_rsa("loans.bank.com")
_corp = _qv_rsa("corp.bank.com")
_sme = _qv_rsa("sme.bank.com")
_kyc = _qv_rsa("kyc.bank.com", AssetType.API)
_cms = _qv_rsa("cms.bank.com")


# ─── 3 x CRITICALLY_VULNERABLE ─────────────────────────────────────────────

def _crit_vuln(hostname: str, asset_type: AssetType = AssetType.WEB) -> TriModeFingerprint:
    """RSA KEX + RSA-2048, TLS 1.1 accepted in probe C."""
    return TriModeFingerprint(
        hostname=hostname, port=443, asset_type=asset_type, ip=_ip(hostname), mode="demo",
        probe_a=ProbeProfile(
            mode="A", tls_version="TLSv1.2", cipher_suite="TLS_RSA_WITH_AES_256_CBC_SHA256", cipher_bits=256,
            key_exchange="RSA", key_exchange_group=None,
            authentication="RSA", signature_algorithm="sha256WithRSAEncryption",
            public_key_type="RSA", public_key_bits=2048,
        ),
        probe_b=ProbeProfile(
            mode="B", tls_version="TLSv1.2", cipher_suite="TLS_RSA_WITH_AES_128_CBC_SHA", cipher_bits=128,
            key_exchange="RSA", key_exchange_group=None,
            authentication="RSA", signature_algorithm="sha256WithRSAEncryption",
            public_key_type="RSA", public_key_bits=2048,
        ),
        probe_c=ProbeProfile(
            mode="C", tls_version="TLSv1.1", cipher_suite="TLS_RSA_WITH_AES_128_CBC_SHA", cipher_bits=128,
            key_exchange="RSA", key_exchange_group=None,
            authentication="RSA", signature_algorithm="sha1WithRSAEncryption",
            public_key_type="RSA", public_key_bits=2048,
        ),
        certificate=_cert(hostname, "Internal CA", "sha1WithRSAEncryption", "RSA", 2048, 45),
    )


_vpn = _crit_vuln("vpn.bank.com", AssetType.VPN)
_reporting = _crit_vuln("reporting.bank.com")
_legacy = _crit_vuln("legacy.bank.com")


# ─── 1 x UNKNOWN ───────────────────────────────────────────────────────────

_staging = TriModeFingerprint(
    hostname="staging.bank.com", port=443, asset_type=AssetType.WEB, ip=_ip("staging.bank.com"), mode="demo",
    probe_a=ProbeProfile(mode="A", error="Connection timeout after 10s"),
    probe_b=ProbeProfile(mode="B", error="Connection timeout after 10s"),
    probe_c=ProbeProfile(mode="C", error="Connection timeout after 10s"),
    certificate=CertificateInfo(),
    error="Connection timeout after 10s",
)


# ── Module-Level Constants ───────────────────────────────────────────────────

DEMO_TRIMODE_FINGERPRINTS: list[TriModeFingerprint] = [
    # 2 Fully Quantum Safe
    _netbanking, _auth,
    # 4 PQC Transition
    _api, _mobileapi, _upi, _cards,
    # 6 QV ECDHE
    _swift, _imps, _neft, _fx, _trade, _custody,
    # 5 QV RSA
    _loans, _corp, _sme, _kyc, _cms,
    # 3 Critically Vulnerable
    _vpn, _reporting, _legacy,
    # 1 Unknown
    _staging,
]

assert len(DEMO_TRIMODE_FINGERPRINTS) == 21, f"Expected 21 fingerprints, got {len(DEMO_TRIMODE_FINGERPRINTS)}"


# ── get_demo_baseline_fingerprints ───────────────────────────────────────────

def get_demo_baseline_fingerprints() -> list[TriModeFingerprint]:
    """Return a slightly degraded baseline (one-week-ago scan).

    Differences from current:
      - 4 assets degraded: probe_c weakened by one tier
      - imps.bank.com and kyc.bank.com removed (not yet discovered)
      - neft.bank.com has a different certificate serial number
    """
    excluded = {"imps.bank.com", "kyc.bank.com"}
    degraded_hosts = {"swift.bank.com", "fx.bank.com", "trade.bank.com", "custody.bank.com"}

    baseline: list[TriModeFingerprint] = []
    for fp in DEMO_TRIMODE_FINGERPRINTS:
        if fp.hostname in excluded:
            continue

        copy = fp.model_copy(deep=True)

        if fp.hostname in degraded_hosts and copy.probe_c:
            old_c = copy.probe_c
            copy.probe_c = ProbeProfile(
                mode="C",
                tls_version="TLSv1.1" if old_c.tls_version == "TLSv1.2" else old_c.tls_version,
                cipher_suite="TLS_RSA_WITH_AES_128_CBC_SHA",
                cipher_bits=128,
                key_exchange="RSA",
                key_exchange_group=None,
                authentication="RSA",
                signature_algorithm=old_c.signature_algorithm,
                public_key_type=old_c.public_key_type,
                public_key_bits=old_c.public_key_bits,
            )

        if fp.hostname == "neft.bank.com":
            copy.certificate = copy.certificate.model_copy(
                update={"serial_number": "0xBASELINE00NEFT"}
            )

        baseline.append(copy)

    return baseline


# ── get_historical_scan_summaries ────────────────────────────────────────────

def get_historical_scan_summaries() -> list[HistoricalScanSummary]:
    """Return 4 pre-built historical scan summaries (weeks 1-4).

    Quantum safety scores: 12 -> 18 -> 21 -> 24 (improving trend).
    All marked mode='demo'.
    """
    base_date = _NOW - timedelta(weeks=4)
    return [
        HistoricalScanSummary(
            week=1, scan_date=(base_date).isoformat().replace("+00:00", "Z"),
            total_assets=18, quantum_safety_score=12,
            fully_quantum_safe=0, pqc_transition=2, quantum_vulnerable=12,
            critically_vulnerable=3, unknown=1, mode="demo",
        ),
        HistoricalScanSummary(
            week=2, scan_date=(base_date + timedelta(weeks=1)).isoformat().replace("+00:00", "Z"),
            total_assets=19, quantum_safety_score=18,
            fully_quantum_safe=1, pqc_transition=3, quantum_vulnerable=11,
            critically_vulnerable=3, unknown=1, mode="demo",
        ),
        HistoricalScanSummary(
            week=3, scan_date=(base_date + timedelta(weeks=2)).isoformat().replace("+00:00", "Z"),
            total_assets=20, quantum_safety_score=21,
            fully_quantum_safe=2, pqc_transition=3, quantum_vulnerable=11,
            critically_vulnerable=3, unknown=1, mode="demo",
        ),
        HistoricalScanSummary(
            week=4, scan_date=(base_date + timedelta(weeks=3)).isoformat().replace("+00:00", "Z"),
            total_assets=21, quantum_safety_score=24,
            fully_quantum_safe=2, pqc_transition=4, quantum_vulnerable=11,
            critically_vulnerable=3, unknown=1, mode="demo",
        ),
    ]


# ── Backward-compatible bridge: TriModeFingerprint -> CryptoFingerprint ──────

def _trimode_to_crypto(fp: TriModeFingerprint) -> CryptoFingerprint:
    """Convert a Phase 6 TriModeFingerprint into a Phase 1-5 CryptoFingerprint.

    Uses Probe A (best case) as the primary TLS info for legacy scoring.
    """
    a = fp.probe_a
    tls = TLSInfo(
        version=a.tls_version or "",
        cipher_suite=a.cipher_suite or "",
        cipher_bits=a.cipher_bits or 0,
        cipher_algorithm="AES",
        key_exchange=a.key_exchange or "",
        authentication=a.authentication or "",
        supports_tls_1_2=any(
            p.tls_version and "1.2" in p.tls_version
            for p in [fp.probe_a, fp.probe_b, fp.probe_c]
        ),
        supports_tls_1_3=any(
            p.tls_version and "1.3" in p.tls_version
            for p in [fp.probe_a, fp.probe_b, fp.probe_c]
        ),
        supports_tls_1_1=any(
            p.tls_version and "1.1" in p.tls_version
            for p in [fp.probe_a, fp.probe_b, fp.probe_c]
        ),
        supports_tls_1_0=any(
            p.tls_version and "1.0" in p.tls_version
            for p in [fp.probe_a, fp.probe_b, fp.probe_c]
        ),
    )

    kex = (a.key_exchange or "").upper()
    sig = (fp.certificate.signature_algorithm or "").upper()
    pqc_kex_names = {"ML-KEM", "MLKEM", "KYBER", "X25519MLKEM768", "X25519KYBER768"}
    pqc_sig_names = {"ML-DSA", "MLDSA", "SLH-DSA"}

    has_pqc_kex = any(n in kex for n in pqc_kex_names)
    has_pqc_sig = any(n in sig for n in pqc_sig_names)
    has_hybrid = "X25519" in kex and has_pqc_kex
    has_fs = any(k in kex for k in ("DHE", "ECDHE", "X25519", "X448", "MLKEM", "KYBER"))

    return CryptoFingerprint(
        tls=tls,
        certificate=fp.certificate,
        has_pqc_kex=has_pqc_kex,
        has_pqc_signature=has_pqc_sig,
        has_hybrid_mode=has_hybrid,
        has_forward_secrecy=has_fs,
    )


# ── generate_demo_results (backward-compatible Phase 1-5 API) ───────────────

def generate_demo_results() -> ScanSummary:
    """Generate realistic demo scan results from Phase 6 TriModeFingerprints.

    This bridges Phase 6 data into the Phase 1-5 ScanSummary format so
    all existing endpoints (/api/scan/demo, /api/cbom, etc.) keep working.
    """
    results: list[ScanResult] = []

    for fp in DEMO_TRIMODE_FINGERPRINTS:
        crypto = _trimode_to_crypto(fp)
        q = classify(crypto)

        asset = DiscoveredAsset(
            hostname=fp.hostname,
            ip=fp.ip or _ip(fp.hostname),
            port=fp.port,
            asset_type=fp.asset_type,
            discovery_method="demo",
        )

        results.append(ScanResult(
            asset=asset,
            fingerprint=crypto,
            q_score=q,
            scan_duration_ms=150 + (len(fp.hostname) * 17) % 500,
        ))

    counts = {s: 0 for s in PQCStatus}
    total_score = 0
    for r in results:
        counts[r.q_score.status] += 1
        total_score += r.q_score.total

    labels = []
    for r in results:
        label = issue_label(r.asset.hostname, r.asset.port, r.q_score)
        if label:
            labels.append(label)

    remediation = _build_remediation_roadmap(results)

    return ScanSummary(
        total_assets=len(results),
        fully_quantum_safe=counts[PQCStatus.FULLY_QUANTUM_SAFE],
        pqc_transition=counts[PQCStatus.PQC_TRANSITION],
        quantum_vulnerable=counts[PQCStatus.QUANTUM_VULNERABLE],
        critically_vulnerable=counts[PQCStatus.CRITICALLY_VULNERABLE],
        unknown=counts.get(PQCStatus.UNKNOWN, 0),
        average_q_score=round(total_score / len(results), 1) if results else 0.0,
        results=results,
        remediation_roadmap=remediation,
        labels=labels,
    )


# ── Remediation roadmap builder ──────────────────────────────────────────────

def _build_remediation_roadmap(results: list[ScanResult]) -> list[RemediationAction]:
    """Build prioritized remediation actions from scan results."""
    critical = [r for r in results if r.q_score.status == PQCStatus.CRITICALLY_VULNERABLE]
    vulnerable = [r for r in results if r.q_score.status == PQCStatus.QUANTUM_VULNERABLE]
    transition = [r for r in results if r.q_score.status == PQCStatus.PQC_TRANSITION]

    actions: list[RemediationAction] = []

    if critical:
        actions.append(RemediationAction(
            priority=RemediationPriority.IMMEDIATE,
            timeframe="0-30 days",
            description="Disable deprecated TLS versions and replace weak keys",
            affected_assets=[f"{r.asset.hostname}:{r.asset.port}" for r in critical],
            specific_actions=[
                "Disable TLS 1.0 and TLS 1.1 on all servers",
                "Replace RSA-1024 keys with RSA-2048 minimum",
                "Remove 3DES and RC4 cipher suites",
                "Renew expired certificates immediately",
                "Replace SHA-1 and MD5 certificate signatures",
            ],
        ))

    vulnerable_tls12 = [r for r in vulnerable if r.fingerprint.tls.version == "TLSv1.2"]
    if vulnerable_tls12:
        actions.append(RemediationAction(
            priority=RemediationPriority.SHORT_TERM,
            timeframe="31-90 days",
            description="Migrate to TLS 1.3 with forward secrecy",
            affected_assets=[f"{r.asset.hostname}:{r.asset.port}" for r in vulnerable_tls12],
            specific_actions=[
                "Upgrade server TLS configuration to support TLS 1.3",
                "Enable ECDHE for forward secrecy on remaining TLS 1.2 connections",
                "Prefer AES-256-GCM over AES-128 cipher suites",
                "Configure server to prefer TLS 1.3 in cipher ordering",
            ],
        ))

    vulnerable_tls13 = [r for r in vulnerable if r.fingerprint.tls.version == "TLSv1.3"]
    if vulnerable_tls13:
        actions.append(RemediationAction(
            priority=RemediationPriority.MEDIUM_TERM,
            timeframe="91-180 days",
            description="Enable PQC hybrid key exchange",
            affected_assets=[f"{r.asset.hostname}:{r.asset.port}" for r in vulnerable_tls13],
            specific_actions=[
                "Enable X25519+ML-KEM-768 hybrid key exchange (supported in OpenSSL 3.2+)",
                "Test hybrid handshake compatibility with clients",
                "Request ML-DSA certificate from CA when available",
                "Monitor NIST post-quantum algorithm implementations in your TLS library",
            ],
        ))

    if transition:
        actions.append(RemediationAction(
            priority=RemediationPriority.STRATEGIC,
            timeframe="180-365 days",
            description="Complete PQC migration to full ML-KEM + ML-DSA",
            affected_assets=[f"{r.asset.hostname}:{r.asset.port}" for r in transition],
            specific_actions=[
                "Replace hybrid key exchange with pure ML-KEM-768 or ML-KEM-1024",
                "Deploy ML-DSA certificates for all services",
                "Update JWT signing to use ML-DSA algorithms",
                "Validate end-to-end quantum safety with full PQC stack",
            ],
        ))

    return actions
