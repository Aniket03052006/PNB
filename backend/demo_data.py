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
    hostname="netbanking.pnb.bank.in", port=443, asset_type=AssetType.WEB, ip=_ip("netbanking.pnb.bank.in"), mode="demo",
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
    certificate=_cert("netbanking.pnb.bank.in", "DigiCert PQC Root CA", "ML-DSA-65", "ML-DSA", 2048, 730),
)

_auth = TriModeFingerprint(
    hostname="auth.pnb.bank.in", port=443, asset_type=AssetType.WEB, ip=_ip("auth.pnb.bank.in"), mode="demo",
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
    certificate=_cert("auth.pnb.bank.in", "GlobalSign PQC CA", "ML-DSA-65", "ML-DSA", 2048, 540),
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


_api = _pqc_transition_fp("api.pnb.bank.in", AssetType.API)
_mobileapi = _pqc_transition_fp("mobileapi.pnb.bank.in", AssetType.API)
_upi = _pqc_transition_fp("upi.pnb.bank.in", AssetType.API)
_cards = _pqc_transition_fp("cards.pnb.bank.in", AssetType.WEB)


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


_swift = _qv_ecdhe("swift.pnb.bank.in", AssetType.API)
_imps = _qv_ecdhe("imps.pnb.bank.in", AssetType.API)
_neft = _qv_ecdhe("neft.pnb.bank.in", AssetType.API)
_fx = _qv_ecdhe("fx.pnb.bank.in", AssetType.WEB)
_trade = _qv_ecdhe("trade.pnb.bank.in", AssetType.WEB)
_custody = _qv_ecdhe("custody.pnb.bank.in", AssetType.WEB)


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


_loans = _qv_rsa("loans.pnb.bank.in")
_corp = _qv_rsa("corp.pnb.bank.in")
_sme = _qv_rsa("sme.pnb.bank.in")
_kyc = _qv_rsa("kyc.pnb.bank.in", AssetType.API)
_cms = _qv_rsa("cms.pnb.bank.in")


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


_vpn = _crit_vuln("vpn.pnb.bank.in", AssetType.VPN)
_reporting = _crit_vuln("reporting.pnb.bank.in")
_legacy = _crit_vuln("legacy.pnb.bank.in")


# ─── 1 x UNKNOWN ───────────────────────────────────────────────────────────

_staging = TriModeFingerprint(
    hostname="staging.pnb.bank.in", port=443, asset_type=AssetType.WEB, ip=_ip("staging.pnb.bank.in"), mode="demo",
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
      - imps.pnb.bank.in and kyc.pnb.bank.in removed (not yet discovered)
      - neft.pnb.bank.in has a different certificate serial number
    """
    excluded = {"imps.pnb.bank.in", "kyc.pnb.bank.in"}
    degraded_hosts = {"swift.pnb.bank.in", "fx.pnb.bank.in", "trade.pnb.bank.in", "custody.pnb.bank.in"}

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

        if fp.hostname == "neft.pnb.bank.in":
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


def get_demo_domain_assets() -> list[dict[str, str]]:
    """Return synthetic domain intelligence records for dashboard views."""
    detection_date = _NOW.date().isoformat()
    records = [
        {
            "domain_name": "proxy.pnb.bank.in",
            "registration_date": "2019-02-11",
            "status": "new",
        },
        {
            "domain_name": "postman.pnb.bank.in",
            "registration_date": "2020-08-22",
            "status": "confirmed",
        },
        {
            "domain_name": "upload.pnbuniv.net.in",
            "registration_date": "2021-03-14",
            "status": "false_positive",
        },
        {
            "domain_name": "www2.pnbrrbkiosk.in",
            "registration_date": "2018-12-05",
            "status": "new",
        },
        {
            "domain_name": "www.cos.pnb.bank.in",
            "registration_date": "2022-07-18",
            "status": "confirmed",
        },
    ]

    return [
        {
            "detection_date": detection_date,
            "domain_name": row["domain_name"],
            "registration_date": row["registration_date"],
            "registrar": "National Internet Exchange of India",
            "company_name": "PNB",
            "status": row["status"],
        }
        for row in records
    ]


def get_demo_ssl_assets() -> list[dict[str, str]]:
    """Return synthetic certificate-fingerprint asset records."""
    detection_date = _NOW.date().isoformat()
    return [
        {
            "detection_date": detection_date,
            "ssl_sha_fingerprint": "5f3a9c8d2e1b4f60718293a4b5c6d7e8f9a0b1c2",
            "valid_from": "2025-01-10",
            "common_name": "Generic Cert for WF Ovrd",
            "company_name": "PNB",
            "certificate_authority": "Symantec",
        },
        {
            "detection_date": detection_date,
            "ssl_sha_fingerprint": "0a1b2c3d4e5f67890123456789abcdef01234567",
            "valid_from": "2025-05-04",
            "common_name": "Generic Cert for WF Ovrd",
            "company_name": "PNB",
            "certificate_authority": "DigiCert",
        },
        {
            "detection_date": detection_date,
            "ssl_sha_fingerprint": "abcdef1234567890fedcba09876543210fedcba9",
            "valid_from": "2024-11-30",
            "common_name": "Generic Cert for WF Ovrd",
            "company_name": "PNB",
            "certificate_authority": "Entrust",
        },
    ]


def get_demo_ip_assets() -> list[dict[str, Any]]:
    """Return synthetic network-IP intelligence records."""
    detection_date = _NOW.date().isoformat()
    rows = [
        ("103.107.224.11", [443, 8443], "MSFT", "India"),
        ("103.107.224.29", [443, 4443], "MSFT", "Nashik India"),
        ("103.107.224.44", [443, 9443], "Quantum-Link-Co", "Chennai India"),
        ("103.107.224.63", [443], "E2E-Networks-IN", "Leh India"),
        ("103.107.225.15", [443, 5443], "MSFT", "India"),
        ("103.107.225.87", [443, 8080], "Quantum-Link-Co", "Nashik India"),
        ("103.107.226.38", [443, 10443], "E2E-Networks-IN", "Chennai India"),
        ("103.107.227.52", [443, 7443], "Quantum-Link-Co", "Leh India"),
    ]

    return [
        {
            "detection_date": detection_date,
            "ip_address": ip,
            "ports": ports,
            "subnet": "103.107.224.0/22",
            "asn": "AS9583",
            "netname": netname,
            "location": location,
            "company": "Punjab National Bank",
        }
        for ip, ports, netname, location in rows
    ]


def get_demo_software_assets() -> list[dict[str, Any]]:
    """Return synthetic exposed software service records."""
    detection_date = _NOW.date().isoformat()
    rows = [
        ("http_server", "2.4.58", 443, "proxy.pnb.bank.in"),
        ("Apache", "2.4.57", 8443, "postman.pnb.bank.in"),
        ("IIS", "10.0", 443, "www2.pnbrrbkiosk.in"),
        ("Microsoft-IIS", "10.0", 9443, "www.cos.pnb.bank.in"),
        ("OpenResty", "1.27.1.1", 443, "upload.pnbuniv.net.in"),
        ("nginx", "1.25.5", 7443, "api.pnb.bank.in"),
    ]

    return [
        {
            "detection_date": detection_date,
            "product": product,
            "version": version,
            "type": "WebServer",
            "port": port,
            "host": host,
            "company_name": "PNB",
        }
        for product, version, port, host in rows
    ]


def get_demo_network_graph() -> dict[str, list[dict[str, str]]]:
    """Return a graph model with domain/ip/ssl nodes and relationship edges."""
    nodes = [
        # FULLY_QUANTUM_SAFE (3)
        {
            "id": "netbanking.pnb.bank.in",
            "label": "netbanking",
            "type": "domain",
            "pqc_status": "FULLY_QUANTUM_SAFE",
            "display_tier": "Elite-PQC",
            "ip_address": "103.107.224.11",
        },
        {
            "id": "auth.pnb.bank.in",
            "label": "auth",
            "type": "domain",
            "pqc_status": "FULLY_QUANTUM_SAFE",
            "display_tier": "Elite-PQC",
            "ip_address": "103.107.224.29",
        },
        {
            "id": "ssl-pqc-01",
            "label": "pqc-cert-01",
            "type": "ssl",
            "pqc_status": "FULLY_QUANTUM_SAFE",
            "display_tier": "Elite-PQC",
            "ip_address": "103.107.224.11",
        },
        # PQC_TRANSITION (3)
        {
            "id": "api.pnb.bank.in",
            "label": "api",
            "type": "domain",
            "pqc_status": "PQC_TRANSITION",
            "display_tier": "Standard",
            "ip_address": "103.107.224.44",
        },
        {
            "id": "mobileapi.pnb.bank.in",
            "label": "mobileapi",
            "type": "domain",
            "pqc_status": "PQC_TRANSITION",
            "display_tier": "Standard",
            "ip_address": "103.107.225.15",
        },
        {
            "id": "ssl-hybrid-01",
            "label": "hybrid-cert-01",
            "type": "ssl",
            "pqc_status": "PQC_TRANSITION",
            "display_tier": "Standard",
            "ip_address": "103.107.224.44",
        },
        # QUANTUM_VULNERABLE (3)
        {
            "id": "swift.pnb.bank.in",
            "label": "swift",
            "type": "domain",
            "pqc_status": "QUANTUM_VULNERABLE",
            "display_tier": "Legacy",
            "ip_address": "103.107.225.87",
        },
        {
            "id": "loans.pnb.bank.in",
            "label": "loans",
            "type": "domain",
            "pqc_status": "QUANTUM_VULNERABLE",
            "display_tier": "Legacy",
            "ip_address": "103.107.226.38",
        },
        {
            "id": "ip-103.107.224.63",
            "label": "edge-ip-63",
            "type": "ip",
            "pqc_status": "QUANTUM_VULNERABLE",
            "display_tier": "Legacy",
            "ip_address": "103.107.224.63",
        },
        # CRITICALLY_VULNERABLE (3)
        {
            "id": "vpn.pnb.bank.in",
            "label": "vpn",
            "type": "domain",
            "pqc_status": "CRITICALLY_VULNERABLE",
            "display_tier": "Critical",
            "ip_address": "103.107.227.52",
        },
        {
            "id": "legacy.pnb.bank.in",
            "label": "legacy",
            "type": "domain",
            "pqc_status": "CRITICALLY_VULNERABLE",
            "display_tier": "Critical",
            "ip_address": "103.107.224.29",
        },
        {
            "id": "ssl-legacy-01",
            "label": "legacy-cert-01",
            "type": "ssl",
            "pqc_status": "CRITICALLY_VULNERABLE",
            "display_tier": "Critical",
            "ip_address": "103.107.227.52",
        },
        # UNKNOWN (3)
        {
            "id": "staging.pnb.bank.in",
            "label": "staging",
            "type": "domain",
            "pqc_status": "UNKNOWN",
            "display_tier": "Unclassified",
            "ip_address": "103.107.225.15",
        },
        {
            "id": "ip-103.107.224.44",
            "label": "edge-ip-44",
            "type": "ip",
            "pqc_status": "UNKNOWN",
            "display_tier": "Unclassified",
            "ip_address": "103.107.224.44",
        },
        {
            "id": "ssl-unknown-01",
            "label": "unknown-cert",
            "type": "ssl",
            "pqc_status": "UNKNOWN",
            "display_tier": "Unclassified",
            "ip_address": "103.107.225.15",
        },
    ]

    edges = [
        # Subnet proximity / IP linkage
        {"source": "netbanking.pnb.bank.in", "target": "ip-103.107.224.63"},
        {"source": "auth.pnb.bank.in", "target": "ip-103.107.224.63"},
        {"source": "api.pnb.bank.in", "target": "ip-103.107.224.44"},
        {"source": "mobileapi.pnb.bank.in", "target": "ip-103.107.224.44"},
        {"source": "swift.pnb.bank.in", "target": "ip-103.107.224.63"},
        {"source": "loans.pnb.bank.in", "target": "ip-103.107.224.63"},
        {"source": "vpn.pnb.bank.in", "target": "ip-103.107.224.63"},
        {"source": "legacy.pnb.bank.in", "target": "ip-103.107.224.63"},
        {"source": "staging.pnb.bank.in", "target": "ip-103.107.224.44"},
        # Certificate linkage
        {"source": "ssl-pqc-01", "target": "netbanking.pnb.bank.in"},
        {"source": "ssl-pqc-01", "target": "auth.pnb.bank.in"},
        {"source": "ssl-hybrid-01", "target": "api.pnb.bank.in"},
        {"source": "ssl-hybrid-01", "target": "mobileapi.pnb.bank.in"},
        {"source": "ssl-legacy-01", "target": "vpn.pnb.bank.in"},
        {"source": "ssl-legacy-01", "target": "legacy.pnb.bank.in"},
        {"source": "ssl-unknown-01", "target": "staging.pnb.bank.in"},
        # Cross-tier operational relationships
        {"source": "netbanking.pnb.bank.in", "target": "api.pnb.bank.in"},
        {"source": "auth.pnb.bank.in", "target": "mobileapi.pnb.bank.in"},
        {"source": "swift.pnb.bank.in", "target": "loans.pnb.bank.in"},
        {"source": "vpn.pnb.bank.in", "target": "legacy.pnb.bank.in"},
        {"source": "api.pnb.bank.in", "target": "staging.pnb.bank.in"},
        {"source": "ssl-hybrid-01", "target": "ssl-unknown-01"},
    ]

    return {"nodes": nodes, "edges": edges}
