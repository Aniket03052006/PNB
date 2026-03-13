"""Q-ARMOR Data Models — Pydantic schemas for scan results and CBOM generation."""

from __future__ import annotations
from enum import Enum
from pydantic import BaseModel, Field
from datetime import datetime, timezone


class PQCStatus(str, Enum):
    FULLY_QUANTUM_SAFE = "FULLY_QUANTUM_SAFE"
    PQC_TRANSITION = "PQC_TRANSITION"
    QUANTUM_VULNERABLE = "QUANTUM_VULNERABLE"
    CRITICALLY_VULNERABLE = "CRITICALLY_VULNERABLE"
    UNKNOWN = "UNKNOWN"


class RemediationPriority(str, Enum):
    IMMEDIATE = "P1_IMMEDIATE"
    SHORT_TERM = "P2_SHORT_TERM"
    MEDIUM_TERM = "P3_MEDIUM_TERM"
    STRATEGIC = "P4_STRATEGIC"


class AssetType(str, Enum):
    WEB = "web"
    API = "api"
    VPN = "vpn"
    MAIL = "mail"
    OTHER = "other"


class DiscoveredAsset(BaseModel):
    hostname: str
    ip: str | None = None
    port: int = 443
    asset_type: AssetType = AssetType.WEB
    discovery_method: str = "manual"
    discovered_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class CertificateInfo(BaseModel):
    subject: str = ""
    issuer: str = ""
    serial_number: str = ""
    not_before: str = ""
    not_after: str = ""
    signature_algorithm: str = ""
    public_key_type: str = ""
    public_key_bits: int = 0
    san_entries: list[str] = Field(default_factory=list)
    is_expired: bool = False
    days_until_expiry: int = 0


class TLSInfo(BaseModel):
    version: str = ""
    cipher_suite: str = ""
    cipher_algorithm: str = ""
    cipher_bits: int = 0
    key_exchange: str = ""
    authentication: str = ""
    supports_tls_1_0: bool = False
    supports_tls_1_1: bool = False
    supports_tls_1_2: bool = False
    supports_tls_1_3: bool = False


class CryptoFingerprint(BaseModel):
    tls: TLSInfo = Field(default_factory=TLSInfo)
    certificate: CertificateInfo = Field(default_factory=CertificateInfo)
    has_forward_secrecy: bool = False
    has_pqc_kex: bool = False
    has_pqc_signature: bool = False
    has_hybrid_mode: bool = False
    jwt_algorithm: str | None = None


# ── Phase 6: Tri-Mode Probe Profile ─────────────────────────────────────────

class ProbeProfile(BaseModel):
    """Single TLS probe result — one of three modes (A/B/C)."""
    mode: str = ""                              # "A" | "B" | "C"
    tls_version: str | None = None
    cipher_suite: str | None = None
    cipher_bits: int | None = None
    key_exchange: str | None = None
    key_exchange_group: str | None = None
    authentication: str | None = None
    signature_algorithm: str | None = None
    public_key_type: str | None = None
    public_key_bits: int | None = None
    certificate_serial: str | None = None
    error: str | None = None


class TriModeFingerprint(BaseModel):
    """Phase 6 tri-mode cryptographic fingerprint for a single asset.

    Contains three probe profiles representing:
      - Probe A: PQC-capable client hello (ML-KEM-768 + X25519MLKEM768)
      - Probe B: TLS 1.3 classical client hello (no PQC groups)
      - Probe C: TLS 1.2 downgrade attempt (worst-case)
    """
    hostname: str
    port: int = 443
    asset_type: AssetType = AssetType.WEB
    ip: str | None = None
    probe_a: ProbeProfile = Field(default_factory=lambda: ProbeProfile(mode="A"))
    probe_b: ProbeProfile = Field(default_factory=lambda: ProbeProfile(mode="B"))
    probe_c: ProbeProfile = Field(default_factory=lambda: ProbeProfile(mode="C"))
    certificate: CertificateInfo = Field(default_factory=CertificateInfo)
    probed_at: str = Field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
    )
    scan_duration_ms: int = 0
    error: str | None = None
    mode: str = "live"                          # "live" | "demo"


class HistoricalScanSummary(BaseModel):
    """Pre-built historical scan summary for the History tab (Phase 6 demo seed)."""
    week: int
    scan_date: str
    total_assets: int = 0
    quantum_safety_score: int = 0
    fully_quantum_safe: int = 0
    pqc_transition: int = 0
    quantum_vulnerable: int = 0
    critically_vulnerable: int = 0
    unknown: int = 0
    mode: str = "demo"


# ── Existing models (unchanged) ─────────────────────────────────────────────


class QScore(BaseModel):
    total: int = 0
    tls_version_score: int = 0       # max 25 (legacy) / 20 (Phase 7)
    key_exchange_score: int = 0      # max 35 (legacy) / 30 (Phase 7)
    certificate_score: int = 0       # max 25 (legacy) / 20 (Phase 7)
    cipher_strength_score: int = 0   # max 15
    agility_score: int = 0           # max 15  (Phase 7 — crypto agility)
    status: PQCStatus = PQCStatus.CRITICALLY_VULNERABLE
    findings: list[str] = Field(default_factory=list)
    recommendations: list[str] = Field(default_factory=list)


class ClassifiedAsset(BaseModel):
    """Phase 7 classified asset — tri-mode scoring with best/typical/worst Q-Scores."""
    hostname: str
    port: int = 443
    asset_type: AssetType = AssetType.WEB
    best_case_score: int = 0          # From Probe A
    typical_score: int = 0            # From Probe B
    worst_case_score: int = 0         # From Probe C
    best_case_q: QScore = Field(default_factory=QScore)
    typical_q: QScore = Field(default_factory=QScore)
    worst_case_q: QScore = Field(default_factory=QScore)
    status: PQCStatus = PQCStatus.UNKNOWN   # Derived from worst_case
    summary: str = ""                 # One-line plain English
    recommended_action: str = ""      # Single recommended next step
    agility_score: int = 0            # 0-15
    agility_details: list[dict] = Field(default_factory=list)


class ScanResult(BaseModel):
    asset: DiscoveredAsset
    fingerprint: CryptoFingerprint = Field(default_factory=CryptoFingerprint)
    q_score: QScore = Field(default_factory=QScore)
    scanned_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    scan_duration_ms: int = 0
    error: str | None = None


class RemediationAction(BaseModel):
    priority: RemediationPriority
    timeframe: str
    description: str
    affected_assets: list[str] = Field(default_factory=list)
    specific_actions: list[str] = Field(default_factory=list)


class PQCLabelLegacy(BaseModel):
    """Legacy PQC label (Phase 4/5 compat)."""
    label_id: str
    asset: str
    issued_at: str
    valid_until: str
    algorithms: list[str]
    standards: list[str]
    status: str = "ACTIVE"


# Alias so old references still work
PQCLabel = PQCLabelLegacy


# ── Phase 8+9 Models ────────────────────────────────────────────────────────

class RegressionEntry(BaseModel):
    """A single regression finding between two consecutive scans."""
    hostname: str
    port: int = 443
    urgency: str = "MEDIUM"                     # HIGH | MEDIUM | LOW
    category: str = ""                          # new_asset | score_regression | missed_upgrade
    description: str = ""
    previous_value: str | None = None
    current_value: str | None = None
    recommended_action: str = ""


class RegressionReport(BaseModel):
    """Phase 8 regression detection output — three distinct finding lists."""
    scan_id: int | None = None
    previous_scan_id: int | None = None
    detected_at: str = Field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
    )
    new_assets: list[RegressionEntry] = Field(default_factory=list)
    score_regressions: list[RegressionEntry] = Field(default_factory=list)
    missed_upgrades: list[RegressionEntry] = Field(default_factory=list)
    total_findings: int = 0
    data_mode: str = "live"                     # "live" | "demo"


class PQCLabelV9(BaseModel):
    """Phase 9 PQC certification label with full metadata."""
    label_id: str                               # LABEL-<UUID8>
    hostname: str
    port: int = 443
    tier: int = 3                               # 1 | 2 | 3
    certification_title: str = ""               # e.g. "FULLY_QUANTUM_SAFE"
    badge_color: str = "#D50000"                # Tier1=#00C853, Tier2=#FF6D00, Tier3=#D50000
    badge_icon: str = "❌"                       # ✅ | 🔶 | ❌
    nist_standards: list[str] = Field(default_factory=list)
    algorithms_in_use: list[str] = Field(default_factory=list)
    issued_at: str = ""
    valid_until: str = ""
    verification_url: str = ""
    is_simulated: bool = False
    primary_gap: str | None = None              # Non-compliant only
    fix_in_days: int | None = None              # Non-compliant only


class LabelSummary(BaseModel):
    """Phase 9 aggregate label summary across all classified assets."""
    labels: list[PQCLabelV9] = Field(default_factory=list)
    total_assets: int = 0
    tier_1_count: int = 0
    tier_2_count: int = 0
    tier_3_count: int = 0
    tier_1_pct: float = 0.0
    tier_2_pct: float = 0.0
    tier_3_pct: float = 0.0
    quantum_safety_score: int = 0               # 0-100 aggregate
    executive_summary: str = ""
    data_mode: str = "live"                     # "live" | "demo"


class ScanSummary(BaseModel):
    total_assets: int = 0
    fully_quantum_safe: int = 0
    pqc_transition: int = 0
    quantum_vulnerable: int = 0
    critically_vulnerable: int = 0
    unknown: int = 0
    average_q_score: float = 0.0
    scan_timestamp: str = Field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
    )
    results: list[ScanResult] = Field(default_factory=list)
    remediation_roadmap: list[RemediationAction] = Field(default_factory=list)
    labels: list[PQCLabel] = Field(default_factory=list)
