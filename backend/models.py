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
    tls_version_score: int = 0       # max 25
    key_exchange_score: int = 0      # max 35
    certificate_score: int = 0       # max 25
    cipher_strength_score: int = 0   # max 15
    status: PQCStatus = PQCStatus.CRITICALLY_VULNERABLE
    findings: list[str] = Field(default_factory=list)
    recommendations: list[str] = Field(default_factory=list)


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


class PQCLabel(BaseModel):
    label_id: str
    asset: str
    issued_at: str
    valid_until: str
    algorithms: list[str]
    standards: list[str]
    status: str = "ACTIVE"


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
