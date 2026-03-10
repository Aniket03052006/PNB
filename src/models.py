"""
Q-ARMOR Phase 1 Data Models.

Dataclass definitions for TLS connection state, certificate metadata,
and per-target scan results. These structures form the extraction schema
that is serialised to JSON for verification.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field, asdict
from datetime import datetime
from typing import Any, List, Optional


# ---------------------------------------------------------------------------
# TLS Connection State
# ---------------------------------------------------------------------------

@dataclass
class TLSConnectionState:
    """Data extracted from the live TLS handshake."""

    target: str = ""
    port: int = 443
    ip_address: str = ""
    sni: str = ""
    tls_version: str = ""
    cipher_suite: str = ""
    cipher_protocol: str = ""
    cipher_bits: int = 0

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


# ---------------------------------------------------------------------------
# Certificate Metadata
# ---------------------------------------------------------------------------

@dataclass
class CertificateMetadata:
    """Parsed fields from the leaf X.509 certificate."""

    subject: str = ""
    issuer: str = ""
    serial_number: str = ""
    not_valid_before: str = ""
    not_valid_after: str = ""
    public_key_algorithm: str = ""
    public_key_size: int = 0
    signature_algorithm: str = ""
    signature_hash_algorithm: str = ""
    subject_alternative_names: List[str] = field(default_factory=list)
    is_expired: bool = False
    days_until_expiry: int = 0
    is_self_signed: bool = False

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


# ---------------------------------------------------------------------------
# Per-Target Scan Result
# ---------------------------------------------------------------------------

@dataclass
class ScanResult:
    """Aggregated result for a single target scan."""

    target: str = ""
    port: int = 443
    status: str = "success"          # "success" | "error"
    error_message: Optional[str] = None
    scan_timestamp: str = ""
    scan_duration_ms: int = 0
    connection: Optional[TLSConnectionState] = None
    certificate: Optional[CertificateMetadata] = None

    def to_dict(self) -> dict[str, Any]:
        """Convert to a plain dict, dropping ``None`` leaves for clean JSON."""
        d = asdict(self)
        # Strip None values at the top level for compact output
        return {k: v for k, v in d.items() if v is not None}


# ---------------------------------------------------------------------------
# Batch Report
# ---------------------------------------------------------------------------

@dataclass
class ScanReport:
    """Collection of results for a multi-target scan run."""

    scanner: str = "Q-ARMOR ACDI Scanner"
    version: str = "1.0.0"
    phase: str = "Phase 1 — Core Discovery & Protocol Analysis"
    scan_started: str = ""
    scan_finished: str = ""
    total_targets: int = 0
    successful: int = 0
    failed: int = 0
    results: List[ScanResult] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    def to_json(self, indent: int = 2) -> str:
        """Serialise the full report to formatted JSON."""
        return json.dumps(self.to_dict(), indent=indent, default=str)
