"""
Q-ARMOR Phase 1 Data Models.

Dataclass definitions for TLS connection state, certificate metadata,
and per-target scan results. These structures form the extraction schema
that is serialised to JSON for verification.

This module provides the core data structures used throughout the
Q-ARMOR scanner for representing TLS handshake information, X.509
certificate details, and aggregated scan results.

Author: Q-ARMOR Team
Version: 1.0.0
"""

# Standard library imports
from __future__ import annotations  # Enables forward references in type hints

import json  # JSON serialization for report output

# Dataclass utilities for structured data models
from dataclasses import dataclass, field, asdict

# DateTime handling for timestamps
from datetime import datetime

# Type hints for enhanced code clarity
from typing import Any, List, Optional


# ---------------------------------------------------------------------------
# TLS Connection State
# ---------------------------------------------------------------------------

@dataclass
class TLSConnectionState:
    """
    Data extracted from the live TLS handshake.
    
    This dataclass captures all relevant information about an established
    TLS connection including protocol version, cipher suite details, and
    connection metadata such as target host and port.
    
    Attributes:
        target: The hostname or IP address of the target server
        port: The TCP port number (default: 443 for HTTPS)
        ip_address: Resolved IP address of the target
        sni: Server Name Indication value used in TLS handshake
        tls_version: TLS protocol version (e.g., "TLSv1.2", "TLSv1.3")
        cipher_suite: Full cipher suite identifier (e.g., "TLS_AES_256_GCM_SHA384")
        cipher_protocol: Protocol component of the cipher suite
        cipher_bits: Key strength in bits (e.g., 256 for AES-256)
    """

    # Target server hostname or IP address
    target: str = ""
    
    # TCP port number - typically 443 for HTTPS connections
    port: int = 443
    
    # Resolved IPv4 or IPv6 address from DNS lookup
    ip_address: str = ""
    
    # Server Name Indication (SNI) hostname sent during TLS handshake
    sni: str = ""
    
    # TLS protocol version (TLSv1.0, TLSv1.1, TLSv1.2, TLSv1.3)
    tls_version: str = ""
    
    # Full cipher suite identifier as defined in RFC standards
    cipher_suite: str = ""
    
    # Protocol portion of cipher suite (e.g., "AES", "CHACHA20")
    cipher_protocol: str = ""
    
    # Symmetric key length in bits (128, 192, or 256)
    cipher_bits: int = 0

    def to_dict(self) -> dict[str, Any]:
        """Convert the TLS connection state to a dictionary representation."""
        return asdict(self)


# ---------------------------------------------------------------------------
# Certificate Metadata
# ---------------------------------------------------------------------------

@dataclass
class CertificateMetadata:
    """
    Parsed fields from the leaf X.509 certificate.
    
    This dataclass stores detailed information extracted from the
    X.509 certificate presented by the target server during the
    TLS handshake. It includes identity information, validity
    periods, and cryptographic parameters.
    
    Attributes:
        subject: Distinguished Name (DN) of the certificate subject
        issuer: Distinguished Name (DN) of the issuing CA
        serial_number: Unique serial number assigned by the issuer
        not_valid_before: Certificate validity start date/time
        not_valid_after: Certificate validity end date/time
        public_key_algorithm: Algorithm used for the public key (e.g., RSA, EC)
        public_key_size: Size of the public key in bits
        signature_algorithm: Algorithm used to sign the certificate
        signature_hash_algorithm: Hash algorithm used in the signature
        subject_alternative_names: List of SAN entries (DNS names, IPs, etc.)
        is_expired: Boolean indicating if the certificate has expired
        days_until_expiry: Number of days until certificate expires (negative if expired)
        is_self_signed: Boolean indicating if certificate is self-signed
    """

    # Subject Distinguished Name (e.g., "CN=example.com, O=Company")
    subject: str = ""
    
    # Issuer Distinguished Name (e.g., "CN=DigiCert, O=DigiCert Inc")
    issuer: str = ""
    
    # Unique serial number assigned by the certificate issuer
    serial_number: str = ""
    
    # Certificate validity period start (ISO 8601 format)
    not_valid_before: str = ""
    
    # Certificate validity period end (ISO 8601 format)
    not_valid_after: str = ""
    
    # Public key algorithm name (RSA, EC, DSA)
    public_key_algorithm: str = ""
    
    # Public key size in bits (e.g., 2048, 4096 for RSA; 256 for EC)
    public_key_size: int = 0
    
    # Signature algorithm (e.g., sha256WithRSAEncryption)
    signature_algorithm: str = ""
    
    # Hash algorithm used in signature (e.g., SHA256, SHA384)
    signature_hash_algorithm: str = ""
    
    # Subject Alternative Names extension values
    subject_alternative_names: List[str] = field(default_factory=list)
    
    # Flag indicating if current date is past not_valid_after
    is_expired: bool = False
    
    # Days remaining until expiration (negative if already expired)
    days_until_expiry: int = 0
    
    # Flag indicating if subject and issuer DNs are identical
    is_self_signed: bool = False

    def to_dict(self) -> dict[str, Any]:
        """Convert the certificate metadata to a dictionary representation."""
        return asdict(self)


# ---------------------------------------------------------------------------
# Per-Target Scan Result
# ---------------------------------------------------------------------------

@dataclass
class ScanResult:
    """
    Aggregated result for a single target scan.
    
    This dataclass represents the complete outcome of scanning a
    single target host. It includes connection state, certificate
    details, timing information, and any error information if the
    scan failed.
    
    Attributes:
        target: The hostname or IP address that was scanned
        port: The TCP port that was scanned
        status: Scan status - "success" or "error"
        error_message: Error description if status is "error"
        scan_timestamp: ISO 8601 timestamp when scan started
        scan_duration_ms: Duration of the scan in milliseconds
        connection: TLS connection state information (if successful)
        certificate: Parsed certificate metadata (if successful)
    """

    # Target hostname or IP address that was scanned
    target: str = ""
    
    # TCP port number that was scanned
    port: int = 443
    
    # Scan outcome status - "success" indicates successful scan,
    # "error" indicates scan failure
    status: str = "success"          # "success" | "error"
    
    # Error message description when status is "error"
    error_message: Optional[str] = None
    
    # ISO 8601 formatted timestamp when scan was initiated
    scan_timestamp: str = ""
    
    # Total scan duration in milliseconds
    scan_duration_ms: int = 0
    
    # TLS connection state captured during handshake (None if error)
    connection: Optional[TLSConnectionState] = None
    
    # Certificate metadata from the leaf certificate (None if error)
    certificate: Optional[CertificateMetadata] = None

    def to_dict(self) -> dict[str, Any]:
        """
        Convert to a plain dict, dropping ``None`` leaves for clean JSON.
        
        This method serializes the scan result to a dictionary,
        excluding any fields with None values to produce clean
        JSON output suitable for verification or storage.
        
        Returns:
            Dictionary representation with None values removed
        """
        d = asdict(self)
        # Strip None values at the top level for compact output
        return {k: v for k, v in d.items() if v is not None}


# ---------------------------------------------------------------------------
# Batch Report
# ---------------------------------------------------------------------------

@dataclass
class ScanReport:
    """
    Collection of results for a multi-target scan run.
    
    This dataclass serves as a container for aggregating multiple
    individual scan results into a comprehensive scan report. It
    includes metadata about the scan run itself (timing, version,
    statistics) along with the individual results.
    
    Attributes:
        scanner: Name of the scanner application
        version: Scanner version string
        phase: Current scan phase description
        scan_started: ISO 8601 timestamp when scan batch started
        scan_finished: ISO 8601 timestamp when scan batch completed
        total_targets: Total number of targets attempted
        successful: Number of successfully scanned targets
        failed: Number of failed scan attempts
        results: List of individual ScanResult objects
    """

    # Name of the scanner tool generating this report
    scanner: str = "Q-ARMOR ACDI Scanner"
    
    # Version identifier for the scanner
    version: str = "1.0.0"
    
    # Description of the current scanning phase
    phase: str = "Phase 1 — Core Discovery & Protocol Analysis"
    
    # ISO 8601 timestamp when this scan batch started
    scan_started: str = ""
    
    # ISO 8601 timestamp when this scan batch completed
    scan_finished: str = ""
    
    # Total count of targets included in this scan batch
    total_targets: int = 0
    
    # Count of targets scanned successfully
    successful: int = 0
    
    # Count of targets that failed to scan
    failed: int = 0
    
    # List of individual scan results for each target
    results: List[ScanResult] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        """Convert the scan report to a dictionary representation."""
        return asdict(self)

    def to_json(self, indent: int = 2) -> str:
        """
        Serialise the full report to formatted JSON.
        
        This method provides JSON serialization of the complete
        scan report including all metadata and results.
        
        Args:
            indent: Number of spaces for JSON indentation (default: 2)
            
        Returns:
            Formatted JSON string representation of the report
        """
        return json.dumps(self.to_dict(), indent=indent, default=str)
