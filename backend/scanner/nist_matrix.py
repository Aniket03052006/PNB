"""
Phase 2 — NIST PQC Validation Matrix.

Categorises cryptographic algorithms, protocols, and key-exchange
mechanisms by their quantum-vulnerability status, aligned with:

  • NIST FIPS 203  (ML-KEM / CRYSTALS-Kyber)
  • NIST FIPS 204  (ML-DSA / CRYSTALS-Dilithium)
  • NIST FIPS 205  (SLH-DSA / SPHINCS+)
  • CNSA 2.0 Suite  (NSA guidance for quantum-resistant algorithms)

Each entry carries a ``quantum_status`` tag used by the Assessment
Engine to evaluate live scan data.

Quantum Status Tags
───────────────────
  VULNERABLE       — Broken by Shor's algorithm (asymmetric) or
                     weakened by Grover's algorithm (symmetric < 256).
  WEAKENED         — Still usable but requires larger key sizes
                     (e.g. AES-128 → AES-256).
  LEGACY_PROTOCOL  — Protocol version too old to negotiate PQC
                     extensions (SSLv3 … TLS 1.2).
  HYBRID_PQC       — Classical + PQC hybrid for transitional safety.
  PQC_SAFE         — Pure post-quantum algorithm approved by NIST.
  COMPLIANT        — Meets current best-practice (AES-256, ChaCha20,
                     TLS 1.3) even if not PQC-specific.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, FrozenSet, List, Set


# ───────────────────────────────────────────────────────────────────────────
# Quantum Status Enum
# ───────────────────────────────────────────────────────────────────────────

class QuantumStatus(str, Enum):
    """Classification tag for a cryptographic primitive."""
    VULNERABLE = "VULNERABLE"            # Broken by quantum (Shor / Grover)
    WEAKENED = "WEAKENED"                # Reduced security margin (Grover)
    LEGACY_PROTOCOL = "LEGACY_PROTOCOL"  # Protocol cannot carry PQC
    HYBRID_PQC = "HYBRID_PQC"           # Classical + PQC transitional
    PQC_SAFE = "PQC_SAFE"              # Pure post-quantum (NIST approved)
    COMPLIANT = "COMPLIANT"             # Meets current best-practice


# ───────────────────────────────────────────────────────────────────────────
# Matrix Entry
# ───────────────────────────────────────────────────────────────────────────

@dataclass(frozen=True)
class MatrixEntry:
    """A single row in the validation matrix."""
    name: str
    quantum_status: QuantumStatus
    category: str                 # "key_exchange", "signature", "symmetric", "protocol", "hash"
    vulnerability: str            # e.g. "Shor's Algorithm", "Grover's Algorithm"
    nist_standard: str = ""       # e.g. "FIPS 203"
    min_safe_key_bits: int = 0    # Minimum key size considered safe (0 = N/A)
    notes: str = ""


# ───────────────────────────────────────────────────────────────────────────
# 1. VULNERABLE — Classical Asymmetric (Shor's Algorithm)
# ───────────────────────────────────────────────────────────────────────────

VULNERABLE_KEY_EXCHANGE: Dict[str, MatrixEntry] = {
    "RSA": MatrixEntry(
        name="RSA",
        quantum_status=QuantumStatus.VULNERABLE,
        category="key_exchange",
        vulnerability="Shor's Algorithm — factorable in polynomial time on a CRQC",
        notes="All RSA key sizes (1024–8192) are equally vulnerable to a sufficiently large quantum computer.",
    ),
    "DH": MatrixEntry(
        name="Diffie-Hellman",
        quantum_status=QuantumStatus.VULNERABLE,
        category="key_exchange",
        vulnerability="Shor's Algorithm — discrete log problem solvable in polynomial time",
        notes="Static DH without ephemeral keys also lacks forward secrecy.",
    ),
    "ECDH": MatrixEntry(
        name="ECDH",
        quantum_status=QuantumStatus.VULNERABLE,
        category="key_exchange",
        vulnerability="Shor's Algorithm — ECDLP solvable on a quantum computer",
        notes="All NIST curves (P-256, P-384, P-521) are vulnerable.",
    ),
    "ECDHE": MatrixEntry(
        name="ECDHE",
        quantum_status=QuantumStatus.VULNERABLE,
        category="key_exchange",
        vulnerability="Shor's Algorithm — ephemeral ECDH keys vulnerable to future quantum decryption",
        notes="Provides forward secrecy against classical attacks; still Harvest-Now-Decrypt-Later vulnerable.",
    ),
    "X25519": MatrixEntry(
        name="X25519",
        quantum_status=QuantumStatus.VULNERABLE,
        category="key_exchange",
        vulnerability="Shor's Algorithm — Curve25519 ECDLP solvable on a quantum computer",
        notes="Currently best-practice for classical KEX, but quantum-vulnerable for long-term secrets.",
    ),
    "X448": MatrixEntry(
        name="X448",
        quantum_status=QuantumStatus.VULNERABLE,
        category="key_exchange",
        vulnerability="Shor's Algorithm — Curve448 ECDLP solvable on a quantum computer",
        notes="Higher classical security margin than X25519 but equally quantum-vulnerable.",
    ),
    "DHE": MatrixEntry(
        name="DHE",
        quantum_status=QuantumStatus.VULNERABLE,
        category="key_exchange",
        vulnerability="Shor's Algorithm — discrete log problem",
        notes="Ephemeral DH with forward secrecy; still quantum-vulnerable.",
    ),
}

VULNERABLE_SIGNATURES: Dict[str, MatrixEntry] = {
    "RSA": MatrixEntry(
        name="RSA",
        quantum_status=QuantumStatus.VULNERABLE,
        category="signature",
        vulnerability="Shor's Algorithm — RSA signature forgery possible on a CRQC",
        notes="sha256WithRSAEncryption, sha384WithRSAEncryption, sha512WithRSAEncryption all vulnerable.",
    ),
    "ECDSA": MatrixEntry(
        name="ECDSA",
        quantum_status=QuantumStatus.VULNERABLE,
        category="signature",
        vulnerability="Shor's Algorithm — ECDSA private key recoverable on a quantum computer",
        notes="ecdsa-with-SHA256, ecdsa-with-SHA384, ecdsa-with-SHA512 all vulnerable.",
    ),
    "ED25519": MatrixEntry(
        name="Ed25519",
        quantum_status=QuantumStatus.VULNERABLE,
        category="signature",
        vulnerability="Shor's Algorithm — EdDSA on Curve25519 solvable on a quantum computer",
        notes="Fast and modern but not quantum-safe.",
    ),
    "ED448": MatrixEntry(
        name="Ed448",
        quantum_status=QuantumStatus.VULNERABLE,
        category="signature",
        vulnerability="Shor's Algorithm — EdDSA on Curve448 solvable on a quantum computer",
        notes="Higher classical security than Ed25519 but equally quantum-vulnerable.",
    ),
    "DSA": MatrixEntry(
        name="DSA",
        quantum_status=QuantumStatus.VULNERABLE,
        category="signature",
        vulnerability="Shor's Algorithm — discrete log based signature broken by quantum",
        notes="Already deprecated in most standards; quantum makes it completely insecure.",
    ),
}


# ───────────────────────────────────────────────────────────────────────────
# 2. WEAKENED — Symmetric (Grover's Algorithm)
# ───────────────────────────────────────────────────────────────────────────

WEAKENED_SYMMETRIC: Dict[str, MatrixEntry] = {
    "AES-128": MatrixEntry(
        name="AES-128",
        quantum_status=QuantumStatus.WEAKENED,
        category="symmetric",
        vulnerability="Grover's Algorithm — effective security reduced from 128 to 64 bits",
        min_safe_key_bits=256,
        notes="Must upgrade to AES-256 for PQC readiness. CNSA 2.0 mandates AES-256.",
    ),
    "AES-192": MatrixEntry(
        name="AES-192",
        quantum_status=QuantumStatus.WEAKENED,
        category="symmetric",
        vulnerability="Grover's Algorithm — effective security reduced from 192 to 96 bits",
        min_safe_key_bits=256,
        notes="Upgrade to AES-256 recommended for full PQC compliance.",
    ),
    "3DES": MatrixEntry(
        name="3DES",
        quantum_status=QuantumStatus.VULNERABLE,
        category="symmetric",
        vulnerability="Block size 64 bits; already deprecated (NIST SP 800-131A). Grover further weakens.",
        notes="Immediately replace with AES-256-GCM.",
    ),
    "RC4": MatrixEntry(
        name="RC4",
        quantum_status=QuantumStatus.VULNERABLE,
        category="symmetric",
        vulnerability="Classically broken (RFC 7465). Quantum irrelevant — already insecure.",
        notes="Must be disabled immediately regardless of quantum considerations.",
    ),
}

COMPLIANT_SYMMETRIC: Dict[str, MatrixEntry] = {
    "AES-256": MatrixEntry(
        name="AES-256",
        quantum_status=QuantumStatus.COMPLIANT,
        category="symmetric",
        vulnerability="Grover's Algorithm reduces to 128-bit effective — still considered safe",
        min_safe_key_bits=256,
        nist_standard="CNSA 2.0",
        notes="Approved for PQC era. AES-256-GCM is the recommended mode.",
    ),
    "CHACHA20": MatrixEntry(
        name="ChaCha20-Poly1305",
        quantum_status=QuantumStatus.COMPLIANT,
        category="symmetric",
        vulnerability="256-bit key; Grover reduces to 128-bit effective — considered safe",
        min_safe_key_bits=256,
        notes="Approved alternative to AES-256-GCM with equivalent quantum safety.",
    ),
}


# ───────────────────────────────────────────────────────────────────────────
# 3. LEGACY PROTOCOLS
# ───────────────────────────────────────────────────────────────────────────

LEGACY_PROTOCOLS: Dict[str, MatrixEntry] = {
    "SSLv2": MatrixEntry(
        name="SSLv2",
        quantum_status=QuantumStatus.LEGACY_PROTOCOL,
        category="protocol",
        vulnerability="Classically broken; cannot support PQC extensions",
        notes="Must be disabled. Prohibited by RFC 6176.",
    ),
    "SSLv3": MatrixEntry(
        name="SSLv3",
        quantum_status=QuantumStatus.LEGACY_PROTOCOL,
        category="protocol",
        vulnerability="POODLE attack; cannot support PQC extensions",
        notes="Must be disabled. Prohibited by RFC 7568.",
    ),
    "TLSv1.0": MatrixEntry(
        name="TLS 1.0",
        quantum_status=QuantumStatus.LEGACY_PROTOCOL,
        category="protocol",
        vulnerability="Deprecated (RFC 8996); no PQC extension support in handshake",
        notes="Must upgrade to TLS 1.3 minimum for PQC key exchange groups.",
    ),
    "TLSv1": MatrixEntry(
        name="TLS 1.0",
        quantum_status=QuantumStatus.LEGACY_PROTOCOL,
        category="protocol",
        vulnerability="Deprecated (RFC 8996); no PQC extension support in handshake",
        notes="Alias for TLSv1.0.",
    ),
    "TLSv1.1": MatrixEntry(
        name="TLS 1.1",
        quantum_status=QuantumStatus.LEGACY_PROTOCOL,
        category="protocol",
        vulnerability="Deprecated (RFC 8996); no PQC extension support in handshake",
        notes="Must upgrade to TLS 1.3 minimum for PQC key exchange groups.",
    ),
    "TLSv1.2": MatrixEntry(
        name="TLS 1.2",
        quantum_status=QuantumStatus.LEGACY_PROTOCOL,
        category="protocol",
        vulnerability="Cannot negotiate PQC key exchange groups natively; lacks supported_groups extension for ML-KEM",
        notes="TLS 1.2 is secure today but cannot carry PQC handshake extensions. Flag as non-compliant for PQC.",
    ),
}

COMPLIANT_PROTOCOLS: Dict[str, MatrixEntry] = {
    "TLSv1.3": MatrixEntry(
        name="TLS 1.3",
        quantum_status=QuantumStatus.COMPLIANT,
        category="protocol",
        vulnerability="None — supports PQC key exchange groups via NamedGroup registry",
        nist_standard="RFC 8446",
        notes="Required for PQC hybrid key exchange (X25519+ML-KEM-768). Foundation for quantum-safe transport.",
    ),
}


# ───────────────────────────────────────────────────────────────────────────
# 4. HYBRID PQC — Transitional
# ───────────────────────────────────────────────────────────────────────────

HYBRID_PQC_KEX: Dict[str, MatrixEntry] = {
    "X25519MLKEM768": MatrixEntry(
        name="X25519 + ML-KEM-768",
        quantum_status=QuantumStatus.HYBRID_PQC,
        category="key_exchange",
        vulnerability="None — dual key agreement provides safety against both classical and quantum",
        nist_standard="FIPS 203 (hybrid draft)",
        notes="IETF draft-ietf-tls-hybrid-design. Recommended transitional approach.",
    ),
    "X25519KYBER768": MatrixEntry(
        name="X25519 + Kyber-768",
        quantum_status=QuantumStatus.HYBRID_PQC,
        category="key_exchange",
        vulnerability="None — dual key agreement; Kyber is the round-3 name for ML-KEM",
        nist_standard="FIPS 203 (hybrid draft)",
        notes="Kyber is the pre-standardization name for ML-KEM. Functionally equivalent.",
    ),
    "SECPG256R1MLKEM768": MatrixEntry(
        name="secp256r1 + ML-KEM-768",
        quantum_status=QuantumStatus.HYBRID_PQC,
        category="key_exchange",
        vulnerability="None — NIST P-256 + ML-KEM hybrid",
        nist_standard="FIPS 203 (hybrid draft)",
        notes="Alternative hybrid using NIST P-256 curve instead of X25519.",
    ),
    "0x11EC": MatrixEntry(
        name="IETF Group 0x11EC (X25519+ML-KEM-768)",
        quantum_status=QuantumStatus.HYBRID_PQC,
        category="key_exchange",
        vulnerability="None — IETF registered hybrid group identifier",
        nist_standard="FIPS 203 (hybrid draft)",
        notes="Numeric group ID used in TLS 1.3 ServerHello for hybrid PQC negotiation.",
    ),
    "X448MLKEM1024": MatrixEntry(
        name="X448 + ML-KEM-1024",
        quantum_status=QuantumStatus.HYBRID_PQC,
        category="key_exchange",
        vulnerability="None — higher-security hybrid combining Curve448 with ML-KEM-1024",
        nist_standard="FIPS 203 (hybrid draft)",
        notes="For environments requiring > 128-bit classical + quantum security.",
    ),
}


# ───────────────────────────────────────────────────────────────────────────
# 5. PURE PQC — NIST Approved
# ───────────────────────────────────────────────────────────────────────────

PURE_PQC_KEM: Dict[str, MatrixEntry] = {
    "ML-KEM-512": MatrixEntry(
        name="ML-KEM-512",
        quantum_status=QuantumStatus.PQC_SAFE,
        category="key_exchange",
        vulnerability="None — lattice-based KEM; NIST security level 1",
        nist_standard="FIPS 203",
        notes="Smallest ML-KEM parameter set. ~128-bit quantum security.",
    ),
    "ML-KEM-768": MatrixEntry(
        name="ML-KEM-768",
        quantum_status=QuantumStatus.PQC_SAFE,
        category="key_exchange",
        vulnerability="None — lattice-based KEM; NIST security level 3",
        nist_standard="FIPS 203",
        notes="Recommended default for most applications. ~192-bit quantum security.",
    ),
    "ML-KEM-1024": MatrixEntry(
        name="ML-KEM-1024",
        quantum_status=QuantumStatus.PQC_SAFE,
        category="key_exchange",
        vulnerability="None — lattice-based KEM; NIST security level 5",
        nist_standard="FIPS 203",
        notes="Highest ML-KEM security. ~256-bit quantum security.",
    ),
}

PURE_PQC_SIGNATURES: Dict[str, MatrixEntry] = {
    "ML-DSA-44": MatrixEntry(
        name="ML-DSA-44 (Dilithium2)",
        quantum_status=QuantumStatus.PQC_SAFE,
        category="signature",
        vulnerability="None — lattice-based signature; NIST security level 2",
        nist_standard="FIPS 204",
        notes="Smallest ML-DSA parameter set. Suitable for certificate signing.",
    ),
    "ML-DSA-65": MatrixEntry(
        name="ML-DSA-65 (Dilithium3)",
        quantum_status=QuantumStatus.PQC_SAFE,
        category="signature",
        vulnerability="None — lattice-based signature; NIST security level 3",
        nist_standard="FIPS 204",
        notes="Recommended default for digital signatures.",
    ),
    "ML-DSA-87": MatrixEntry(
        name="ML-DSA-87 (Dilithium5)",
        quantum_status=QuantumStatus.PQC_SAFE,
        category="signature",
        vulnerability="None — lattice-based signature; NIST security level 5",
        nist_standard="FIPS 204",
        notes="Highest ML-DSA security level.",
    ),
    "SLH-DSA-SHA2-128S": MatrixEntry(
        name="SLH-DSA-SHA2-128s (SPHINCS+)",
        quantum_status=QuantumStatus.PQC_SAFE,
        category="signature",
        vulnerability="None — hash-based signature; conservative security assumption",
        nist_standard="FIPS 205",
        notes="Stateless hash-based signature. Larger signatures but conservative security.",
    ),
    "SLH-DSA-SHAKE-128S": MatrixEntry(
        name="SLH-DSA-SHAKE-128s (SPHINCS+)",
        quantum_status=QuantumStatus.PQC_SAFE,
        category="signature",
        vulnerability="None — hash-based signature with SHAKE-256 instantiation",
        nist_standard="FIPS 205",
        notes="SHAKE-based variant of SLH-DSA.",
    ),
    "SLH-DSA-SHA2-192S": MatrixEntry(
        name="SLH-DSA-SHA2-192s",
        quantum_status=QuantumStatus.PQC_SAFE,
        category="signature",
        vulnerability="None — hash-based signature; NIST security level 3",
        nist_standard="FIPS 205",
        notes="192-bit security variant.",
    ),
    "SLH-DSA-SHA2-256S": MatrixEntry(
        name="SLH-DSA-SHA2-256s",
        quantum_status=QuantumStatus.PQC_SAFE,
        category="signature",
        vulnerability="None — hash-based signature; NIST security level 5",
        nist_standard="FIPS 205",
        notes="Highest SLH-DSA security level.",
    ),
}


# ───────────────────────────────────────────────────────────────────────────
# Hash Algorithm Classification
# ───────────────────────────────────────────────────────────────────────────

HASH_ALGORITHMS: Dict[str, MatrixEntry] = {
    "MD5": MatrixEntry(
        name="MD5",
        quantum_status=QuantumStatus.VULNERABLE,
        category="hash",
        vulnerability="Classically broken (collision attacks). Grover further weakens.",
        notes="Must not be used for any cryptographic purpose.",
    ),
    "SHA1": MatrixEntry(
        name="SHA-1",
        quantum_status=QuantumStatus.VULNERABLE,
        category="hash",
        vulnerability="Classically broken (SHAttered attack). Grover further weakens to ~80-bit.",
        notes="Prohibited for certificate signatures since 2017.",
    ),
    "SHA256": MatrixEntry(
        name="SHA-256",
        quantum_status=QuantumStatus.COMPLIANT,
        category="hash",
        vulnerability="Grover reduces to ~128-bit collision resistance — still considered safe",
        notes="Minimum recommended hash for PQC era.",
    ),
    "SHA384": MatrixEntry(
        name="SHA-384",
        quantum_status=QuantumStatus.COMPLIANT,
        category="hash",
        vulnerability="Grover reduces to ~192-bit collision resistance — safe",
        notes="Preferred for high-security applications.",
    ),
    "SHA512": MatrixEntry(
        name="SHA-512",
        quantum_status=QuantumStatus.COMPLIANT,
        category="hash",
        vulnerability="Grover reduces to ~256-bit collision resistance — safe",
        notes="Highest security SHA-2 variant.",
    ),
}


# ───────────────────────────────────────────────────────────────────────────
# Lookup Helpers
# ───────────────────────────────────────────────────────────────────────────

# Unified lookup: normalised uppercase key → MatrixEntry
_ALL_ENTRIES: Dict[str, MatrixEntry] = {}

for _registry in (
    VULNERABLE_KEY_EXCHANGE,
    VULNERABLE_SIGNATURES,
    WEAKENED_SYMMETRIC,
    COMPLIANT_SYMMETRIC,
    LEGACY_PROTOCOLS,
    COMPLIANT_PROTOCOLS,
    HYBRID_PQC_KEX,
    PURE_PQC_KEM,
    PURE_PQC_SIGNATURES,
    HASH_ALGORITHMS,
):
    for _key, _entry in _registry.items():
        _ALL_ENTRIES[_key.upper().replace("-", "").replace("_", "").replace(" ", "")] = _entry


def lookup(algorithm_or_protocol: str) -> MatrixEntry | None:
    """Look up an algorithm/protocol in the full NIST matrix.

    Normalises the input (uppercase, strip hyphens/underscores/spaces)
    before matching.  Returns ``None`` if no match is found.
    """
    normalised = algorithm_or_protocol.upper().replace("-", "").replace("_", "").replace(" ", "")

    # Direct match
    if normalised in _ALL_ENTRIES:
        return _ALL_ENTRIES[normalised]

    # Substring match (e.g. "sha256WithRSAEncryption" should match RSA sig)
    for key, entry in _ALL_ENTRIES.items():
        if key in normalised or normalised in key:
            return entry

    return None


def classify_kex(kex_name: str) -> QuantumStatus:
    """Classify a key-exchange algorithm string."""
    norm = kex_name.upper().replace("-", "").replace("_", "").replace(" ", "")

    # Check hybrid FIRST (X25519MLKEM768 contains MLKEM768, must not match pure)
    for key in HYBRID_PQC_KEX:
        if key.upper().replace("-", "").replace("_", "") in norm:
            return QuantumStatus.HYBRID_PQC

    # Check pure PQC
    for key in PURE_PQC_KEM:
        if key.upper().replace("-", "").replace("_", "") in norm:
            return QuantumStatus.PQC_SAFE

    # Classical vulnerable
    for key in VULNERABLE_KEY_EXCHANGE:
        if key.upper().replace("-", "").replace("_", "") in norm:
            return QuantumStatus.VULNERABLE

    return QuantumStatus.VULNERABLE  # Default: assume vulnerable if unknown


def classify_signature(sig_algo: str) -> QuantumStatus:
    """Classify a signature algorithm string."""
    norm = sig_algo.upper().replace("-", "").replace("_", "").replace(" ", "")

    # Check pure PQC signatures
    for key in PURE_PQC_SIGNATURES:
        if key.upper().replace("-", "").replace("_", "") in norm:
            return QuantumStatus.PQC_SAFE

    # Classical vulnerable
    for key in VULNERABLE_SIGNATURES:
        if key.upper().replace("-", "").replace("_", "") in norm:
            return QuantumStatus.VULNERABLE

    return QuantumStatus.VULNERABLE


def classify_protocol(tls_version: str) -> QuantumStatus:
    """Classify a TLS/SSL protocol version string."""
    norm = tls_version.strip()

    if norm in COMPLIANT_PROTOCOLS:
        return QuantumStatus.COMPLIANT

    if norm in LEGACY_PROTOCOLS:
        return QuantumStatus.LEGACY_PROTOCOL

    # Fuzzy match
    upper = norm.upper().replace(" ", "").replace("_", "")
    if "1.3" in upper or "13" in upper:
        return QuantumStatus.COMPLIANT
    if any(tag in upper for tag in ("SSL", "1.0", "10", "1.1", "11")):
        return QuantumStatus.LEGACY_PROTOCOL
    if "1.2" in upper or "12" in upper:
        return QuantumStatus.LEGACY_PROTOCOL

    return QuantumStatus.LEGACY_PROTOCOL


def classify_symmetric(cipher_name: str, key_bits: int) -> QuantumStatus:
    """Classify a symmetric cipher by name and key size."""
    upper = cipher_name.upper().replace("-", "").replace("_", "")

    # Check for known-broken ciphers
    if "RC4" in upper:
        return QuantumStatus.VULNERABLE
    if "3DES" in upper or "DESEDE" in upper:
        return QuantumStatus.VULNERABLE
    if "NULL" in upper:
        return QuantumStatus.VULNERABLE

    # ChaCha20 always 256-bit
    if "CHACHA" in upper:
        return QuantumStatus.COMPLIANT

    # AES by key size
    if "AES" in upper:
        if key_bits >= 256:
            return QuantumStatus.COMPLIANT
        return QuantumStatus.WEAKENED

    # Generic: judge by key size
    if key_bits >= 256:
        return QuantumStatus.COMPLIANT
    if key_bits >= 128:
        return QuantumStatus.WEAKENED

    return QuantumStatus.VULNERABLE


# ───────────────────────────────────────────────────────────────────────────
# Summary Accessors (for dashboard / reporting)
# ───────────────────────────────────────────────────────────────────────────

def get_vulnerable_algorithms() -> List[str]:
    """Return all algorithm names marked VULNERABLE."""
    return sorted({
        e.name
        for e in _ALL_ENTRIES.values()
        if e.quantum_status == QuantumStatus.VULNERABLE
    })


def get_pqc_safe_algorithms() -> List[str]:
    """Return all algorithm names marked PQC_SAFE."""
    return sorted({
        e.name
        for e in _ALL_ENTRIES.values()
        if e.quantum_status == QuantumStatus.PQC_SAFE
    })


def get_hybrid_algorithms() -> List[str]:
    """Return all algorithm names marked HYBRID_PQC."""
    return sorted({
        e.name
        for e in _ALL_ENTRIES.values()
        if e.quantum_status == QuantumStatus.HYBRID_PQC
    })


# ───────────────────────────────────────────────────────────────────────────
# Phase 7: Simple Algorithm → Quantum Status Lookup Dict
# ───────────────────────────────────────────────────────────────────────────

ALGORITHM_STATUS: Dict[str, str] = {
    # Asymmetric — quantum-vulnerable (Shor)
    "RSA-1024":       "quantum_vulnerable",
    "RSA-2048":       "quantum_vulnerable",
    "RSA-4096":       "quantum_vulnerable",
    "ECDSA-P256":     "quantum_vulnerable",
    "ECDSA-P384":     "quantum_vulnerable",
    "X25519":         "quantum_vulnerable",
    "DH-Group2":      "quantum_vulnerable",
    "DH-Group14":     "quantum_vulnerable",

    # Symmetric — quantum impact varies
    "AES-128":        "quantum_vulnerable",   # Grover halves effective bits → 64
    "AES-256":        "quantum_safe",         # Grover → 128 effective bits — safe
    "ChaCha20-Poly1305": "quantum_safe",
    "3DES":           "quantum_vulnerable",

    # PQC — NIST approved (FIPS 203/204/205)
    "ML-KEM-512":     "quantum_safe",
    "ML-KEM-768":     "quantum_safe",
    "ML-KEM-1024":    "quantum_safe",
    "ML-DSA-44":      "quantum_safe",
    "ML-DSA-65":      "quantum_safe",
    "ML-DSA-87":      "quantum_safe",
    "SLH-DSA-128s":   "quantum_safe",

    # Hybrid — transitional
    "X25519MLKEM768": "hybrid",
    "X25519KYBER768": "hybrid",
}
