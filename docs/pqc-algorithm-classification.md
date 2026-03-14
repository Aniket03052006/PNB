# PQC Algorithm Classification Rules

This file documents the algorithm families and posture rules used by the Q-ARMOR classifier.

## Overall status rules

- `FULLY_QUANTUM_SAFE`
  - TLS 1.3 on the negotiated path
  - PQC key exchange present
  - PQC certificate/signature present
  - strong worst-case score
- `PQC_TRANSITION`
  - TLS 1.3 present
  - ML-KEM or hybrid PQC key exchange present
  - classical certificate and/or downgrade exposure may still remain
- `QUANTUM_VULNERABLE`
  - classical cryptography only
  - no immediately-broken legacy protocol requirement
- `CRITICALLY_VULNERABLE`
  - legacy TLS or very weak worst-case posture
- `UNKNOWN`
  - probe failed or data was insufficient

Important behavior:
- Pure `ML-KEM-*` key exchange without a PQC certificate is treated as `PQC_TRANSITION`, not `FULLY_QUANTUM_SAFE`.
- Hybrid groups such as `X25519MLKEM768` are also treated as `PQC_TRANSITION`.

## Key exchange families

### PQC / transition-capable

- `ML-KEM-512`
- `ML-KEM-768`
- `ML-KEM-1024`
- `KYBER`
- `KYBER768`
- `KYBER1024`
- `X25519MLKEM768`
- `X25519KYBER768`
- `X448MLKEM1024`
- `SECP256R1MLKEM768`
- `0x11ec`

### Classical only

- `RSA`
- `DH`
- `DHE`
- `ECDHE`
- `X25519`
- `X448`

Interpretation:
- Pure `ML-KEM-*` is a PQC KEM.
- `X25519MLKEM768` and similar groups are hybrid transitional groups.
- `ECDHE`, `X25519`, and `RSA` remain classical and quantum-vulnerable.

## Certificate and signature families

### PQC signatures

- `ML-DSA-44`
- `ML-DSA-65`
- `ML-DSA-87`
- `SLH-DSA`
- `SLH-DSA-128s`

### Classical signatures

- `RSA`
- `RSA-2048`
- `RSA-4096`
- `ECDSA`
- `ECDSA-P256`
- `ECDSA-P384`
- `ECDSA-P521`
- `ED25519`
- `ED448`

Interpretation:
- PQC certificates are required for `FULLY_QUANTUM_SAFE`.
- Classical certificates with ML-KEM still count as `PQC_TRANSITION`.

## Protocol posture

- `TLSv1.3`
  - required for transition or fully-safe posture
- `TLSv1.2`
  - modern enough to avoid immediate critical posture in many cases, but not sufficient for native PQC transition
- `TLSv1.1`
- `TLSv1.0`
- `SSLv3`
- `SSLv2`
  - treated as legacy / critical

## Symmetric cipher posture

### Strong / acceptable in this model

- `AES-256-GCM`
- `TLS_AES_256_GCM_SHA384`
- `ChaCha20-Poly1305`
- `AES-192`
- `AES-128-GCM`

### Weak / vulnerable

- `3DES`
- `RC4`
- `NULL`
- low-bit legacy CBC suites

## Scoring dimensions

The live classifier scores these dimensions:

- TLS version
- Key exchange
- Certificate / signature
- Cipher strength
- Crypto agility

The final dashboard tier is not based on score alone. Algorithm posture also matters, especially:

- ML-KEM without PQC certificate -> `PQC_TRANSITION`
- Hybrid PQC without PQC certificate -> `PQC_TRANSITION`
- PQC KEX + PQC certificate + TLS 1.3 -> `FULLY_QUANTUM_SAFE`
