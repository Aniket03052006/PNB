# Q-ARMOR: Quantum-Aware Mapping & Observation for Risk Remediation

A cryptographic scanner and inventory engine that discovers quantum-vulnerable cryptography across a bank's public-facing assets, assesses each endpoint against the **NIST PQC Validation Matrix**, and produces a **Cryptographic Bill of Materials (CBOM)** in the industry-standard **CycloneDX 1.6** format — with an actionable **PQC migration roadmap**.

> **Scan. Classify. Assess. Remediate. Future-proof.**

> Built for the **Punjab National Bank (PNB) Cybersecurity Hackathon 2025-26**.

---

## Table of Contents

- [Overview](#overview)
- [Architecture](#architecture)
- [Features](#features)
- [Phase 1 — CLI Scanner](#phase-1--cli-scanner)
- [Phase 2 — PQC Assessment & Remediation](#phase-2--pqc-assessment--remediation)
- [Tech Stack](#tech-stack)
- [Project Structure](#project-structure)
- [Setup & Installation](#setup--installation)
- [Running the Application](#running-the-application)
- [CLI Scanner Usage](#cli-scanner-usage)
- [Dashboard](#dashboard)
- [Testing](#testing)
- [API Reference](#api-reference)
- [How It Works](#how-it-works)
- [NIST PQC Standards](#nist-pqc-standards)
- [Regulatory Alignment](#regulatory-alignment)
- [References](#references)

---

## Overview

Banks have hundreds of public-facing assets (websites, APIs, VPN gateways) that rely on classical cryptography (RSA, ECDSA, AES). These algorithms are mathematically breakable by quantum computers using Shor's algorithm. Nation-state adversaries are already executing **Harvest Now, Decrypt Later (HNDL)** attacks — intercepting encrypted traffic today for future decryption.

Q-ARMOR provides **visibility** into where quantum-vulnerable cryptography exists, then drives the fix with a prioritized remediation roadmap.

---

## Architecture

```
+------------------------------------------------------------------+
|                        Q-ARMOR SYSTEM                            |
|                                                                  |
|  Phase 1: Discovery & Scanning                                   |
|  +-------------+    +----------------+    +------------+         |
|  |   ASSET     |    |  SCAN ENGINE   |    | CBOM GEN   |         |
|  | DISCOVERY   |--->| (Multi-Probe)  |--->| CycloneDX  |         |
|  |   MODULE    |    |                |    |  1.6 JSON  |         |
|  +-------------+    +----------------+    +------------+         |
|        |                    |                    |               |
|        v                    v                    v               |
|  +-------------+    +----------------+    +------------+         |
|  | - DNS enum  |    | - TLS handshake|    |  PQC RISK  |         |
|  | - CT logs   |    | - Cipher suite |    |  SCORING   |         |
|  | - Port scan |    | - Cert chain   |    |  ENGINE    |         |
|  |             |    | - Key exchange |    |            |         |
|  |             |    | - PQC detect   |    |  LABEL     |         |
|  |             |    |                |    |  ISSUER    |         |
|  +-------------+    +----------------+    +------------+         |
|                                                                  |
|  Phase 2: PQC Assessment & Remediation                           |
|  +----------------+   +------------------+   +--------------+    |
|  | NIST PQC       |   |  ASSESSMENT      |   | REMEDIATION  |   |
|  | VALIDATION     |-->|  ENGINE          |-->| GENERATOR    |   |
|  | MATRIX         |   | (4-dimension)    |   | (prioritised)|   |
|  +----------------+   +------------------+   +--------------+    |
|        |                      |                     |            |
|        v                      v                     v            |
|  +----------------+   +------------------+   +--------------+    |
|  | - KEX classify |   | - Per-endpoint   |   | - P1 Critical|   |
|  | - Sig classify |   |   risk scoring   |   | - P2 High    |   |
|  | - TLS classify |   | - HNDL detection |   | - P3 Medium  |   |
|  | - Sym classify |   | - Aggregate KPIs |   | - P4 Low     |   |
|  | - Hybrid detect|   | - Batch analysis |   | - Roadmap    |   |
|  +----------------+   +------------------+   +--------------+    |
|                                                                  |
|  +------------------------------------------------------------+ |
|  |                  DASHBOARD (HTML/CSS/JS)                    | |
|  |  Overview | PQC Assessment | Remediation Plan | NIST Matrix| |
|  |  Donut Charts | Dimension Bars | Risk Table | HNDL Status  | |
|  +------------------------------------------------------------+ |
+------------------------------------------------------------------+
```

---

## Features

| Feature | Description |
|---------|-------------|
| Asset Discovery | DNS subdomain enumeration, Certificate Transparency logs (crt.sh), port scanning |
| TLS Probing | Full SSL/TLS handshake analysis — version, cipher suite, key exchange, certificate inspection |
| PQC Classification | Deterministic Q-Score (0-100) based on NIST FIPS 203/204/205 |
| CBOM Generation | OWASP CycloneDX 1.6 compliant JSON output |
| PQC Labels | Verifiable certification for quantum-safe assets |
| **NIST Validation Matrix** | Classifies every algorithm as Vulnerable / Weakened / Hybrid PQC / PQC Safe / Compliant |
| **4-Dimension Assessment** | Per-endpoint evaluation: TLS protocol, Key Exchange, Certificate, Symmetric Cipher |
| **HNDL Detection** | Identifies endpoints vulnerable to Harvest-Now, Decrypt-Later attacks |
| **Remediation Roadmap** | Prioritized 4-tier action plan (P1 Critical → P4 Low) with concrete steps and timelines |
| **Interactive Dashboard** | 4-tab HTML/CSS/JS dashboard with donut charts, dimension bars, risk tables, and strategic roadmap |
| Demo Mode | 21 pre-configured simulated bank assets for hackathon demonstration |

---

## Phase 1 — CLI Scanner

Phase 1 delivers a **standalone command-line extraction engine** — the foundation upon which all subsequent phases (classification, CBOM generation, remediation) are built.

### What Phase 1 Does

| Capability | Detail |
|-----------|--------|
| **TLS Handshake** | Connects to any target:port using Python `socket` + `ssl`, with verification disabled so expired / self-signed certs are analysed without dropping the connection |
| **Protocol Extraction** | Captures negotiated TLS version (e.g. TLSv1.3), cipher suite, cipher bits, and SNI |
| **Certificate Parsing** | Parses the leaf X.509 certificate via the `cryptography` library — subject, issuer, validity window, public-key algorithm & size, signature algorithm, SANs |
| **Concurrency** | `concurrent.futures.ThreadPoolExecutor` drives parallel scans when a target list is supplied |
| **JSON Output** | Clean `json.dumps()` output to stdout (or file via `--output`), ready for piping into downstream tooling |
| **Robust Error Handling** | Unreachable hosts, DNS failures, and socket timeouts are caught gracefully — the scanner never crashes mid-batch |

### Quick Start (Phase 1)

```bash
# Single target
python scan.py --target google.com

# Custom port
python scan.py --target 10.0.0.1 --port 8443

# Batch scan from a file
python scan.py --list targets.txt

# Save JSON report
python scan.py --target pnbindia.in --output pnb_report.json

# Verbose logging
python scan.py --target example.com -v
```

---

## Phase 2 — PQC Assessment & Remediation

Phase 2 adds a **NIST PQC Validation Matrix**, **4-dimension assessment engine**, **HNDL detection**, and a **prioritised remediation generator** — evaluated per-endpoint and aggregated into dashboard KPIs.

### NIST Validation Matrix (`nist_matrix.py`)

Every cryptographic algorithm encountered during scanning is classified into one of six quantum-vulnerability statuses:

| Status | Meaning |
|--------|---------|
| `VULNERABLE` | Broken by Shor's algorithm (RSA, ECDSA, ECDHE, DH) |
| `WEAKENED` | Security halved by Grover's algorithm (AES-128, 3DES) |
| `LEGACY_PROTOCOL` | Deprecated protocol that cannot negotiate PQC (TLS 1.0/1.1, SSLv3) |
| `HYBRID_PQC` | Transitional classical + PQC hybrid (e.g., X25519MLKEM768) |
| `PQC_SAFE` | NIST-approved post-quantum algorithm (ML-KEM-768, ML-DSA-65) |
| `COMPLIANT` | Meets current best practice (TLS 1.3, AES-256-GCM) |

### Assessment Engine (`assessment.py`)

Each endpoint is evaluated across **4 cryptographic dimensions**:

1. **TLS Protocol** — Is TLS 1.3 in use? (Required for PQC key exchange groups)
2. **Key Exchange** — Vulnerable / Hybrid / PQC-Safe classification
3. **Certificate** — Signature algorithm quantum vulnerability
4. **Symmetric Cipher** — Grover's algorithm impact (AES-128 → 64-bit effective)

Output includes:
- Per-endpoint `overall_quantum_risk`: `HIGH` / `MEDIUM` / `LOW`
- `hndl_vulnerable` flag — Harvest-Now, Decrypt-Later detection
- Detailed findings and NIST references

### Remediation Generator (`remediation.py`)

For each non-compliant dimension, generates prioritised actions:

| Priority | Timeframe | Example |
|----------|-----------|---------|
| **P1 CRITICAL** | 0–30 days | Disable deprecated TLS, enable PQC KEX |
| **P2 HIGH** | 30–90 days | HNDL advisory, certificate migration planning |
| **P3 MEDIUM** | 90–180 days | Upgrade AES-128 to AES-256, enable hybrid mode |
| **P4 LOW** | 180–365 days | Migrate from hybrid to pure PQC KEX |

### CLI Assessment

```bash
# Run scan with Phase 2 assessment
python scan.py --target google.com --assess

# Export full Phase 2 report as JSON
python scan.py --target google.com --assess --format assess --output report.json

# Batch assessment
python scan.py --list targets.txt --assess
```

---

## Tech Stack

| Component | Technology |
|-----------|-----------|
| Backend | Python 3.11+, FastAPI, Uvicorn |
| Scanning | Python `ssl`, `socket`, `dns.resolver`, `cryptography` |
| Data Models | Pydantic v2 |
| HTTP Client | httpx (for CT log queries) |
| Frontend | Vanilla HTML, CSS, JavaScript |
| CBOM Format | OWASP CycloneDX 1.6 JSON |
| PQC Standards | NIST FIPS 203 (ML-KEM), FIPS 204 (ML-DSA), FIPS 205 (SLH-DSA) |

---

## Project Structure

```
Q-ARMOR/
|-- scan.py                          # CLI scanner entry point (Phase 1 + Phase 2)
|-- run.py                           # Web dashboard entry point
|-- requirements.txt                 # Python dependencies
|-- .gitignore
|-- README.md                        # This file
|
|-- src/                             # Phase 1 CLI scanner modules
|   |-- __init__.py
|   |-- models.py                    # Dataclasses (TLSConnectionState, CertificateMetadata, ScanResult)
|   |-- prober.py                    # Network prober — socket/ssl TLS handshake
|   |-- cert_parser.py              # X.509 certificate parser (cryptography lib)
|   +-- scanner.py                   # Orchestrator — ThreadPoolExecutor concurrency
|
|-- backend/                         # Web dashboard backend
|   |-- __init__.py
|   |-- app.py                       # FastAPI application & API routes (Phase 1 + Phase 2)
|   |-- models.py                    # Pydantic data models
|   |-- demo_data.py                 # Simulated bank asset dataset
|   |
|   +-- scanner/
|       |-- __init__.py
|       |-- discoverer.py            # Module 1: Asset discovery
|       |-- prober.py                # Module 2: TLS/crypto fingerprinting (async)
|       |-- classifier.py            # Module 3: PQC risk scoring
|       |-- cbom_generator.py        # Module 4: CycloneDX 1.6 CBOM
|       |-- label_issuer.py          # Module 5: PQC label generation
|       |-- nist_matrix.py           # Module 6: NIST PQC Validation Matrix (Phase 2)
|       |-- assessment.py            # Module 7: 4-Dimension Assessment Engine (Phase 2)
|       +-- remediation.py           # Module 8: Prioritised Remediation Generator (Phase 2)
|
|-- frontend/
|   |-- index.html                   # Dashboard SPA (4-tab: Overview, Assessment, Remediation, Matrix)
|   |-- css/
|   |   +-- styles.css               # Cybersecurity dark theme + Phase 2 chart/table styles
|   +-- js/
|       +-- app.js                   # Dashboard controller (Phase 1 + Phase 2 rendering)
|
|-- tests/
|   +-- test_classifier.py           # Unit tests for PQC classifier
|
+-- docs/
    |-- ARCHITECTURE.md              # System architecture details
    +-- API.md                       # API endpoint documentation
```

---

## Setup & Installation

### Prerequisites

- **Python 3.11+** (3.10 minimum)
- **pip** (Python package manager)

### Step-by-Step

1. **Clone the repository**
   ```bash
   git clone <repo-url>
   cd PNB
   ```

2. **Create a virtual environment** (recommended)
   ```bash
   python3 -m venv venv
   source venv/bin/activate      # macOS/Linux
   # venv\Scripts\activate       # Windows
   ```

3. **Install dependencies**
   ```bash
   pip install -r requirements.txt
   ```

---

## Running the Application

### Phase 1: CLI Scanner

```bash
# Scan a single target
python scan.py --target google.com

# Scan a single target on a custom port
python scan.py --target 192.168.1.10 --port 8443

# Scan multiple targets from a file (one hostname per line)
python scan.py --list targets.txt

# Increase concurrency (default: auto)
python scan.py --list targets.txt --workers 16

# Save JSON report to file
python scan.py --target pnbindia.in --output report.json

# Verbose mode (debug logging to stderr)
python scan.py --target example.com -v
```

#### Sample targets.txt

```text
# PNB public-facing assets
pnbindia.in
netpnb.com
pnbnet.net.in
google.com
cloudflare.com
```

### Web Dashboard

```bash
python run.py
```

The server starts at **http://localhost:8000**.

### Access the dashboard

Open your browser and navigate to:

```
http://localhost:8000
```

### Run a demo scan

Click the **"Run Demo Scan"** button on the dashboard, or call the API directly:

```bash
curl http://localhost:8000/api/scan/demo
```

### Scan a real domain

```bash
curl -X POST http://localhost:8000/api/scan/domain/example.com
```

### Probe a single host

```bash
curl http://localhost:8000/api/scan/single/google.com?port=443
```

### Export CBOM

After running a scan, export the CycloneDX 1.6 CBOM:

```bash
curl http://localhost:8000/api/cbom -o qarmor-cbom.json
```

---

## CLI Scanner Usage

### Command-Line Arguments

| Argument | Short | Required | Default | Description |
|----------|-------|----------|---------|-------------|
| `--target` | `-t` | Yes* | — | Single target hostname or IP |
| `--list` | `-l` | Yes* | — | Path to file with one target per line |
| `--port` | `-p` | No | `443` | Destination TCP port |
| `--workers` | `-w` | No | auto | Thread-pool size for concurrent scans |
| `--output` | `-o` | No | stdout | Write JSON report to this file |
| `--verbose` | `-v` | No | off | Enable debug logging to stderr |

*`--target` and `--list` are mutually exclusive; one is required.

### JSON Output Schema

```json
{
  "scanner": "Q-ARMOR ACDI Scanner",
  "version": "1.0.0",
  "phase": "Phase 1 — Core Discovery & Protocol Analysis",
  "scan_started": "2026-03-10T12:00:00Z",
  "scan_finished": "2026-03-10T12:00:03Z",
  "total_targets": 1,
  "successful": 1,
  "failed": 0,
  "results": [
    {
      "target": "example.com",
      "port": 443,
      "status": "success",
      "scan_timestamp": "2026-03-10T12:00:00Z",
      "scan_duration_ms": 245,
      "connection": {
        "target": "example.com",
        "port": 443,
        "ip_address": "93.184.216.34",
        "sni": "example.com",
        "tls_version": "TLSv1.3",
        "cipher_suite": "TLS_AES_256_GCM_SHA384",
        "cipher_protocol": "TLSv1.3",
        "cipher_bits": 256
      },
      "certificate": {
        "subject": "CN=www.example.org, O=Internet Corporation for Assigned Names and Numbers, ...",
        "issuer": "CN=DigiCert TLS RSA SHA256 2020 CA1, O=DigiCert Inc, C=US",
        "serial_number": "0FDA3EB26...",
        "not_valid_before": "2024-01-30T00:00:00Z",
        "not_valid_after": "2025-03-01T23:59:59Z",
        "public_key_algorithm": "RSA",
        "public_key_size": 2048,
        "signature_algorithm": "sha256WithRSAEncryption",
        "signature_hash_algorithm": "sha256",
        "subject_alternative_names": ["www.example.org", "example.net", "example.org"],
        "is_expired": false,
        "days_until_expiry": 356,
        "is_self_signed": false
      }
    }
  ]
}
```

---

## Dashboard

The web dashboard is a **4-tab HTML/CSS/JS single-page application** served by FastAPI.

### Tab 1: Overview
- **Stats Grid** — Total assets, Quantum Safe, PQC Transition, Vulnerable, Critical
- **Asset Inventory Table** — Sorted by Q-Score, shows TLS version, KEX, cert algorithm, status badge
- **Q-Score Ring** — Animated SVG ring with distribution bars

### Tab 2: PQC Assessment
- **KPI Cards** — Assessed endpoints, High/Medium/Low risk counts, HNDL exposed count
- **Donut Charts** — Key Exchange status, TLS compliance, Risk distribution (Canvas-rendered)
- **Dimension Breakdown Bars** — Stacked bars for KEX, TLS, Certificate, Symmetric, HNDL
- **Per-Endpoint Assessment Table** — Risk badge, TLS/KEX/Cert/Sym status pills, HNDL indicator

### Tab 3: Remediation Plan
- **Priority Cards** — Total actions, P1 Critical, P2 High, P3 Medium, P4 Low
- **Category Bars** — Actions by category (TLS, KEX, Certificate, Symmetric, HNDL advisory)
- **Strategic Roadmap** — Timeline view grouped by phase with detailed steps and impact warnings

### Tab 4: NIST Matrix
- **Vulnerable Algorithms** — Red-tagged list of quantum-vulnerable algorithms
- **PQC-Safe Algorithms** — Green-tagged NIST-approved post-quantum algorithms
- **Hybrid PQC Algorithms** — Blue-tagged transitional hybrid algorithms

---

## Testing

### Run unit tests

```bash
python -m pytest tests/ -v
```

### Test individual API endpoints

```bash
# Health check
curl http://localhost:8000/api/health

# Demo scan
curl http://localhost:8000/api/scan/demo | python -m json.tool

# Summary stats
curl http://localhost:8000/api/summary

# Remediation roadmap
curl http://localhost:8000/api/remediation

# PQC labels
curl http://localhost:8000/api/labels

# CBOM export
curl http://localhost:8000/api/cbom | python -m json.tool
```

### Validate CBOM output

The CBOM output follows the OWASP CycloneDX 1.6 specification. Key fields to verify:

- `bomFormat` = `"CycloneDX"`
- `specVersion` = `"1.6"`
- Each component has `cryptoProperties`, `certificates`, and `pqcAssessment`
- Q-ARMOR custom properties are prefixed with `qarmor:`

---

## API Reference

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/health` | Service health check |
| GET | `/api/scan/demo` | Run demo scan with 15 simulated bank assets |
| POST | `/api/scan/domain/{domain}` | Discover and scan all assets for a domain |
| GET | `/api/scan/single/{hostname}?port=443` | Probe a single hostname:port |
| GET | `/api/cbom` | Export latest scan as CycloneDX 1.6 CBOM JSON |
| GET | `/api/summary` | Get summary statistics of latest scan |
| GET | `/api/remediation` | Get prioritized remediation roadmap |
| GET | `/api/labels` | Get all PQC-Ready labels issued |
| GET | `/api/assess` | Run Phase 2 PQC assessment on latest scan |
| GET | `/api/assess/endpoint/{hostname}?port=443` | Assess a single endpoint against NIST matrix |
| GET | `/api/assess/remediation` | Get prioritized Phase 2 remediation plan |
| GET | `/api/assess/matrix` | Get full NIST PQC validation matrix reference |

---

## How It Works

### Step 1: Asset Discovery
The discoverer module finds internet-facing assets using DNS subdomain brute-forcing, Certificate Transparency log queries (crt.sh), and port scanning.

### Step 2: Cryptographic Fingerprinting
For each asset, the prober performs a full TLS handshake to extract:
- TLS version (1.0, 1.1, 1.2, 1.3)
- Negotiated cipher suite
- Key exchange algorithm (RSA, ECDHE, ML-KEM)
- Certificate signature algorithm
- Public key type and size

### Step 3: PQC Risk Classification
The classifier scores each asset on a 0-100 Q-Score:

| Dimension | Max Points |
|-----------|-----------|
| TLS Version | 30 |
| Key Exchange Algorithm | 30 |
| Certificate Algorithm | 25 |
| Cipher Strength | 15 |

| Q-Score | Status | Meaning |
|---------|--------|---------|
| 90-100 | Fully Quantum Safe | ML-KEM + ML-DSA deployed |
| 70-89 | PQC Transition | Hybrid mode active |
| 40-69 | Quantum Vulnerable | Classical crypto only |
| 0-39 | Critically Vulnerable | Deprecated TLS or weak keys |

### Step 4: CBOM Generation
All results are aggregated into a CycloneDX 1.6 JSON document — compatible with SBOM toolchains like Dependency-Track.

### Step 5: Label Issuance
Compliant assets receive a PQC-Ready label with algorithm details and validity period.

### Step 6: Remediation Roadmap
Non-compliant assets get a prioritized action plan:
- **P1 (0-30 days)**: Disable deprecated TLS, replace weak keys
- **P2 (31-90 days)**: Migrate to TLS 1.3, enable forward secrecy
- **P3 (91-180 days)**: Enable hybrid PQC key exchange
- **P4 (180-365 days)**: Full ML-KEM + ML-DSA deployment

### Step 7: NIST PQC Validation (Phase 2)
Every algorithm is mapped through the NIST Validation Matrix across 6 quantum-readiness levels:
`VULNERABLE → WEAKENED → LEGACY_PROTOCOL → HYBRID_PQC → PQC_SAFE → COMPLIANT`

Four assessment dimensions are evaluated per endpoint:
- **TLS Protocol** — Version compliance (1.3 = Pass, ≤1.1 = Fail)
- **Key Exchange** — KEX quantum safety (ML-KEM = Safe, RSA = Vulnerable)
- **Certificate** — Signature algorithm strength (ML-DSA = Safe, RSA-2048 = Vulnerable)
- **Symmetric Cipher** — Block cipher strength (AES-256 = Safe, 3DES = Vulnerable)

### Step 8: Strategic Remediation Generation (Phase 2)
Based on assessment results, a multi-phase migration roadmap is generated with:
- Per-endpoint prioritized actions (P1–P4)
- Aggregate statistics by priority and category
- HNDL (Harvest Now, Decrypt Later) exposure warnings
- Phase-grouped strategic roadmap for organizational planning

---

## NIST PQC Standards

Q-ARMOR benchmarks against three finalized NIST standards (August 2024):

| Standard | Algorithm | Replaces | Use Case |
|----------|-----------|----------|----------|
| FIPS 203 | ML-KEM | RSA/ECDH | Key Exchange |
| FIPS 204 | ML-DSA | RSA/ECDSA | Digital Signatures |
| FIPS 205 | SLH-DSA | — | Hash-Based Signatures (backup) |

---

## Regulatory Alignment

| Regulation | How Q-ARMOR Supports |
|------------|---------------------|
| RBI Cybersecurity Framework | Automated cryptographic asset inventory |
| SEBI Cyber Resilience | Continuous security assessment of internet-facing systems |
| NIST CSF 2.0 | Identify function — current inventory of cryptographic assets |
| ISO 27001:2022 (A.8.24) | Use of Cryptography audit |
| DORA (EU) | ICT risk management including cryptographic hygiene |

---

## References

1. PQCC (2023). *Transitioning to Quantum-Safe Cryptography: Exploring the Role and Value for Developing and Implementing a CBOM.*
2. Vallivaara et al. (2024). *Supporting PQC migration with automated CBOM generation.* University of Jyvaskyla.
3. OWASP CycloneDX. *CBOM Specification v1.6.* cyclonedx.org
4. NIST (August 2024). *FIPS 203: ML-KEM Standard.*
5. NIST (August 2024). *FIPS 204: ML-DSA Standard.*
6. NIST (August 2024). *FIPS 205: SLH-DSA Standard.*
7. NSA (2022). *CNSA 2.0 Advisory Guidance.*

---

**Q-ARMOR v2.0.0 — Built for the Quantum-Ready Cybersecurity Track**
