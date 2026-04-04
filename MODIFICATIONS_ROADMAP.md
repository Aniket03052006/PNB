# Q-ARMOR v9.0.0 — Comprehensive Modifications Roadmap

**Project:** Q-ARMOR Post-Quantum Cryptography Scanner  
**Status:** Phase 7-9 Implementation Review & Gap Analysis  
**Date:** April 2, 2026  
**Version:** v9.0.0

---

## EXECUTIVE SUMMARY

**Completion Status:** ~75-80% Core Functionality  
**Critical Gaps:** 12-15 Priority Items  
**Non-Critical Improvements:** 25-30 Enhancement Items  
**Estimated Effort:** 40-60 development hours

This document maps the complete Software Requirements Specification (SRS) against the current codebase implementation and identifies all required modifications for production readiness.

---

## TABLE OF CONTENTS

1. [Implementation Status by Phase](#implementation-status-by-phase)
2. [Critical Issues & Gaps](#critical-issues--gaps)
3. [Feature-by-Feature Analysis](#feature-by-feature-analysis)
4. [Detailed Modification List](#detailed-modification-list)
5. [Testing & QA Checklist](#testing--qa-checklist)
6. [Deployment Readiness](#deployment-readiness)

---

## IMPLEMENTATION STATUS BY PHASE

### Phase 1: Asset Discovery & TLS Protocol Analysis
**Status: ✅ 90% COMPLETE**

**Implemented:**
- ✅ DNS resolution (A/AAAA records)
- ✅ Certificate Transparency log querying
- ✅ Subdomain enumeration via CT logs
- ✅ Discoverability checks
- ✅ Asset type classification
- ✅ Support for IPv4/IPv6

**Gaps & Improvements:**
- ⚠️ `discoverer.py` needs additional port scanning options (currently supports SCAN_PORTS hardcoded)
- ⚠️ API crawl expansion (`LOCAL_API_CRAWL=1`) not fully tested
- ⚠️ Retry logic on DNS failure could be more robust (add exponential backoff)
- ⚠️ CT log query timeout not configurable
- ⚠️ Error handling on discovery missing from some edge cases

**Required Actions:**
- [ ] Add configurable port ranges to `discover_assets()`
- [ ] Implement exponential backoff for DNS retries
- [ ] Add timeout parameter to CT log queries
- [ ] Document rate limiting on CT logs (typically 100 req/sec)
- [ ] Add metrics/logging for discovery performance

---

### Phase 2: TLS Probing
**Status: ✅ 95% COMPLETE**

**Implemented:**
- ✅ Full TLS handshake via Python `ssl` module
- ✅ OpenSSL `s_client` subprocess for ServerHello parsing
- ✅ X.509 certificate extraction and parsing
- ✅ SNI support in all probes
- ✅ Tri-mode probing (Probe A/B/C)
- ✅ Partial fingerprint fallback on error
- ✅ Async/await with semaphore concurrency control
- ✅ PQC algorithm detection

**Gaps & Improvements:**
- ⚠️ `prober.py` needs better error messages for specific failure modes (timeout vs. refused)
- ⚠️ OpenSSL version detection not validated at startup
- ⚠️ OCSP stapling information not extracted
- ⚠️ TLS session resumption (session ID/tickets) not analyzed
- ⚠️ Cipher suite negotiation preferences not ranked

**Required Actions:**
- [ ] Add OpenSSL version check at startup (require 1.1.1+ or 3.x)
- [ ] Validate OpenSSL binary availability before first probe
- [ ] Add OCSP stapling detection to Certificate model
- [ ] Extract and analyze TLS session resumption capability
- [ ] Implement cipher ranking/preference detection
- [ ] Add per-probe timeout configuration

---

### Phase 3: PQC Classification
**Status: ✅ 98% COMPLETE**

**Implemented:**
- ✅ 5-dimension Q-Score (TLS 20 + KEX 30 + Cert 20 + Cipher 15 + Agility 15)
- ✅ Tri-mode scoring (best/typical/worst)
- ✅ 5-tier status assignment (FULLY_QUANTUM_SAFE, PQC_TRANSITION, QUANTUM_VULNERABLE, CRITICALLY_VULNERABLE, UNKNOWN)
- ✅ Backward compatibility with legacy 4-dimension scoring
- ✅ Plain English summary generation
- ✅ Recommended action per asset

**Gaps & Improvements:**
- ⚠️ `classifier.py` QScore computation could include more granular scoring thresholds
- ⚠️ Legacy classifier path not fully tested with Phase 7 data
- ⚠️ Score boundaries hardcoded—should be configurable policy
- ⚠️ Phase 7 Agility indicators need validation metrics
- ⚠️ Score drift detection not in place (for monitoring score consistency)

**Required Actions:**
- [ ] Move score thresholds to configuration file (policy.yaml)
- [ ] Implement score-threshold versioning for policy changes
- [ ] Add test cases for all status boundary conditions
- [ ] Validate agility indicators against real-world data
- [ ] Add score audit trail (what changed and why)
- [ ] Document scoring algorithm with decision tree

---

### Phase 4: Certification Labeling (3-Tier System)
**Status: ✅ 95% COMPLETE**

**Implemented:**
- ✅ 3-tier labeling system (Tier 1/2/3)
- ✅ Label generation from ClassifiedAsset
- ✅ Label summary aggregation
- ✅ Badge colors and icons
- ✅ NIST standards mapping
- ✅ Validity period calculation

**Gaps & Improvements:**
- ⚠️ `labeler.py` tier thresholds hardcoded (TIER_1_MIN_BEST=90, TIER_2_MIN_BEST=70)
- ⚠️ Gap analysis (primary_gap field) only populated for Tier 3
- ⚠️ fix_in_days calculation could be more sophisticated
- ⚠️ Label revocation reasons limited to algorithm regression and cert expiry
- ⚠️ No granularity for hybrid labels (e.g., "95% Tier 1, 5% Tier 2")

**Required Actions:**
- [ ] Move tier thresholds to policy.yaml
- [ ] Implement gap analysis for all tiers
- [ ] Create remediation timeline matrix (based on status + score)
- [ ] Add custom revocation reasons
- [ ] Implement fuzzy tier assignment logic for edge cases
- [ ] Add tier upgrade/downgrade notifications

---

### Phase 5: Compliance Attestation (CDXA)
**Status: ✅ 90% COMPLETE**

**Implemented:**
- ✅ CDXA v2 generation from LabelSummary + CBOM
- ✅ Ed25519 digital signing
- ✅ SHA-256 content hashing
- ✅ 90-day validity window
- ✅ FIPS 203/204/205 compliance claims
- ✅ Auto-generated keypair at `.keys/`
- ✅ FastAPI router with /generate, /download, /verify endpoints

**Gaps & Improvements:**
- ⚠️ `attestor.py` keypair generation not validated at startup
- ⚠️ No key rotation mechanism
- ⚠️ No key storage backup/recovery procedure
- ⚠️ CDXA verification endpoint not fully tested
- ⚠️ No audit trail of attestation-signing events
- ⚠️ Missing FIPS 203/204/205 compliance claims detail
- ⚠️ No integration with external timestamp servers (for non-repudiation)

**Required Actions:**
- [ ] Validate Ed25519 keypair existence and integrity at startup
- [ ] Implement key rotation procedure (with version tracking)
- [ ] Add key backup/recovery documentation
- [ ] Create complete FIPS compliance claim templates
- [ ] Add audit log for all attestation operations
- [ ] Implement external timestamp integration (RFC 3161)
- [ ] Add batch attestation verification endpoint
- [ ] Test signature verification across jurisdictions

---

### Phase 6: Tri-Mode Probing & Asset Discovery Foundation
**Status: ✅ 99% COMPLETE**

**Implemented:**
- ✅ Probe A (PQC-capable client hello)
- ✅ Probe B (TLS 1.3 classical)
- ✅ Probe C (TLS 1.2 downgrade)
- ✅ TriModeFingerprint data structure
- ✅ Demo mode with 21 pre-built fingerprints
- ✅ Tri-mode batch probing with concurrency control

**Gaps & Improvements:**
- ⚠️ No Probe D for TLS 1.0/1.1 extreme downgrade testing
- ⚠️ Custom cipher suite ordering not supported
- ⚠️ Session resumption (cookies/session IDs) not tested across probes
- ⚠️ No "probe replay" for flaky endpoints

**Required Actions:**
- [ ] Add Probe D (TLS 1.0/1.1) as optional extreme-case test
- [ ] Implement custom client cipher suite specification
- [ ] Add session resumption testing
- [ ] Implement automatic retry for transient failures
- [ ] Add probe fingerprint caching (30-sec TTL) to avoid redundant work

---

### Phase 7: Classification + Agility Assessment + SQLite Persistence
**Status: ✅ 95% COMPLETE**

**Implemented:**
- ✅ 5-dimension Q-Score computation
- ✅ Tri-mode ClassifiedAsset (best/typical/worst)
- ✅ Crypto-agility scoring (5 indicators × 3 pts)
- ✅ SQLite WAL-mode database
- ✅ Scan history persistence
- ✅ Asset score table with per-asset history
- ✅ Delta comparison between scans
- ✅ Asset-level score history tracking

**Gaps & Improvements:**
- ⚠️ `database.py` schema not fully normalized (some denormalization for performance)
- ⚠️ No index optimization for common queries
- ⚠️ Scan table doesn't have explicit "domain" field for filtering
- ⚠️ No soft-delete mechanism (for audit compliance)
- ⚠️ Query performance on large datasets not benchmarked
- ⚠️ No backup routine or export capability
- ⚠️ Missing "scan_duration" field in scans table

**Required Actions:**
- [ ] Add indexes to database schema (hostname, timestamp, domain, scan_id)
- [ ] Implement query performance metrics
- [ ] Add domain field to scans table
- [ ] Implement soft-delete pattern for compliance
- [ ] Create database backup routine
- [ ] Add export-to-CSV functionality
- [ ] Benchmark query performance on 10k+ records
- [ ] Add migration script support for schema changes

---

### Phase 8: Regression Detection & Enhanced CBOM v2
**Status: ✅ 90% COMPLETE**

**Implemented:**
- ✅ New asset detection (shadow IT)
- ✅ Score regression detection (≥5 point drops)
- ✅ Missed upgrade detection (cert renewed, algo didn't improve)
- ✅ CycloneDX 1.7 CBOM generation
- ✅ pqcAssessment extension
- ✅ Vulnerability sourcing from regression report
- ✅ Provenance tracking
- ✅ Dependency graph generation

**Gaps & Improvements:**
- ⚠️ `regression_detector.py` urgency calculation could be more granular
- ⚠️ Signature rank hierarchy incomplete (some modern algos missing)
- ⚠️ "Missed upgrade" logic only checks signature algo, not KEX/TLS
- ⚠️ No trend analysis (e.g., "score declining over 3 scans")
- ⚠️ CBOM v2 response compression not optimized
- ⚠️ CBOM versioning field missing
- ⚠️ No CBOM schema validation at generation

**Required Actions:**
- [ ] Expand signature ranking to include all modern algorithms
- [ ] Implement multi-dimensional regression detection (KEX, TLS, cert)
- [ ] Add trend analysis (slope calculation over N scans)
- [ ] Add CBOM versioning field (auto-increment)
- [ ] Implement CBOM schema validation at generation
- [ ] Create CBOM diffing endpoint (compare two CBOMs)
- [ ] Add CBOM upload/comparison endpoint
- [ ] Optimize CBOM response compression

---

### Phase 9: Labeling v2 + Registry + Attestation v2
**Status: ✅ 92% COMPLETE**

**Implemented:**
- ✅ PQCLabelV9 model with full metadata
- ✅ Label registry (append-only log)
- ✅ Label verification (VALID/REVOKED/EXPIRED)
- ✅ Auto-revoke on algorithm regression
- ✅ Auto-revoke on certificate expiry
- ✅ Label listing with filters
- ✅ CDXA v2 with FIPS claims
- ✅ FastAPI router for registry operations

**Gaps & Improvements:**
- ⚠️ `label_registry.py` auto-revoke logic runs at classification time, not continuously
- ⚠️ No label transfer mechanism (if asset migrates to new hostname)
- ⚠️ Revocation audit trail incomplete
- ⚠️ No label inheritance (parent/child relationships)
- ⚠️ Manual revocation endpoint created but not documented
- ⚠️ Label verification doesn't check CBOM consistency
- ⚠️ Missing alert on label expiry approaching

**Required Actions:**
- [ ] Add continuous label expiry checker (run at /api/health)
- [ ] Implement label transfer protocol
- [ ] Create comprehensive revocation audit log
- [ ] Add label hierarchy/inheritance support
- [ ] Document manual revocation endpoint
- [ ] Implement CBOM validation during label verification
- [ ] Add pre-expiry alert notification (30 days before)
- [ ] Create label metadata versioning

---

## CRITICAL ISSUES & GAPS

### Issue #1: Production Readiness — Error Handling
**Severity: HIGH**  
**Affected Components:** `prober.py`, `discoverer.py`, `pipeline.py`  
**Current State:** Basic error handling with UNKNOWN status fallback  
**Problem:** Error messages not distinguishing between transient (retry-able) vs. permanent failures

**Impact:**
- Users uncertain which failures are temporary
- No automatic retry on transient failures
- Dashboard doesn't guide remediation for different error types

**Fix:**
```python
# In prober.py, classify errors:
class ProbeError(Enum):
    TIMEOUT = "timeout"           # Retry possible
    REFUSED = "connection_refused"  # Permanent, re-evaluate endpoint
    TLS_ALERT = "tls_alert"       # Permanent, protocol mismatch
    DNS_FAIL = "dns_failure"      # Retry with backoff
    OPENSSL_FAIL = "openssl_error"  # Check OpenSSL version
    
# Implement exponential backoff for TIMEOUT/DNS_FAIL
```

---

### Issue #2: Database Scalability
**Severity: HIGH**  
**Affected Components:** `database.py`  
**Current State:** SQLite with basic schema, no indexing strategy  
**Problem:** No performance testing on large scans (>1000 assets); missing indexes

**Impact:**
- Slow queries on production datasets
- No scan limits documented
- Unfair comparison with expected performance

**Fix:**
```sql
-- Add to database schema:
CREATE INDEX idx_scans_timestamp ON scans(timestamp);
CREATE INDEX idx_scans_mode ON scans(mode);
CREATE INDEX idx_asset_scores_hostname ON asset_scores(hostname);
CREATE INDEX idx_asset_scores_scan_id ON asset_scores(scan_id);
CREATE INDEX idx_labels_hostname_port ON labels(hostname, port);
CREATE INDEX idx_labels_status ON labels(status);
```

---

### Issue #3: API Authentication — Not Enforced at Entry
**Severity: CRITICAL**  
**Affected Components:** `app.py`, `auth.py`  
**Current State:** Auth middleware implemented but many endpoints lack proper checks  
**Problem:** Some sensitive endpoints (demo/scan) accessible without token; token validation incomplete

**Impact:**
- Potential unauthorized access to scan results
- No rate limiting per user
- No audit trail of who ran which scans

**Fix:**
- [ ] Review all `/api/` endpoints for auth requirement
- [ ] Move authentication check upstream (middleware)
- [ ] Implement per-user rate limiting
- [ ] Add request audit logging
- [ ] Document which endpoints are truly public

---

### Issue #4: Frontend Dashboard — Missing Real-Time Updates
**Severity: MEDIUM**  
**Affected Components:** `frontend/index.html`, `frontend/js/app.js`  
**Current State:** Dashboard polls APIs periodically, no WebSocket support  
**Problem:** Long-scan progress invisible; no feedback during 30-second live scans

**Impact:**
- Users think application hung during scanning
- No way to cancel long scans
- Poor UX for large asset sets

**Fix:**
- [ ] Implement WebSocket endpoint for scan progress
- [ ] Add scan progress bar to dashboard
- [ ] Expose `/api/scan/status/{scan_id}` endpoint
- [ ] Implement server-sent events as fallback

---

### Issue #5: Negotiation Policy — Output Format Unclear
**Severity: MEDIUM**  
**Affected Components:** `negotiation_policy.py`  
**Current State:** `negotiation_security_score` injected into Q-Score during pipeline  
**Problem:** Not clear if policy adjustment is legitimate scoring or post-hoc modification

**Impact:**
- Score audit trail confused by policy adjustments
- Can't distinguish crypto-quality from policy-quality
- Difficult to tune scoring thresholds

**Fix:**
- [ ] Separate negotiation adjustment in output (don't mix into Q-Score)
- [ ] Create separate `negotiation_adjusted_score` field
- [ ] Document policy impact on each score component

---

### Issue #6: Agility Assessment — Validation Against Reality
**Severity: MEDIUM**  
**Affected Components:** `agility_assessor.py`  
**Current State:** 5 indicators hardcoded, no validation  
**Problem:** Indicators don't correlate with actual agility; threshold values arbitrary

**Impact:**
- Agility scores don't predict real migration capacity
- Algorithm diversity doesn't guarantee flexibility

**Fix:**
- [ ] Validate indicators against real-world migrations
- [ ] Add weighting per indicator (not all worth same)
- [ ] Implement feedback loop to adjust thresholds
- [ ] Document agility assumptions

---

### Issue #7: Alert Notifications — Webhook Delivery Not Guaranteed
**Severity: MEDIUM**  
**Affected Components:** `notifier.py`  
**Current State:** Fire-and-forget webhook delivery, no retry  
**Problem:** If Slack/Teams endpoint down, alerts lost silently

**Impact:**
- Critical alerts never reach on-call teams
- No visibility that notification failed
- No fallback mechanism

**Fix:**
- [ ] Implement webhook delivery retry (3x with backoff)
- [ ] Store failed alerts in database queue
- [ ] Add alert delivery status API endpoint
- [ ] Log all webhook successes/failures

---

### Issue #8: CBOM Export — No Validation or Versioning
**Severity: MEDIUM**  
**Affected Components:** `cbom_generator.py`  
**Current State:** CBOM generated on-demand, no schema validation  
**Problem:** No guarantee CBOM conforms to CycloneDX 1.7; no versioning if format changes

**Impact:**
- CBOM might not parse in downstream tools
- No forward/backward compatibility guarantee

**Fix:**
- [ ] Add CycloneDX schema validation library (cyclonedx-python)
- [ ] Implement CBOM versioning field
- [ ] Create migration scripts for old CBOM versions
- [ ] Add CBOM compliance test endpoint

---

### Issue #9: Demo Data Inconsistency
**Severity: MEDIUM**  
**Affected Components:** `demo_data.py`  
**Current State:** 21 assets hardcoded with static fingerprints  
**Problem:** Demo doesn't evolve; real scenarios have dynamic assets

**Impact:**
- Hard to test regression detection
- Can't simulate real scan progression
- Demo not representative of production

**Fix:**
- [ ] Add parametric demo generator (deterministic but varied)
- [ ] Implement time-decay for score changes (simulate aging)
- [ ] Create scenario-based demos (different bank profiles)
- [ ] Make demo data updatable via API

---

### Issue #10: Testing — Coverage Gaps and Missing Scenarios
**Severity: HIGH**  
**Affected Components:** `tests/test_classifier.py`  
**Current State:** 21 tests covering classifier only  
**Problem:** No tests for pipeline, database, api, regression, attestation, etc.

**Impact:**
- Regressions shipped without detection
- Edge cases not handled
- Confidence in code quality low

**Fix:**
- [ ] Create comprehensive test suite (100+ tests)
- [ ] Add API integration tests
- [ ] Add database persistence tests
- [ ] Add regression detection tests
- [ ] Add attestation verification tests
- [ ] Add end-to-end pipeline tests
- [ ] Add performance/load tests

---

## FEATURE-BY-FEATURE ANALYSIS

### Feature F1: Asset Discovery ✅
- **Status:** 90% complete
- **Missing:** Configurable port ranges, API expansion, retry with backoff
- **Priority:** Medium
- **Effort:** 4-6 hours

### Feature F2: TLS Probing ✅
- **Status:** 98% complete
- **Missing:** OCSP stapling, session resumption, cipher ranking, OpenSSL version check
- **Priority:** Medium
- **Effort:** 6-8 hours

### Feature F3: PQC Classification ✅
- **Status:** 99% complete
- **Missing:** Configurable thresholds, score versioning
- **Priority:** Low
- **Effort:** 2-3 hours

### Feature F4: Status Assignment ✅
- **Status:** 98% complete
- **Missing:** Fuzzy tier assignment for edge cases
- **Priority:** Low
- **Effort:** 1-2 hours

### Feature F5: NIST Assessment ✅
- **Status:** 95% complete
- **Missing:** Enhanced granularity in assessment output
- **Priority:** Low
- **Effort:** 2-3 hours

### Feature F6: Remediation ✅
- **Status:** 90% complete
- **Missing:** Timeline refinement, priority recalculation, integration with ticketing systems
- **Priority:** Medium
- **Effort:** 6-8 hours

### Feature F7: CBOM Export ✅
- **Status:** 92% complete
- **Missing:** Schema validation, versioning, diffing
- **Priority:** High
- **Effort:** 8-10 hours

### Feature F8: Certification Labels ✅
- **Status:** 93% complete
- **Missing:** Fuzzy assignment, hierarchies, transfer protocol
- **Priority:** Medium
- **Effort:** 6-8 hours

### Feature F9: CDXA Attestation ✅
- **Status:** 88% complete
- **Missing:** Key rotation, timestamp server integration, audit trail
- **Priority:** High
- **Effort:** 10-12 hours

### Feature F10: Alert Detection ✅
- **Status:** 85% complete
- **Missing:** Webhook retry, queue, thresholds tuning
- **Priority:** High
- **Effort:** 6-8 hours

### Feature F11: Webhook Notifications ✅
- **Status:** 80% complete
- **Missing:** Retry, failover, Teams adaptive card richness
- **Priority:** High
- **Effort:** 4-6 hours

### Feature F12: CI/CD Gate ✅
- **Status:** 95% complete
- **Missing:** Policy-as-code, custom exit codes
- **Priority:** Low
- **Effort:** 2-3 hours

### Feature F13: Demo Mode ✅
- **Status:** 100% complete
- **Missing:** Parametric variations, scenarios
- **Priority:** Low
- **Effort:** 3-4 hours

### Feature F14: Phase 7 Classification ✅
- **Status:** 97% complete
- **Missing:** Score audit trail, policy versioning
- **Priority:** Medium
- **Effort:** 4-5 hours

### Feature F15: Agility Assessment ✅
- **Status:** 85% complete
- **Missing:** Real-world validation, weighting, feedback loop
- **Priority:** Medium
- **Effort:** 8-10 hours

### Feature F16: SQLite Persistence ✅
- **Status:** 90% complete
- **Missing:** Indexing, backup, export, schema versioning
- **Priority:** High
- **Effort:** 8-10 hours

### Feature F17: Regression Detection ✅
- **Status:** 88% complete
- **Missing:** Trend analysis, multi-dimensional detection
- **Priority:** High
- **Effort:** 6-8 hours

### Feature F18: CycloneDX 1.7 CBOM ✅
- **Status:** 90% complete
- **Missing:** Validation, versioning, diffing
- **Priority:** High
- **Effort:** 8-10 hours

### Feature F19: Phase 9 PQC Labeling ✅
- **Status:** 92% complete
- **Missing:** Transfer, inheritance, expiry alerts
- **Priority:** Medium
- **Effort:** 6-8 hours

### Feature F20: Label Registry ✅
- **Status:** 90% complete
- **Missing:** Audit trail, transfer protocol
- **Priority:** Medium
- **Effort:** 4-6 hours

### Feature F21: FIPS Attestation v2 ✅
- **Status:** 88% complete
- **Missing:** detailed claims, timestamp integration
- **Priority:** High
- **Effort:** 6-8 hours

---

## DETAILED MODIFICATION LIST

### TIER 1: CRITICAL (Block Production)

#### 1.1 Database — Add Schema Indexes
**File:** `backend/scanner/database.py`  
**Change Type:** Schema Addition  
**Effort:** 2 hours

```python
# In init_db(), add indexes:
def init_db():
    """Initialize SQLite database with optimized schema."""
    with _connect() as conn:
        conn.executescript("""
            -- Existing tables...
            
            -- NEW: Performance indexes
            CREATE INDEX IF NOT EXISTS idx_scans_timestamp 
                ON scans(timestamp DESC);
            CREATE INDEX IF NOT EXISTS idx_scans_mode_timestamp 
                ON scans(mode, timestamp DESC);
            CREATE INDEX IF NOT EXISTS idx_asset_scores_scan_hostname 
                ON asset_scores(scan_id, hostname);
            CREATE INDEX IF NOT EXISTS idx_labels_hostname_port 
                ON labels(hostname, port);
            CREATE INDEX IF NOT EXISTS idx_labels_status 
                ON labels(status);
            CREATE INDEX IF NOT EXISTS idx_alerts_scan_severity 
                ON alerts(scan_id, severity);
        """)
```

---

#### 1.2 Authentication — Enforce on All API Endpoints
**File:** `backend/app.py`  
**Change Type:** Logic Enhancement  
**Effort:** 3 hours

**Current:**
```python
@app.middleware("http")
async def enforce_api_auth(request: Request, call_next):
    path = request.url.path
    if request.method == "OPTIONS" or _is_public_path(path) or not path.startswith("/api/"):
        return await call_next(request)
```

**Required:**
- [ ] Audit all 45+ API endpoints
- [ ] Document PUBLIC_ROUTES explicitly
- [ ] Move `/api/scan/demo`, `/api/classify/demo` to authenticated-only (or allow via API key)
- [ ] Implement per-user rate limiting in auth middleware
- [ ] Add request ID/user ID logging to all endpoints

---

#### 1.3 Error Handling — Distinguish Transient vs. Permanent Failures
**File:** `backend/scanner/prober.py`  
**Change Type:** Enhancement  
**Effort:** 4 hours

**Add:**
```python
class ProbeFailureType(str, Enum):
    """Classify probe failures for retry logic."""
    TIMEOUT = "timeout"              # Retry w/ backoff
    REFUSED = "connection_refused"   # Permanent
    TLS_ALERT = "tls_alert"         # Permanent
    DNS_FAILURE = "dns_failure"     # Retry w/ backoff
    OPENSSL_ERROR = "openssl_error"  # Check config
    UNKNOWN = "unknown_error"        # Retry cautiously

def probe_tls(...) -> ProbeProfile:
    """Enhanced error classification."""
    try:
        # existing code
    except socket.timeout:
        return ProbeProfile(
            error=f"Timeout after {timeout}s",
            failure_type=ProbeFailureType.TIMEOUT
        )
    except ConnectionRefusedError:
        return ProbeProfile(
            error="Connection refused",
            failure_type=ProbeFailureType.REFUSED
        )
    # ... more specific exceptions
```

---

#### 1.4 Webhook Delivery — Implement Retry & Queue
**File:** `backend/scanner/notifier.py`  
**Change Type:** Major Enhancement  
**Effort:** 5 hours

**Required:**
- [ ] Implement 3x retry with exponential backoff (1s, 5s, 30s)
- [ ] Store failed alerts in database queue
- [ ] Add `/api/alerts/queue` endpoint to check pending notifications
- [ ] Log all webhook send attempts
- [ ] Create alert delivery status dashboard

**Code sketch:**
```python
async def send_alerts_reliable(alerts: list[dict[str, Any]]):
    """Send alerts with retry and fallback queueing."""
    for alert in alerts:
        try:
            await _send_to_webhooks_with_retry(alert)
        except Exception as e:
            logger.error(f"Failed to send alert {alert['id']}: {e}")
            db.queue_alert_for_retry(alert)
```

---

#### 1.5 CBOM Generation — Add Schema Validation
**File:** `backend/scanner/cbom_generator.py`  
**Change Type:** Enhancement  
**Effort:** 4 hours

**Required:**
- [ ] Add `cyclonedx` package to requirements
- [ ] Validate CBOM structure against CycloneDX 1.7 schema
- [ ] Add `/api/cbom/validate` endpoint
- [ ] Implement CBOM versioning field
- [ ] Create CBOM migration guide for format changes

```python
from cyclonedx.model import Bom
from cyclonedx.validation import validate

def generate_cbom_v2(...) -> dict:
    """Generate and validate CycloneDX 1.7 CBOM."""
    # ... existing generation code ...
    
    # NEW: Validate
    bom_json = json.loads(json.dumps(cbom_dict))
    try:
        bom = Bom.model_validate(bom_json)
        logger.info(f"CBOM validation passed: {bom.serial_number}")
    except Exception as e:
        logger.error(f"CBOM validation failed: {e}")
        # Still return, but flag as unvalidated
        cbom_dict["validation_status"] = "FAILED"
        cbom_dict["validation_error"] = str(e)
    
    return cbom_dict
```

---

#### 1.6 Assessment Engine — Document NIST Matrix
**File:** `backend/scanner/assessment.py` + `docs/`  
**Change Type:** Documentation + Code  
**Effort:** 3 hours

**Required:**
- [ ] Document NIST matrix evaluation logic with decision tree
- [ ] Create assessment examples in docs
- [ ] Add comments to assessment.py code
- [ ] Link to NIST FIPS 203/204/205 specs

---

### TIER 2: HIGH PRIORITY (Production Quality)

#### 2.1 Database Backup & Export
**File:** `backend/scanner/database.py`  
**Change Type:** New Feature  
**Effort:** 4 hours

**Add:**
- [ ] `export_scan_to_csv(scan_id) -> str` (CSV)
- [ ] `export_all_labels_to_csv() -> str`
- [ ] `/api/db/export/csv?type=scans|labels|alerts` endpoint
- [ ] Backup routine documentation

---

#### 2.2 Agility Assessment — Real-World Validation
**File:** `backend/scanner/agility_assessor.py`  
**Change Type:** Enhancement  
**Effort:** 8 hours

**Required:**
- [ ] Add weighting to indicators (not all 3 pts each)
- [ ] Validate CDN detection accuracy
- [ ] Validate software currency detection
- [ ] Validate ACME CA detection
- [ ] Create test set of known-good and known-bad assets
- [ ] Document agility assumptions

---

#### 2.3 Regression Detection — Multi-Dimensional
**File:** `backend/scanner/regression_detector.py`  
**Change Type:** Enhancement  
**Effort:** 6 hours

**Required:**
- [ ] Detect regression in KEX algorithm
- [ ] Detect TLS version downgrade
- [ ] Detect certificate chain weakening
- [ ] Add trend analysis (score slope over 3+ scans)
- [ ] Implement urgency matrix (multi-factor)

---

#### 2.4 Dashboard — Real-Time Scan Progress
**File:** `frontend/js/app.js` + `backend/app.py`  
**Change Type:** Major Feature  
**Effort:** 8 hours

**Required:**
- [ ] Add `/api/scan/status/{scan_id}` endpoint
- [ ] Implement WebSocket for progress updates
- [ ] Add user-facing progress bar
- [ ] Allow scan cancellation
- [ ] Add estimated time remaining

---

#### 2.5 Attestation — Key Rotation & Backup
**File:** `backend/scanner/attestor.py`  
**Change Type:** Enhancement  
**Effort:** 6 hours

**Required:**
- [ ] Implement key rotation procedure
- [ ] Add key versioning
- [ ] Document backup/recovery steps
- [ ] Implement timestamp server integration (RFC 3161)
- [ ] Add key management API endpoints

---

#### 2.6 Negotiation Policy — Separate Scoring
**File:** `backend/pipeline.py` + `backend/scanner/negotiation_policy.py`  
**Change Type:** Refactoring  
**Effort:** 4 hours

**Required:**
- [ ] Don't modify Q-Score in place
- [ ] Create separate `negotiation_adjusted_score` field
- [ ] Document policy impact separately
- [ ] Add audit trail of adjustments

---

#### 2.7 Config File Support
**File:** New `config/` directory  
**Change Type:** New Feature  
**Effort:** 5 hours

**Required:**
- [ ] Create `config/scoring.yaml` (Q-Score thresholds)
- [ ] Create `config/alert_policies.yaml` (alert triggers)
- [ ] Create `config/discovery.yaml` (port ranges, CT log settings)
- [ ] Implement environment variable overrides
- [ ] Add config validation at startup

---

### TIER 3: MEDIUM PRIORITY (Feature Completeness)

#### 3.1 Phase Badges & Status Indicators
**File:** `frontend/`, `backend/models.py`  
**Change Type:** UI Enhancement  
**Effort:** 3 hours

**Required:**
- [ ] Expose phase completion status in API
- [ ] Add phase badges to dashboard
- [ ] Document what each phase delivers

---

#### 3.2 Label Transfer Protocol
**File:** `backend/scanner/label_registry.py`  
**Change Type:** New Feature  
**Effort:** 5 hours

**Required:**
- [ ] `/api/registry/transfer/{label_id}` endpoint
- [ ] Allow hostname/IP change
- [ ] Maintain chain of custody
- [ ] Update validity period

---

#### 3.3 Scan History UI Improvements
**File:** `frontend/index.html`  
**Change Type:** UI Enhancement  
**Effort:** 4 hours

**Required:**
- [ ] Historical trend charts
- [ ] Scan comparison UI
- [ ] Asset timeline view
- [ ] Filter by hostname, status, date range

---

#### 3.4 OpenSSL Version Check
**File:** `backend/scanner/prober.py`  
**Change Type:** Enhancement  
**Effort:** 2 hours

**Required:**
```python
def _validate_openssl():
    """Check OpenSSL version at startup."""
    try:
        output = subprocess.check_output(["openssl", "version"], text=True)
        version = output.split()[1]
        major, minor = map(int, version.split(".")[:2])
        if (major, minor) < (1, 1):
            raise RuntimeError(f"OpenSSL {version} too old; require 1.1.1+")
        logger.info(f"OpenSSL version: {version} ✓")
    except Exception as e:
        logger.error(f"OpenSSL validation failed: {e}")
        raise
```

---

#### 3.5 OCSP Stapling Detection
**File:** `backend/scanner/prober.py`  
**Change Type:** Enhancement  
**Effort:** 3 hours

**Add to ProbeProfile:**
```python
class ProbeProfile(BaseModel):
    # ... existing fields ...
    ocsp_stapling_enabled: bool = False
    ocsp_response: str | None = None  # Base64-encoded
```

---

#### 3.6 Session Resumption Analysis
**File:** `backend/scanner/prober.py`  
**Change Type:** Enhancement  
**Effort:** 4 hours

**Add to ProbeProfile:**
```python
class ProbeProfile(BaseModel):
    # ... existing fields ...
    session_id: str | None = None
    ticket_resumes: bool = False
    session_cache_supported: bool = False
```

---

#### 3.7 API Rate Limiting
**File:** `backend/app.py`  
**Change Type:** Enhancement  
**Effort:** 4 hours

**Required:**
- [ ] Implement per-user rate limiting
- [ ] Configure limits via environment
- [ ] Return 429 on limit exceeded
- [ ] Add rate limit headers to responses

---

#### 3.8 Comprehensive Testing Suite
**File:** `tests/` (expand)  
**Change Type:** Test Coverage  
**Effort:** 20-25 hours

**Required:**
- [ ] Unit tests for each module (50+ tests)
- [ ] Integration tests for API endpoints (30+ tests)
- [ ] Database persistence tests (10+ tests)
- [ ] Regression detection tests (15+ tests)
- [ ] Attestation verification tests (10+ tests)
- [ ] End-to-end pipeline tests (5+ tests)
- [ ] Performance/load tests (5+ tests)

---

### TIER 4: LOW PRIORITY (Polish & Optimization)

#### 4.1 Fuzzy Tier Assignment
**File:** `backend/scanner/labeler.py`  
**Change Type:** Enhancement  
**Effort:** 3-4 hours

**Allow:**
- Multi-tier labels for assets with mixed statuses
- Weighted tier calculation

---

#### 4.2 Score Audit Trail
**File:** `backend/pipeline.py` + `database.py`  
**Change Type:** New Feature  
**Effort:** 4 hours

**Track:**
- Initial Q-Score
- Policy adjustments
- Agility adjustments
- Final score

---

#### 4.3 CBOM Diffing Endpoint
**File:** `backend/scanner/cbom_generator.py`  
**Change Type:** New Feature  
**Effort:** 4 hours

**Add:** `/api/cbom/diff?cbom_a={id}&cbom_b={id}` endpoint

---

#### 4.4 Parameterized Demo Data
**File:** `backend/demo_data.py`  
**Change Type:** Enhancement  
**Effort:** 5 hours

**Allow:**
- Different demo scenarios (banking, healthcare, e-commerce)
- Parametric asset generation
- Time-decay simulation

---

#### 4.5 Custom Cipher Suite Selection
**File:** `backend/scanner/prober.py`  
**Change Type:** Enhancement  
**Effort:** 4 hours

**Allow:** Custom cipher suite ordering in probes

---

#### 4.6 Policy-as-Code for CI/CD Gate
**File:** Backend  
**Change Type:** New Feature  
**Effort:** 5 hours

**Add:** Custom policies for CI gate (not just HIGH risk)

---

#### 4.7 Dashboard Theme Customization
**File:** `frontend/css/styles.css` + `frontend/js/app.js`  
**Change Type:** Enhancement  
**Effort:** 3 hours

**Add:** Light/dark theme toggle

---

#### 4.8 Kubernetes Deployment Manifests
**File:** New `k8s/` directory  
**Change Type:** DevOps  
**Effort:** 6 hours

**Create:**
- Deployment.yaml
- Service.yaml
- ConfigMap.yaml
- StatefulSet for SQLite backup
- NetworkPolicy.yaml

---

#### 4.9 Helm Chart
**File:** New `helm/` directory  
**Change Type:** DevOps  
**Effort:** 8 hours

**Create:**
- Helm chart for production deployment
- Values.yaml with all configurations
- Templates for all resources

---

## TESTING & QA CHECKLIST

### Unit Testing
- [ ] Classifier: All 5 statuses + boundary conditions
- [ ] Labeler: All 3 tiers + edge cases
- [ ] Regression detector: All 3 regression types
- [ ] Attestor: Sign/verify cycles
- [ ] CBOM generator: Schema validation
- [ ] Agility assessor: All 5 indicators
- [ ] Notifier: All alert types and webhook formats

### Integration Testing
- [ ] End-to-end pipeline: demo mode
- [ ] End-to-end pipeline: live mode (small asset set)
- [ ] Database: scan persistence and retrieval
- [ ] API: all 45+ endpoints
- [ ] Auth: token validation, rate limiting
- [ ] Webhook: Slack and Teams integration

### Regression Testing
- [ ] Classification consistency across runs
- [ ] Score stability (same asset, different dates)
- [ ] Demo data always produces same results

### Performance Testing
- [ ] Single probe latency < 10 seconds
- [ ] Batch scan (20 assets) < 30 seconds
- [ ] CBOM generation < 200ms
- [ ] Dashboard render < 1 second
- [ ] Database query performance on 10k+ records

### Security Testing
- [ ] Auth token validation
- [ ] CORS headers correct
- [ ] No credential leaks in logs
- [ ] Ed25519 signature verification
- [ ] OpenSSL subprocess is safe (no injection)

### Documentation Testing
- [ ] API endpoints match code
- [ ] Error codes documented
- [ ] Example requests/responses provided
- [ ] Deployment instructions accurate

### User Acceptance Testing
- [ ] Demo scan works end-to-end
- [ ] Live scan with real domain
- [ ] CBOM export parseable
- [ ] Label verification endpoint works
- [ ] Attestation signature verifiable

---

## DEPLOYMENT READINESS

### Pre-Deployment Checklist

- [ ] All critical issues resolved (Section 2)
- [ ] Test coverage > 80%
- [ ] Performance benchmarks passed
- [ ] Security audit completed
- [ ] Documentation complete and accurate
- [ ] API endpoints frozen (no breaking changes)
- [ ] Database schema stable
- [ ] OpenSSL version validated
- [ ] Environment variables documented
- [ ] Deployment manifests (Docker, K8s, Helm) ready

### Production Deployment Steps

1. **Infrastructure**
   - [ ] Database (SQLite) on persistent volume
   - [ ] Railway/Cloud Run with auto-scaling
   - [ ] Vercel frontend with CDN
   - [ ] SSL/TLS certificates (Let's Encrypt)

2. **Configuration**
   - [ ] Set FRONTEND_URLS (CORS origins)
   - [ ] Set SUPABASE_* environment variables
   - [ ] Configure QARMOR_LIVE_SCAN_LIMIT
   - [ ] Set Slack/Teams webhook URLs
   - [ ] Enable request logging

3. **Validation**
   - [ ] Health check endpoint responds
   - [ ] Demo scan completes
   - [ ] Attestation signature verifiable
   - [ ] Database initialized
   - [ ] Frontend accessible and renders

4. **Monitoring**
   - [ ] Error rate tracking
   - [ ] Request latency monitoring
   - [ ] Database query performance
   - [ ] Webhook delivery status

---

## SUMMARY OF MODIFICATIONS

| Category | Count | Priority | Effort (hrs) |
|----------|-------|----------|------------|
| Critical Issues | 10 | P1 | 25-30 |
| Feature Completeness | 21 | P2-P3 | 70-80 |
| Testing & QA | 7 | P1 | 30 |
| Documentation | 5 | P2-P3 | 15 |
| Deployment & DevOps | 3 | P2 | 20 |
| **TOTAL** | **46** | — | **160-175** |

---

## NEXT STEPS

1. **Immediate (Week 1):** Critical Issues #1-8 (Database, Auth, Error Handling, Webhooks, CBOM validation)
2. **Short-term (Week 2-3):** Tier 2 Features (Agility validation, Regression enhancement, Dashboard progress)
3. **Medium-term (Week 4):** Tier 3 Features (Labels, Config, History)
4. **Long-term (Week 5+):** Tier 4 Features (Polish, DevOps manifests)

---

**Document Status:** DRAFT — Ready for Review  
**Last Updated:** April 2, 2026  
**Next Review:** April 9, 2026

