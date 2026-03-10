"""Unit tests for Q-ARMOR PQC Classifier."""

import pytest
from backend.models import CryptoFingerprint, TLSInfo, CertificateInfo, PQCStatus
from backend.scanner.classifier import classify


def make_fingerprint(
    tls_version="TLSv1.3",
    cipher_bits=256,
    kex="ECDHE",
    auth="RSA",
    sig_algo="sha256WithRSAEncryption",
    pk_type="RSA",
    pk_bits=2048,
    pqc_kex=False,
    pqc_sig=False,
    hybrid=False,
):
    """Helper to build a CryptoFingerprint for testing."""
    return CryptoFingerprint(
        tls=TLSInfo(
            version=tls_version,
            cipher_suite=f"TLS_{kex}_{auth}_WITH_AES_{cipher_bits}_GCM_SHA384",
            cipher_bits=cipher_bits,
            cipher_algorithm="AES",
            key_exchange=kex,
            authentication=auth,
            supports_tls_1_3="1.3" in tls_version,
            supports_tls_1_2="1.2" in tls_version or "1.3" in tls_version,
        ),
        certificate=CertificateInfo(
            signature_algorithm=sig_algo,
            public_key_type=pk_type,
            public_key_bits=pk_bits,
        ),
        has_pqc_kex=pqc_kex,
        has_pqc_signature=pqc_sig,
        has_hybrid_mode=hybrid,
        has_forward_secrecy=kex in ("ECDHE", "DHE"),
    )


class TestQScoreClassifier:
    """Tests for the PQC risk classification engine."""

    def test_fully_quantum_safe(self):
        """ML-KEM + ML-DSA on TLS 1.3 should score >= 90."""
        fp = make_fingerprint(
            tls_version="TLSv1.3", kex="ML-KEM-768", auth="ML-DSA-65",
            sig_algo="ML-DSA-65", pk_type="ML-DSA", pk_bits=2048,
            pqc_kex=True, pqc_sig=True,
        )
        q = classify(fp)
        assert q.total >= 90
        assert q.status == PQCStatus.FULLY_QUANTUM_SAFE

    def test_pqc_transition_hybrid(self):
        """Hybrid X25519+ML-KEM with classical cert should be PQC_TRANSITION."""
        fp = make_fingerprint(
            tls_version="TLSv1.3", kex="X25519MLKEM768", auth="ECDSA",
            sig_algo="sha256WithRSAEncryption", pk_type="EC", pk_bits=256,
            pqc_kex=True, pqc_sig=False, hybrid=True,
        )
        q = classify(fp)
        assert 70 <= q.total < 90
        assert q.status == PQCStatus.PQC_TRANSITION

    def test_quantum_vulnerable_tls13_ecdhe(self):
        """TLS 1.3 with ECDHE (no PQC) should be QUANTUM_VULNERABLE."""
        fp = make_fingerprint(
            tls_version="TLSv1.3", kex="ECDHE", auth="RSA",
            sig_algo="sha256WithRSAEncryption", pk_type="RSA", pk_bits=2048,
        )
        q = classify(fp)
        assert 40 <= q.total < 90
        assert q.status == PQCStatus.QUANTUM_VULNERABLE

    def test_quantum_vulnerable_tls12(self):
        """TLS 1.2 with ECDHE should be QUANTUM_VULNERABLE."""
        fp = make_fingerprint(
            tls_version="TLSv1.2", kex="ECDHE", auth="RSA",
        )
        q = classify(fp)
        assert q.status == PQCStatus.QUANTUM_VULNERABLE

    def test_critically_vulnerable_tls10(self):
        """TLS 1.0 with RSA should be CRITICALLY_VULNERABLE."""
        fp = make_fingerprint(
            tls_version="TLSv1.0", kex="RSA", auth="RSA",
            cipher_bits=128, sig_algo="sha1WithRSAEncryption",
            pk_type="RSA", pk_bits=1024,
        )
        q = classify(fp)
        assert q.status == PQCStatus.CRITICALLY_VULNERABLE
        assert q.total < 40

    def test_critically_vulnerable_tls11(self):
        """TLS 1.1 is always CRITICALLY_VULNERABLE regardless of cipher."""
        fp = make_fingerprint(
            tls_version="TLSv1.1", kex="RSA", auth="RSA",
            cipher_bits=256,
        )
        q = classify(fp)
        assert q.status == PQCStatus.CRITICALLY_VULNERABLE

    def test_score_components_add_up(self):
        """Total score should equal sum of components."""
        fp = make_fingerprint()
        q = classify(fp)
        expected = (
            q.tls_version_score + q.key_exchange_score +
            q.certificate_score + q.cipher_strength_score
        )
        assert q.total == expected

    def test_weak_cipher_generates_finding(self):
        """Cipher bits < 128 should generate a finding."""
        fp = make_fingerprint(cipher_bits=112)
        q = classify(fp)
        assert any("Weak cipher" in f or "112" in f for f in q.findings)

    def test_rsa_kex_generates_shor_finding(self):
        """RSA key exchange should warn about Shor's algorithm."""
        fp = make_fingerprint(kex="RSA")
        q = classify(fp)
        assert any("Shor" in f for f in q.findings)

    def test_expired_cert_generates_critical_finding(self):
        """Expired certificate should generate a CRITICAL finding."""
        fp = make_fingerprint()
        fp.certificate.is_expired = True
        fp.certificate.days_until_expiry = -5
        q = classify(fp)
        assert any("expired" in f.lower() for f in q.findings)

    def test_small_rsa_key_generates_critical_finding(self):
        """RSA key < 2048 bits should generate a CRITICAL finding."""
        fp = make_fingerprint(pk_bits=1024, pk_type="RSA")
        q = classify(fp)
        assert any("1024" in f for f in q.findings)

    def test_recommendations_present(self):
        """Vulnerable assets should always have recommendations."""
        fp = make_fingerprint(
            tls_version="TLSv1.2", kex="RSA", auth="RSA",
            cipher_bits=128, pk_bits=1024, pk_type="RSA",
        )
        q = classify(fp)
        assert len(q.recommendations) > 0


class TestDemoData:
    """Tests for demo data generation."""

    def test_demo_generates_all_statuses(self):
        """Demo data should contain all four PQC status categories."""
        from backend.demo_data import generate_demo_results
        summary = generate_demo_results()
        assert summary.fully_quantum_safe > 0
        assert summary.pqc_transition > 0
        assert summary.quantum_vulnerable > 0
        assert summary.critically_vulnerable > 0

    def test_demo_total_matches(self):
        """Total assets should match sum of status categories."""
        from backend.demo_data import generate_demo_results
        summary = generate_demo_results()
        total = (
            summary.fully_quantum_safe + summary.pqc_transition +
            summary.quantum_vulnerable + summary.critically_vulnerable
        )
        assert summary.total_assets == total

    def test_demo_has_labels(self):
        """Demo data should issue PQC labels for compliant assets."""
        from backend.demo_data import generate_demo_results
        summary = generate_demo_results()
        assert len(summary.labels) > 0

    def test_demo_has_remediation(self):
        """Demo data should include remediation roadmap."""
        from backend.demo_data import generate_demo_results
        summary = generate_demo_results()
        assert len(summary.remediation_roadmap) > 0


class TestCBOMGenerator:
    """Tests for CycloneDX 1.6 CBOM generation."""

    def test_cbom_format(self):
        """CBOM should have correct CycloneDX format fields."""
        from backend.demo_data import generate_demo_results
        from backend.scanner.cbom_generator import generate_cbom
        summary = generate_demo_results()
        cbom = generate_cbom(summary)
        assert cbom["bomFormat"] == "CycloneDX"
        assert cbom["specVersion"] == "1.6"
        assert "components" in cbom
        assert len(cbom["components"]) == summary.total_assets

    def test_cbom_components_have_crypto_properties(self):
        """Each CBOM component should have cryptoProperties."""
        from backend.demo_data import generate_demo_results
        from backend.scanner.cbom_generator import generate_cbom
        summary = generate_demo_results()
        cbom = generate_cbom(summary)
        for comp in cbom["components"]:
            assert "cryptoProperties" in comp
            assert "pqcAssessment" in comp
            assert "qScore" in comp["pqcAssessment"]
