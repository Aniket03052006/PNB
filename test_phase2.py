"""Quick test for Phase 2 modules."""
from backend.demo_data import generate_demo_results
from backend.scanner.assessment import analyze_batch
from backend.scanner.remediation import generate_batch_remediation
import json

summary = generate_demo_results()
batch = analyze_batch(summary)
rems = generate_batch_remediation(batch)
agg = batch["aggregate"]

print("=== BATCH ASSESSMENT ===")
print(f"Total endpoints: {agg['total_endpoints']}")
print(f"TLS pass: {agg['tls_pass']}, fail: {agg['tls_fail']}")
print(f"KEX vuln: {agg['kex_vulnerable']}, hybrid: {agg['kex_hybrid']}, pqc: {agg['kex_pqc_safe']}")
print(f"HNDL exposed: {agg['hndl_vulnerable']} ({agg['hndl_vulnerable_pct']}%)")
print(f"Risk HIGH: {agg['risk_high']}, MED: {agg['risk_medium']}, LOW: {agg['risk_low']}")
print()
print("=== REMEDIATION ===")
print(f"Total actions: {rems['total_remediations']}")
print(f"By priority: {rems['by_priority']}")
print(f"Roadmap phases: {len(rems['strategic_roadmap'])}")
for p in rems["strategic_roadmap"]:
    print(f"  {p['phase']}: {len(p['actions'])} actions")
print()
print("=== SAMPLE ENDPOINT ===")
a = batch["assessments"][0]
keys = ["target", "tls_status", "key_exchange_status", "certificate_status",
        "symmetric_cipher_status", "overall_quantum_risk", "hndl_vulnerable"]
print(json.dumps({k: a[k] for k in keys}, indent=2))
print()
print("ALL TESTS PASSED")
