#!/usr/bin/env python3
"""
Q-ARMOR ACDI Scanner — Unified CLI Entry Point.

Usage
-----
  # Scan a single target (default port 443)
  python scan.py --target example.com

  # Scan on a custom port
  python scan.py --target 192.168.1.10 --port 8443

  # Scan a list of targets from a file
  python scan.py --list targets.txt

  # Output as CBOM JSON
  python scan.py --target example.com --format cbom

  # Output as machine-readable JSON
  python scan.py --target example.com --format json

  # Save output to a file
  python scan.py --target example.com --output report.json

  # Discover subdomains for a domain and scan all
  python scan.py --target example.com --discover

  # Verbose logging
  python scan.py --target example.com -v
"""

from __future__ import annotations

import argparse
import asyncio
import json
import logging
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

from backend.models import (
    DiscoveredAsset, ScanResult, ScanSummary, PQCStatus, CryptoFingerprint,
)
from backend.scanner.prober import probe_tls
from backend.scanner.classifier import classify
from backend.scanner.cbom_generator import generate_cbom, generate_simple_report
from backend.scanner.label_issuer import issue_label
from backend.scanner.assessment import analyze_endpoint, analyze_batch
from backend.scanner.remediation import generate_remediation, generate_batch_remediation

logger = logging.getLogger("qarmor.cli")


# ── Logging ──────────────────────────────────────────────────────────────────

def _configure_logging(verbose: bool = False) -> None:
    level = logging.DEBUG if verbose else logging.INFO
    fmt = "%(asctime)s  %(levelname)-8s  %(message)s"
    handler = logging.StreamHandler(sys.stderr)
    handler.setFormatter(logging.Formatter(fmt, datefmt="%H:%M:%S"))
    root = logging.getLogger("qarmor")
    root.setLevel(level)
    root.addHandler(handler)


# ── CLI Parser ───────────────────────────────────────────────────────────────

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="scan",
        description=(
            "Q-ARMOR ACDI Scanner — Core Discovery & Protocol Analysis.\n"
            "Probes TLS endpoints, extracts negotiated cryptographic parameters,\n"
            "and classifies PQC readiness with a Q-Score (0–100)."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            "  python scan.py --target google.com\n"
            "  python scan.py --target 8.8.8.8 --port 443\n"
            "  python scan.py --list targets.txt\n"
            "  python scan.py --target example.com --format cbom --output cbom.json\n"
            "  python scan.py --target example.com --discover\n"
        ),
    )

    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--target", "-t", type=str, help="Single target hostname or IP.")
    group.add_argument("--list", "-l", type=str, dest="target_list",
                        help="File with one target per line.")

    parser.add_argument("--port", "-p", type=int, default=443, help="Port (default 443).")
    parser.add_argument("--format", "-f", choices=["table", "json", "cbom", "assess"],
                        default="table", help="Output format (default: table). 'assess' shows Phase 2 PQC assessment.")
    parser.add_argument("--assess", "-a", action="store_true",
                        help="Run Phase 2 PQC assessment after scan (always-on with --format assess).")
    parser.add_argument("--output", "-o", type=str, default=None, help="Output file path.")
    parser.add_argument("--discover", "-d", action="store_true",
                        help="Discover subdomains via DNS + CT logs before scanning.")
    parser.add_argument("--verbose", "-v", action="store_true", help="Verbose logging.")
    return parser


# ── Helpers ──────────────────────────────────────────────────────────────────

def _load_targets(filepath: str) -> list[str]:
    path = Path(filepath)
    if not path.is_file():
        print(f"[ERROR] File not found: {filepath}", file=sys.stderr)
        sys.exit(1)
    targets = [
        line.strip().split(":")[0].strip()
        for line in path.read_text().splitlines()
        if line.strip() and not line.strip().startswith("#")
    ]
    if not targets:
        print(f"[ERROR] No valid targets in {filepath}", file=sys.stderr)
        sys.exit(1)
    return targets


STATUS_COLORS = {
    "FULLY_QUANTUM_SAFE":    "\033[92m",
    "PQC_TRANSITION":        "\033[96m",
    "QUANTUM_VULNERABLE":    "\033[93m",
    "CRITICALLY_VULNERABLE": "\033[91m",
    "UNKNOWN":               "\033[90m",
}
RESET = "\033[0m"
BOLD = "\033[1m"


def _color(text: str, status: str) -> str:
    return f"{STATUS_COLORS.get(status, '')}{text}{RESET}"


def _print_table(results: list[ScanResult]) -> None:
    header = f"{'ASSET':<40} {'TLS':<8} {'KEY EXCHANGE':<20} {'CERT':<12} {'Q-SCORE':>7}  {'STATUS'}"
    print(f"\n{BOLD}{header}{RESET}")
    print("─" * 110)

    for r in sorted(results, key=lambda x: x.q_score.total):
        asset = f"{r.asset.hostname}:{r.asset.port}"
        tls_v = r.fingerprint.tls.version or "—"
        kex = r.fingerprint.tls.key_exchange or "—"
        cert_algo = r.fingerprint.certificate.public_key_type or "—"
        score = r.q_score.total
        status = r.q_score.status.value

        score_str = _color(f"{score:>3}/100", status)
        status_str = _color(status, status)

        print(f"  {asset:<38} {tls_v:<8} {kex:<20} {cert_algo:<12} {score_str}  {status_str}")

    print()


def _print_findings(results: list[ScanResult]) -> None:
    vuln = [r for r in results if r.q_score.status in (
        PQCStatus.CRITICALLY_VULNERABLE, PQCStatus.QUANTUM_VULNERABLE
    )]
    if not vuln:
        return

    print(f"\n{BOLD}─── KEY FINDINGS ───{RESET}")
    for r in vuln[:5]:
        print(f"\n  {BOLD}{r.asset.hostname}:{r.asset.port}{RESET}")
        for f in r.q_score.findings[:3]:
            print(f"    • {f}")
        for rec in r.q_score.recommendations[:2]:
            print(f"    → {_color(rec, r.q_score.status.value)}")


def _print_summary(summary: ScanSummary) -> None:
    print(f"\n{BOLD}─── SCAN SUMMARY ───{RESET}")
    print(f"  Total Assets:          {summary.total_assets}")
    print(f"  Avg Q-Score:           {summary.average_q_score}")
    print(f"  Fully Quantum Safe:    {_color(str(summary.fully_quantum_safe), 'FULLY_QUANTUM_SAFE')}")
    print(f"  PQC Transition:        {_color(str(summary.pqc_transition), 'PQC_TRANSITION')}")
    print(f"  Quantum Vulnerable:    {_color(str(summary.quantum_vulnerable), 'QUANTUM_VULNERABLE')}")
    print(f"  Critically Vulnerable: {_color(str(summary.critically_vulnerable), 'CRITICALLY_VULNERABLE')}")
    if summary.unknown > 0:
        print(f"  Unknown:               {_color(str(summary.unknown), 'UNKNOWN')}")
    print()


RISK_COLORS = {
    "HIGH":   "\033[91m",
    "MEDIUM": "\033[93m",
    "LOW":    "\033[92m",
}


def _print_assessment(summary: ScanSummary) -> None:
    """Print Phase 2 PQC Assessment results to the terminal."""
    batch = analyze_batch(summary)
    rems = generate_batch_remediation(batch)
    agg = batch["aggregate"]

    print(f"\n{BOLD}═══ PHASE 2: PQC VALIDATION & ASSESSMENT ═══{RESET}")
    print()

    # KPI Summary
    print(f"  {BOLD}KPIs:{RESET}")
    print(f"    HNDL-Exposed Endpoints:  {RISK_COLORS['HIGH']}{agg['hndl_vulnerable']}/{agg['total_endpoints']}{RESET} ({agg['hndl_vulnerable_pct']}%)")
    print(f"    TLS Compliant (≥1.3):    {agg['tls_pass']}/{agg['total_endpoints']} ({agg['tls_pass_pct']}%)")
    print(f"    Key Exchange PQC-Safe:   {agg['kex_pqc_safe']}/{agg['total_endpoints']}")
    print(f"    Key Exchange Hybrid:     {agg['kex_hybrid']}/{agg['total_endpoints']}")
    print(f"    Key Exchange Vulnerable: {RISK_COLORS['HIGH']}{agg['kex_vulnerable']}/{agg['total_endpoints']}{RESET}")
    print(f"    Symmetric Compliant:     {agg['sym_pass']}/{agg['total_endpoints']}")
    print()

    # Per-endpoint assessment table
    header = f"{'ENDPOINT':<40} {'TLS':^6} {'KEX':^12} {'CERT':^12} {'SYM':^6} {'RISK':^8} {'HNDL':^6}"
    print(f"  {BOLD}{header}{RESET}")
    print(f"  {'─' * 95}")

    for a in batch["assessments"]:
        ep = f"{a.get('target', '?')}:{a.get('port', 443)}"
        tls_s = a.get('tls_status', '—')
        kex_s = a.get('key_exchange_status', '—')
        cert_s = a.get('certificate_status', '—')
        sym_s = a.get('symmetric_cipher_status', '—')
        risk = a.get('overall_quantum_risk', '—')
        hndl = "⚠ YES" if a.get('hndl_vulnerable') else "✓ No"

        # Color code
        tls_c = f"\033[92m{tls_s}\033[0m" if tls_s == "PASS" else f"\033[91m{tls_s}\033[0m"
        kex_c = (f"\033[92m{kex_s}\033[0m" if kex_s == "PQC_SAFE"
                 else f"\033[96m{kex_s}\033[0m" if kex_s == "HYBRID"
                 else f"\033[91m{kex_s}\033[0m")
        cert_c = (f"\033[92m{cert_s}\033[0m" if cert_s == "PQC_SAFE"
                  else f"\033[96m{cert_s}\033[0m" if cert_s == "HYBRID"
                  else f"\033[91m{cert_s}\033[0m")
        sym_c = f"\033[92m{sym_s}\033[0m" if sym_s == "PASS" else f"\033[91m{sym_s}\033[0m"
        risk_c = f"{RISK_COLORS.get(risk, '')}{risk}\033[0m"
        hndl_c = f"\033[91m{hndl}\033[0m" if "YES" in hndl else f"\033[92m{hndl}\033[0m"

        print(f"  {ep:<38} {tls_c:^17} {kex_c:^23} {cert_c:^23} {sym_c:^17} {risk_c:^19} {hndl_c:^17}")

    print()

    # Risk breakdown
    print(f"  {BOLD}Risk Distribution:{RESET}")
    print(f"    \033[91m■\033[0m HIGH:   {agg['risk_high']}  ({agg['risk_high_pct']}%)")
    print(f"    \033[93m■\033[0m MEDIUM: {agg['risk_medium']}")
    print(f"    \033[92m■\033[0m LOW:    {agg['risk_low']}")
    print()

    # Top remediations
    critical = rems.get("critical_actions", [])
    if critical:
        print(f"  {BOLD}🔴 Critical Remediations ({len(critical)}):{RESET}")
        for r in critical[:5]:
            print(f"    • {r['title']}")
            print(f"      {r['description'][:120]}...")
            print()

    return batch, rems


# ── Core Scan ────────────────────────────────────────────────────────────────

async def scan_targets(targets: list[str], port: int) -> ScanSummary:
    results: list[ScanResult] = []

    async def scan_one(host: str) -> ScanResult:
        t0 = time.monotonic()
        try:
            fp = await probe_tls(host, port)
            q = classify(fp)
            duration = int((time.monotonic() - t0) * 1000)
            return ScanResult(
                asset=DiscoveredAsset(hostname=host, port=port),
                fingerprint=fp,
                q_score=q,
                scan_duration_ms=duration,
            )
        except Exception as exc:
            duration = int((time.monotonic() - t0) * 1000)
            logger.warning("Scan failed for %s:%d — %s", host, port, exc)
            fp = CryptoFingerprint()
            q = classify(fp)  # Will return UNKNOWN
            return ScanResult(
                asset=DiscoveredAsset(hostname=host, port=port),
                fingerprint=fp,
                q_score=q,
                scan_duration_ms=duration,
                error=str(exc),
            )

    tasks = [scan_one(h) for h in targets]
    results = await asyncio.gather(*tasks)

    counts = {s: 0 for s in PQCStatus}
    total_score = 0
    for r in results:
        counts[r.q_score.status] += 1
        total_score += r.q_score.total

    labels = []
    for r in results:
        label = issue_label(r.asset.hostname, r.asset.port, r.q_score)
        if label:
            labels.append(label)

    from backend.demo_data import _build_remediation_roadmap
    return ScanSummary(
        total_assets=len(results),
        fully_quantum_safe=counts[PQCStatus.FULLY_QUANTUM_SAFE],
        pqc_transition=counts[PQCStatus.PQC_TRANSITION],
        quantum_vulnerable=counts[PQCStatus.QUANTUM_VULNERABLE],
        critically_vulnerable=counts[PQCStatus.CRITICALLY_VULNERABLE],
        unknown=counts.get(PQCStatus.UNKNOWN, 0),
        average_q_score=round(total_score / len(results), 1) if results else 0.0,
        results=list(results),
        remediation_roadmap=_build_remediation_roadmap(list(results)),
        labels=labels,
    )


# ── Banner ───────────────────────────────────────────────────────────────────

BANNER = r"""
╔══════════════════════════════════════════════════════════════════════╗
║                                                                      ║
║    ██████   ██████  ██████  ███    ███  ██████  ██████               ║
║   ██    ██  ██   ██ ██   ██ ████  ████ ██    ██ ██   ██              ║
║   ██    ██  ██████  ██████  ██ ████ ██ ██    ██ ██████               ║
║   ██ ▄▄ ██  ██   ██ ██   ██ ██  ██  ██ ██    ██ ██   ██             ║
║    ██████   ██   ██ ██   ██ ██      ██  ██████  ██   ██              ║
║       ▀▀                                                             ║
║   Quantum-Aware Mapping & Observation for Risk Remediation           ║
║   PQC Readiness Scanner — NIST FIPS 203/204/205                      ║
║                                                                      ║
╚══════════════════════════════════════════════════════════════════════╝
"""


# ── Main ─────────────────────────────────────────────────────────────────────

def main() -> None:
    parser = build_parser()
    args = parser.parse_args()
    _configure_logging(args.verbose)

    print(BANNER, file=sys.stderr)

    # Resolve targets
    if args.target:
        targets = [args.target.strip()]
    else:
        targets = _load_targets(args.target_list)

    # Discover subdomains if requested
    if args.discover and len(targets) == 1:
        logger.info("Discovering assets for %s...", targets[0])
        from backend.scanner.discoverer import discover_assets
        assets = asyncio.run(discover_assets(targets[0], include_ct=True, include_port_scan=False))
        targets = list(set(a.hostname for a in assets))
        logger.info("Discovered %d unique hosts", len(targets))

    logger.info("Scanning %d target(s) on port %d...", len(targets), args.port)

    summary = asyncio.run(scan_targets(targets, args.port))

    # Output
    if args.format == "table":
        _print_table(summary.results)
        _print_findings(summary.results)
        _print_summary(summary)
        # Run Phase 2 assessment if --assess flag is set
        if args.assess:
            _print_assessment(summary)
    elif args.format == "assess":
        # Full Phase 2 assessment output
        _print_table(summary.results)
        _print_summary(summary)
        batch_data, rem_data = _print_assessment(summary)
        if args.output:
            full_report = {
                "phase1_summary": {
                    "total_assets": summary.total_assets,
                    "average_q_score": summary.average_q_score,
                    "fully_quantum_safe": summary.fully_quantum_safe,
                    "pqc_transition": summary.pqc_transition,
                    "quantum_vulnerable": summary.quantum_vulnerable,
                    "critically_vulnerable": summary.critically_vulnerable,
                },
                "phase2_assessment": batch_data,
                "phase2_remediation": rem_data,
            }
            output = json.dumps(full_report, indent=2, default=str)
            Path(args.output).write_text(output, encoding="utf-8")
            logger.info("Full Phase 2 assessment saved to %s", args.output)
    elif args.format == "json":
        output = json.dumps(generate_simple_report(summary), indent=2)
        if args.output:
            Path(args.output).write_text(output, encoding="utf-8")
            logger.info("Report saved to %s", args.output)
        else:
            print(output)
    elif args.format == "cbom":
        cbom = generate_cbom(summary)
        output = json.dumps(cbom, indent=2)
        if args.output:
            Path(args.output).write_text(output, encoding="utf-8")
            logger.info("CBOM saved to %s", args.output)
        else:
            print(output)

    # Exit summary
    success = sum(1 for r in summary.results if r.q_score.status != PQCStatus.UNKNOWN)
    failed = sum(1 for r in summary.results if r.q_score.status == PQCStatus.UNKNOWN)
    print(
        f"\n[+] Scan complete — {success} succeeded, {failed} failed "
        f"out of {summary.total_assets} targets.",
        file=sys.stderr,
    )

    if success == 0 and failed > 0:
        sys.exit(1)


if __name__ == "__main__":
    main()
