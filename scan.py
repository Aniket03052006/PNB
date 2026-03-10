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

from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.text import Text
from rich import box

from backend.models import (
    DiscoveredAsset, ScanResult, ScanSummary, PQCStatus, CryptoFingerprint,
)
from backend.scanner.prober import probe_tls
from backend.scanner.classifier import classify
from backend.scanner.cbom_generator import generate_cbom, generate_simple_report
from backend.scanner.label_issuer import issue_label
from backend.scanner.assessment import analyze_endpoint, analyze_batch
from backend.scanner.remediation import generate_remediation, generate_batch_remediation
from backend.scanner.labeler import evaluate_and_label, summarize_labels
from backend.scanner.attestor import generate_attestation
from backend.scanner.notifier import detect_alerts, send_alerts

logger = logging.getLogger("qarmor.cli")
console = Console()


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
    parser.add_argument("--attest", action="store_true",
                        help="Generate a signed CDXA attestation document (Phase 5).")
    parser.add_argument("--ci", action="store_true",
                        help="CI/CD mode: exit(1) if any endpoint has HIGH quantum risk (Phase 5).")
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
    "FULLY_QUANTUM_SAFE":    "bold green",
    "PQC_TRANSITION":        "bold cyan",
    "QUANTUM_VULNERABLE":    "bold yellow",
    "CRITICALLY_VULNERABLE": "bold red",
    "UNKNOWN":               "dim",
}

RISK_STYLE = {
    "HIGH":   "bold red",
    "MEDIUM": "bold yellow",
    "LOW":    "bold green",
}

LABEL_STYLE = {
    "Fully Quantum Safe": "bold green",
    "PQC Ready":          "bold cyan",
    "Non-Compliant":      "bold red",
}


def _print_table(results: list[ScanResult]) -> None:
    table = Table(
        title="[bold cyan]Q-ARMOR Scan Results[/bold cyan]",
        box=box.ROUNDED,
        border_style="bright_black",
        header_style="bold white",
        show_lines=False,
        pad_edge=True,
    )
    table.add_column("Asset", style="cyan", min_width=30)
    table.add_column("TLS", justify="center", min_width=8)
    table.add_column("Key Exchange", min_width=18)
    table.add_column("Cert", min_width=10)
    table.add_column("Q-Score", justify="right", min_width=8)
    table.add_column("Status", min_width=22)

    for r in sorted(results, key=lambda x: x.q_score.total):
        asset = f"{r.asset.hostname}:{r.asset.port}"
        tls_v = r.fingerprint.tls.version or "—"
        kex = r.fingerprint.tls.key_exchange or "—"
        cert_algo = r.fingerprint.certificate.public_key_type or "—"
        score = r.q_score.total
        status = r.q_score.status.value
        style = STATUS_COLORS.get(status, "")

        table.add_row(
            asset,
            tls_v,
            kex,
            cert_algo,
            f"[{style}]{score}/100[/{style}]",
            f"[{style}]{status}[/{style}]",
        )

    console.print()
    console.print(table)
    console.print()


def _print_findings(results: list[ScanResult]) -> None:
    vuln = [r for r in results if r.q_score.status in (
        PQCStatus.CRITICALLY_VULNERABLE, PQCStatus.QUANTUM_VULNERABLE
    )]
    if not vuln:
        return

    console.print()
    console.rule("[bold yellow]KEY FINDINGS[/bold yellow]", style="yellow")
    for r in vuln[:5]:
        console.print(f"\n  [bold]{r.asset.hostname}:{r.asset.port}[/bold]")
        for f in r.q_score.findings[:3]:
            console.print(f"    [dim]•[/dim] {f}")
        style = STATUS_COLORS.get(r.q_score.status.value, "")
        for rec in r.q_score.recommendations[:2]:
            console.print(f"    [dim]→[/dim] [{style}]{rec}[/{style}]")


def _print_summary(summary: ScanSummary) -> None:
    console.print()
    console.rule("[bold white]SCAN SUMMARY[/bold white]", style="bright_black")
    console.print(f"  Total Assets:          {summary.total_assets}")
    console.print(f"  Avg Q-Score:           {summary.average_q_score}")
    console.print(f"  Fully Quantum Safe:    [bold green]{summary.fully_quantum_safe}[/bold green]")
    console.print(f"  PQC Transition:        [bold cyan]{summary.pqc_transition}[/bold cyan]")
    console.print(f"  Quantum Vulnerable:    [bold yellow]{summary.quantum_vulnerable}[/bold yellow]")
    console.print(f"  Critically Vulnerable: [bold red]{summary.critically_vulnerable}[/bold red]")
    if summary.unknown > 0:
        console.print(f"  Unknown:               [dim]{summary.unknown}[/dim]")
    console.print()


def _print_assessment(summary: ScanSummary) -> None:
    """Print Phase 2 PQC Assessment + Phase 4 Labels using rich tables."""
    batch = analyze_batch(summary)
    rems = generate_batch_remediation(batch)
    agg = batch["aggregate"]

    # ── Phase 4: Certification Labels ────────────────────────────────
    labels = evaluate_and_label(batch["assessments"])
    label_summary = summarize_labels(labels)
    label_map = {f"{l['target']}:{l['port']}": l for l in labels}

    console.print()
    console.rule("[bold cyan]PHASE 2: PQC VALIDATION & ASSESSMENT[/bold cyan]", style="cyan")
    console.print()

    # KPI Summary
    kpi_table = Table(
        title="[bold]Assessment KPIs[/bold]",
        box=box.SIMPLE_HEAVY,
        border_style="bright_black",
        show_header=False,
        pad_edge=True,
    )
    kpi_table.add_column("Metric", style="white", min_width=26)
    kpi_table.add_column("Value", justify="right", min_width=16)

    kpi_table.add_row("HNDL-Exposed Endpoints", f"[bold red]{agg['hndl_vulnerable']}/{agg['total_endpoints']}[/bold red] ({agg['hndl_vulnerable_pct']}%)")
    kpi_table.add_row("TLS Compliant (≥1.3)", f"{agg['tls_pass']}/{agg['total_endpoints']} ({agg['tls_pass_pct']}%)")
    kpi_table.add_row("Key Exchange PQC-Safe", f"[bold green]{agg['kex_pqc_safe']}/{agg['total_endpoints']}[/bold green]")
    kpi_table.add_row("Key Exchange Hybrid", f"[bold cyan]{agg['kex_hybrid']}/{agg['total_endpoints']}[/bold cyan]")
    kpi_table.add_row("Key Exchange Vulnerable", f"[bold red]{agg['kex_vulnerable']}/{agg['total_endpoints']}[/bold red]")
    kpi_table.add_row("Symmetric Compliant", f"{agg['sym_pass']}/{agg['total_endpoints']}")

    console.print(kpi_table)
    console.print()

    # Per-endpoint assessment table with Label column
    assess_table = Table(
        title="[bold]Per-Endpoint Assessment[/bold]",
        box=box.ROUNDED,
        border_style="bright_black",
        header_style="bold white",
        show_lines=False,
        pad_edge=True,
    )
    assess_table.add_column("Endpoint", style="cyan", min_width=30)
    assess_table.add_column("TLS", justify="center", min_width=6)
    assess_table.add_column("KEX", justify="center", min_width=12)
    assess_table.add_column("CERT", justify="center", min_width=12)
    assess_table.add_column("SYM", justify="center", min_width=6)
    assess_table.add_column("Risk", justify="center", min_width=8)
    assess_table.add_column("HNDL", justify="center", min_width=6)
    assess_table.add_column("Awarded Label", justify="center", min_width=20)

    kex_style_map = {"PQC_SAFE": "bold green", "HYBRID": "bold cyan", "VULNERABLE": "bold red"}
    cert_style_map = {"PQC_SAFE": "bold green", "HYBRID": "bold cyan", "VULNERABLE": "bold red"}

    for a in batch["assessments"]:
        ep = f"{a.get('target', '?')}:{a.get('port', 443)}"
        tls_s = a.get('tls_status', '—')
        kex_s = a.get('key_exchange_status', '—')
        cert_s = a.get('certificate_status', '—')
        sym_s = a.get('symmetric_cipher_status', '—')
        risk = a.get('overall_quantum_risk', '—')
        hndl = a.get('hndl_vulnerable', False)

        # Style cells
        tls_styled = f"[bold green]{tls_s}[/bold green]" if tls_s == "PASS" else f"[bold red]{tls_s}[/bold red]"
        kex_styled = f"[{kex_style_map.get(kex_s, 'bold red')}]{kex_s}[/{kex_style_map.get(kex_s, 'bold red')}]"
        cert_styled = f"[{cert_style_map.get(cert_s, 'bold red')}]{cert_s}[/{cert_style_map.get(cert_s, 'bold red')}]"
        sym_styled = f"[bold green]{sym_s}[/bold green]" if sym_s == "PASS" else f"[bold red]{sym_s}[/bold red]"
        risk_styled = f"[{RISK_STYLE.get(risk, 'bold red')}]{risk}[/{RISK_STYLE.get(risk, 'bold red')}]"
        hndl_styled = "[bold red]⚠ YES[/bold red]" if hndl else "[bold green]✓ No[/bold green]"

        # Label
        label_rec = label_map.get(ep, {})
        label_text = label_rec.get("label", "—")
        label_icon = label_rec.get("tier_icon", "")
        label_style = LABEL_STYLE.get(label_text, "dim")
        label_display = f"[{label_style}]{label_icon} {label_text}[/{label_style}]"

        assess_table.add_row(
            ep, tls_styled, kex_styled, cert_styled,
            sym_styled, risk_styled, hndl_styled, label_display,
        )

    console.print(assess_table)
    console.print()

    # Risk distribution
    console.rule("[bold]Risk Distribution[/bold]", style="bright_black")
    console.print(f"    [bold red]■[/bold red] HIGH:   {agg['risk_high']}  ({agg['risk_high_pct']}%)")
    console.print(f"    [bold yellow]■[/bold yellow] MEDIUM: {agg['risk_medium']}")
    console.print(f"    [bold green]■[/bold green] LOW:    {agg['risk_low']}")
    console.print()

    # Phase 4 Label summary
    console.rule("[bold cyan]PHASE 4: CERTIFICATION LABELS[/bold cyan]", style="cyan")
    console.print(f"    [bold green]✅[/bold green] Fully Quantum Safe:  {label_summary['fully_quantum_safe']}  ({label_summary['fully_quantum_safe_pct']})")
    console.print(f"    [bold cyan]🔶[/bold cyan] PQC Ready:           {label_summary['pqc_ready']}  ({label_summary['pqc_ready_pct']})")
    console.print(f"    [bold red]❌[/bold red] Non-Compliant:       {label_summary['non_compliant']}  ({label_summary['non_compliant_pct']})")
    console.print()

    # Top remediations
    critical = rems.get("critical_actions", [])
    if critical:
        console.rule(f"[bold red]Critical Remediations ({len(critical)})[/bold red]", style="red")
        for r in critical[:5]:
            console.print(f"    [bold]•[/bold] {r['title']}")
            console.print(f"      [dim]{r['description'][:120]}...[/dim]")
            console.print()

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

BANNER = r"""[bold cyan]
╔══════════════════════════════════════════════════════════════════════╗
║                                                                      ║
║    ██████   ██████  ██████  ███    ███  ██████  ██████               ║
║   ██    ██  ██   ██ ██   ██ ████  ████ ██    ██ ██   ██              ║
║   ██    ██  ██████  ██████  ██ ████ ██ ██    ██ ██████               ║
║   ██ ▄▄ ██  ██   ██ ██   ██ ██  ██  ██ ██    ██ ██   ██             ║
║    ██████   ██   ██ ���█   ██ ██      ██  ██████  ██   ██              ║
║       ▀▀                                                             ║
║   Quantum-Aware Mapping & Observation for Risk Remediation           ║
║   PQC Readiness Scanner — NIST FIPS 203/204/205                      ║
║                                                                      ║
╚══════════════════════════════════════════════════════════════════════╝
[/bold cyan]"""


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

    # ── Phase 5: Attestation & Alerts ────────────────────────────────
    if args.attest or args.ci:
        batch = analyze_batch(summary)
        assessments = batch.get("assessments", [])

        # Generate attestation
        if args.attest:
            console.print()
            console.rule("[bold magenta]PHASE 5: COMPLIANCE ATTESTATION[/bold magenta]", style="magenta")
            try:
                attest_output = args.output.replace(".json", "-cdxa.json") if args.output else "attestation-cdxa.json"
                cdxa = generate_attestation(
                    assessment_results=assessments,
                    output_file=attest_output,
                )
                body = cdxa.get("attestation", {})
                comp_summary = body.get("complianceSummary", {})
                overall = comp_summary.get("overallStatus", "UNKNOWN")
                style = "bold green" if overall == "COMPLIANT" else "bold cyan" if overall == "PARTIAL" else "bold red"
                console.print(f"    Attestation Status:  [{style}]{overall}[/{style}]")
                console.print(f"    Compliant:           {comp_summary.get('compliant', 0)} ({comp_summary.get('compliant_pct', '0%')})")
                console.print(f"    Partial:             {comp_summary.get('partial', 0)} ({comp_summary.get('partial_pct', '0%')})")
                console.print(f"    Non-Compliant:       {comp_summary.get('nonCompliant', 0)} ({comp_summary.get('nonCompliant_pct', '0%')})")
                console.print(f"    Serial:              [dim]{body.get('serialNumber', '')}[/dim]")
                console.print(f"    Valid Until:          {body.get('validity', {}).get('notAfter', '')}")
                console.print(f"    Signed:              [bold green]Ed25519[/bold green]")
                console.print(f"    Saved to:            [bold]{attest_output}[/bold]")
                console.print()
            except Exception as exc:
                console.print(f"    [bold red]Attestation failed: {exc}[/bold red]")

        # Detect and display alerts
        labels = evaluate_and_label(assessments) if "assessments" in (batch or {}) else []
        alerts = detect_alerts(assessments, labels)
        if alerts:
            console.print()
            console.rule("[bold red]SECURITY ALERTS[/bold red]", style="red")
            severity_icon = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "🟢"}
            for alert in alerts:
                icon = severity_icon.get(alert.get("severity", "HIGH"), "⚠️")
                console.print(f"    {icon} [{alert.get('severity', 'HIGH')}] {alert.get('title', 'Alert')}")
                console.print(f"       {alert.get('message', '')}")
                eps = alert.get("affected_endpoints", [])
                if eps:
                    console.print(f"       Affected: {', '.join(eps[:5])}")
                console.print()

        # CI/CD build-breaking check
        if args.ci:
            high_risk = [
                a for a in assessments
                if a.get("overall_quantum_risk") == "HIGH"
            ]
            if high_risk:
                console.print()
                console.print(
                    Panel(
                        f"[bold red]CI/CD GATE FAILED[/bold red]\n\n"
                        f"{len(high_risk)} endpoint(s) have HIGH quantum risk.\n"
                        f"Build terminated with exit code 1.",
                        title="[bold red]BUILD BREAKER[/bold red]",
                        border_style="red",
                    )
                )
                sys.exit(1)
            else:
                console.print(
                    Panel(
                        f"[bold green]CI/CD GATE PASSED[/bold green]\n\n"
                        f"All {len(assessments)} endpoint(s) pass quantum risk compliance.",
                        title="[bold green]COMPLIANCE OK[/bold green]",
                        border_style="green",
                    )
                )

    if success == 0 and failed > 0:
        sys.exit(1)


if __name__ == "__main__":
    main()
