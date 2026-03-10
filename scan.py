#!/usr/bin/env python3
"""
Q-ARMOR ACDI Scanner — Phase 1 CLI Entry Point.

Usage
-----
  # Scan a single target (default port 443)
  python scan.py --target example.com

  # Scan on a custom port
  python scan.py --target 192.168.1.10 --port 8443

  # Scan a list of targets from a file
  python scan.py --list targets.txt --port 443

  # Increase concurrency for large lists
  python scan.py --list targets.txt --workers 16

  # Save output to a file
  python scan.py --target example.com --output report.json

  # Verbose logging
  python scan.py --target example.com -v
"""

from __future__ import annotations

import argparse
import json
import logging
import sys
from pathlib import Path

from src.scanner import run_scan


# ---------------------------------------------------------------------------
# Logging configuration
# ---------------------------------------------------------------------------

def _configure_logging(verbose: bool = False) -> None:
    level = logging.DEBUG if verbose else logging.INFO
    fmt = "%(asctime)s  %(levelname)-8s  %(message)s"
    datefmt = "%H:%M:%S"

    handler = logging.StreamHandler(sys.stderr)
    handler.setFormatter(logging.Formatter(fmt, datefmt=datefmt))

    root = logging.getLogger("qarmor")
    root.setLevel(level)
    root.addHandler(handler)


# ---------------------------------------------------------------------------
# CLI argument parser
# ---------------------------------------------------------------------------

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="scan",
        description=(
            "Q-ARMOR ACDI Scanner — Phase 1: Core Discovery & Protocol Analysis.\n"
            "Probes public-facing TLS endpoints, extracts negotiated cipher suites,\n"
            "and parses X.509 certificates for PQC-readiness evaluation."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            "  python scan.py --target google.com\n"
            "  python scan.py --target 8.8.8.8 --port 443\n"
            "  python scan.py --list targets.txt --workers 8\n"
            "  python scan.py --target pnbindia.in --output pnb_report.json\n"
        ),
    )

    # Target specification (mutually exclusive)
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument(
        "--target", "-t",
        type=str,
        help="Single target hostname or IP address.",
    )
    group.add_argument(
        "--list", "-l",
        type=str,
        dest="target_list",
        help="Path to a text file with one target per line.",
    )

    # Connection options
    parser.add_argument(
        "--port", "-p",
        type=int,
        default=443,
        help="Destination port (default: 443).",
    )
    parser.add_argument(
        "--workers", "-w",
        type=int,
        default=None,
        help="Thread-pool size for concurrent scanning (default: auto).",
    )

    # Output options
    parser.add_argument(
        "--output", "-o",
        type=str,
        default=None,
        help="Write JSON report to this file instead of stdout.",
    )
    parser.add_argument(
        "--verbose", "-v",
        action="store_true",
        help="Enable verbose / debug logging to stderr.",
    )

    return parser


# ---------------------------------------------------------------------------
# Target loading helpers
# ---------------------------------------------------------------------------

def _load_targets_from_file(filepath: str) -> list[str]:
    """Read targets from a text file (one host per line, # comments ok)."""
    path = Path(filepath)
    if not path.is_file():
        print(f"[ERROR] Target list file not found: {filepath}", file=sys.stderr)
        sys.exit(1)

    targets: list[str] = []
    for line in path.read_text().splitlines():
        stripped = line.strip()
        if stripped and not stripped.startswith("#"):
            # Support "host:port" notation — strip port if present
            # (the --port flag is the canonical port source)
            host = stripped.split(":")[0].strip()
            if host:
                targets.append(host)

    if not targets:
        print(f"[ERROR] No valid targets found in {filepath}", file=sys.stderr)
        sys.exit(1)

    return targets


# ---------------------------------------------------------------------------
# Banner
# ---------------------------------------------------------------------------

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
║   Phase 1: Core Discovery & Protocol Analysis                        ║
║                                                                      ║
╚══════════════════════════════════════════════════════════════════════╝
"""


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> None:
    parser = build_parser()
    args = parser.parse_args()

    _configure_logging(args.verbose)
    logger = logging.getLogger("qarmor.cli")

    print(BANNER, file=sys.stderr)

    # ---- Resolve target list ---------------------------------------------
    if args.target:
        targets = [args.target.strip()]
    else:
        targets = _load_targets_from_file(args.target_list)

    port: int = args.port
    logger.info("Targets: %d  |  Port: %d", len(targets), port)

    # ---- Run the scan ----------------------------------------------------
    report = run_scan(targets, port=port, max_workers=args.workers)

    # ---- Output -----------------------------------------------------------
    json_output = report.to_json(indent=2)

    if args.output:
        out_path = Path(args.output)
        out_path.write_text(json_output, encoding="utf-8")
        logger.info("Report written to %s", out_path.resolve())
        print(f"\n[+] Report saved → {out_path.resolve()}", file=sys.stderr)
    else:
        print(json_output)

    # ---- Exit summary ----------------------------------------------------
    print(
        f"\n[+] Scan complete — {report.successful} succeeded, "
        f"{report.failed} failed out of {report.total_targets} targets.",
        file=sys.stderr,
    )

    # Exit with non-zero if every single target failed
    if report.successful == 0 and report.failed > 0:
        sys.exit(1)


if __name__ == "__main__":
    main()
