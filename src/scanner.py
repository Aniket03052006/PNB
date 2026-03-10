"""
Q-ARMOR Phase 1 — Scanner Orchestrator.

Coordinates the prober and certificate parser, drives concurrent scans
using ``concurrent.futures.ThreadPoolExecutor``, and assembles the final
``ScanReport``.

Concurrency model
-----------------
Each target is scanned inside its own thread so that slow / unreachable
hosts do not block the rest of the batch.  The thread pool size defaults
to ``min(32, len(targets) + 4)`` — generous enough for typical runs but
bounded to avoid socket exhaustion.
"""

from __future__ import annotations

import logging
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from typing import List, Optional

from src.cert_parser import parse_certificate
from src.models import ScanReport, ScanResult
from src.prober import probe_target

logger = logging.getLogger("qarmor.scanner")


# ---------------------------------------------------------------------------
# Single-target scan  (runs inside a worker thread)
# ---------------------------------------------------------------------------

def _scan_single(target: str, port: int) -> ScanResult:
    """Scan a single *target:port* and return a ``ScanResult``.

    All exceptions are caught and stored in the result's ``error_message``
    field so the caller never sees an unhandled crash.
    """
    result = ScanResult(
        target=target,
        port=port,
        scan_timestamp=datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
    )

    t0 = time.monotonic()

    try:
        # ---- Step 1: TLS handshake & raw extraction ----------------------
        conn_state, cert_der = probe_target(target, port)
        result.connection = conn_state

        # ---- Step 2: Certificate parsing (if we got DER bytes) -----------
        if cert_der:
            try:
                cert_meta = parse_certificate(cert_der)
                result.certificate = cert_meta
            except ValueError as exc:
                logger.warning("Certificate parse error for %s:%d — %s",
                               target, port, exc)
                # Connection data is still valid; cert just could not parse
        else:
            logger.info("No certificate returned by %s:%d", target, port)

        result.status = "success"

    except ConnectionError as exc:
        result.status = "error"
        result.error_message = str(exc)
        logger.warning("Connection failed → %s:%d — %s", target, port, exc)

    except Exception as exc:  # noqa: BLE001  — intentional broad catch
        result.status = "error"
        result.error_message = f"Unexpected error: {exc}"
        logger.exception("Unexpected failure scanning %s:%d", target, port)

    result.scan_duration_ms = int((time.monotonic() - t0) * 1000)
    return result


# ---------------------------------------------------------------------------
# Batch scan  (public API)
# ---------------------------------------------------------------------------

def run_scan(
    targets: List[str],
    port: int = 443,
    max_workers: Optional[int] = None,
) -> ScanReport:
    """Scan a list of targets concurrently and return a complete report.

    Parameters
    ----------
    targets : list[str]
        Hostnames or IP addresses.
    port : int
        Destination port (default 443).
    max_workers : int | None
        Thread-pool size.  ``None`` → ``min(32, len(targets) + 4)``.

    Returns
    -------
    ScanReport
        Fully populated report ready for JSON serialisation.
    """
    if max_workers is None:
        max_workers = min(32, len(targets) + 4)

    report = ScanReport(
        scan_started=datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        total_targets=len(targets),
    )

    results: list[ScanResult] = []

    logger.info(
        "Starting scan of %d target(s) on port %d  [workers=%d]",
        len(targets), port, max_workers,
    )

    with ThreadPoolExecutor(max_workers=max_workers) as pool:
        future_map = {
            pool.submit(_scan_single, t.strip(), port): t.strip()
            for t in targets if t.strip()
        }

        for future in as_completed(future_map):
            hostname = future_map[future]
            try:
                scan_result = future.result()
                results.append(scan_result)
                status_icon = "✓" if scan_result.status == "success" else "✗"
                logger.info(
                    "  %s  %s:%d  [%dms]",
                    status_icon, hostname, port, scan_result.scan_duration_ms,
                )
            except Exception as exc:  # noqa: BLE001
                # Should never happen (_scan_single handles its own errors)
                err_result = ScanResult(
                    target=hostname,
                    port=port,
                    status="error",
                    error_message=f"Worker exception: {exc}",
                    scan_timestamp=datetime.now(timezone.utc).strftime(
                        "%Y-%m-%dT%H:%M:%SZ"
                    ),
                )
                results.append(err_result)
                logger.error("Worker crashed for %s — %s", hostname, exc)

    # ---- Populate summary stats ------------------------------------------
    report.results = sorted(results, key=lambda r: r.target)
    report.successful = sum(1 for r in results if r.status == "success")
    report.failed = sum(1 for r in results if r.status == "error")
    report.scan_finished = datetime.now(timezone.utc).strftime(
        "%Y-%m-%dT%H:%M:%SZ"
    )

    logger.info(
        "Scan complete — %d succeeded, %d failed out of %d targets.",
        report.successful, report.failed, report.total_targets,
    )

    return report
