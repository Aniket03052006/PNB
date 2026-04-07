"""Phase 7 — SQLite Persistence Layer.

Database: ``data/scanner.db``  (created automatically on first import)

Tables
──────
  scans          — one row per scan run (summary + JSON results blob)
  asset_scores   — per-asset tri-mode scores (FK → scans)
  labels         — PQC certification labels with revocation support
  alerts         — security / compliance alerts tied to scans

All public functions use context managers.  Exceptions are caught internally
and logged — callers never see raw sqlite3 errors.
"""

from __future__ import annotations

import json
import logging
import sqlite3
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

logger = logging.getLogger("qarmor.database")

# ── Database location ────────────────────────────────────────────────────────

_DATA_DIR = Path(__file__).resolve().parent.parent.parent / "data"
_DATA_DIR.mkdir(parents=True, exist_ok=True)
DB_PATH = _DATA_DIR / "scanner.db"


# ── Helpers ──────────────────────────────────────────────────────────────────

@contextmanager
def _connect():
    """Yield a SQLite connection with WAL mode and foreign keys enabled."""
    conn = sqlite3.connect(str(DB_PATH), timeout=10)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL;")
    conn.execute("PRAGMA foreign_keys=ON;")
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


# ═══════════════════════════════════════════════════════════════════════════
# Schema
# ═══════════════════════════════════════════════════════════════════════════

_SCHEMA = """
CREATE TABLE IF NOT EXISTS scans (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_date    TEXT    NOT NULL,
    mode         TEXT    NOT NULL DEFAULT 'demo',
    domain       TEXT    NOT NULL DEFAULT '',
    total_assets INTEGER NOT NULL DEFAULT 0,
    avg_score    REAL    NOT NULL DEFAULT 0.0,
    fully_safe   INTEGER NOT NULL DEFAULT 0,
    pqc_trans    INTEGER NOT NULL DEFAULT 0,
    q_vuln       INTEGER NOT NULL DEFAULT 0,
    crit_vuln    INTEGER NOT NULL DEFAULT 0,
    unknown      INTEGER NOT NULL DEFAULT 0,
    results_json TEXT    NOT NULL DEFAULT '[]'
);

CREATE TABLE IF NOT EXISTS asset_scores (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id        INTEGER NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    hostname       TEXT    NOT NULL,
    port           INTEGER NOT NULL DEFAULT 443,
    asset_type     TEXT    NOT NULL DEFAULT 'web',
    best_score     INTEGER NOT NULL DEFAULT 0,
    typical_score  INTEGER NOT NULL DEFAULT 0,
    worst_score    INTEGER NOT NULL DEFAULT 0,
    status         TEXT    NOT NULL DEFAULT 'UNKNOWN',
    summary        TEXT    NOT NULL DEFAULT '',
    action         TEXT    NOT NULL DEFAULT '',
    agility_score  INTEGER NOT NULL DEFAULT 0,
    scored_at      TEXT    NOT NULL
);

CREATE TABLE IF NOT EXISTS labels (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    label_id    TEXT    NOT NULL UNIQUE,
    hostname    TEXT    NOT NULL,
    port        INTEGER NOT NULL DEFAULT 443,
    tier        INTEGER NOT NULL DEFAULT 3,
    label_text  TEXT    NOT NULL DEFAULT '',
    issued_at   TEXT    NOT NULL,
    valid_until TEXT    NOT NULL,
    revoked     INTEGER NOT NULL DEFAULT 0,
    revoked_at  TEXT,
    reason      TEXT    NOT NULL DEFAULT ''
);

CREATE TABLE IF NOT EXISTS alerts (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id    INTEGER REFERENCES scans(id) ON DELETE SET NULL,
    severity   TEXT    NOT NULL DEFAULT 'INFO',
    category   TEXT    NOT NULL DEFAULT '',
    message    TEXT    NOT NULL DEFAULT '',
    hostname   TEXT,
    created_at TEXT    NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_asset_scores_scan   ON asset_scores(scan_id);
CREATE INDEX IF NOT EXISTS idx_asset_scores_host   ON asset_scores(hostname);
CREATE INDEX IF NOT EXISTS idx_labels_hostname      ON labels(hostname);
CREATE INDEX IF NOT EXISTS idx_alerts_scan          ON alerts(scan_id);
CREATE INDEX IF NOT EXISTS idx_alerts_severity      ON alerts(severity);
CREATE INDEX IF NOT EXISTS idx_scans_domain         ON scans(domain);
CREATE INDEX IF NOT EXISTS idx_scans_mode           ON scans(mode);
CREATE INDEX IF NOT EXISTS idx_scans_date           ON scans(scan_date DESC);
"""


def init_db() -> None:
    """Create tables and seed demo data if the scans table is empty."""
    try:
        with _connect() as conn:
            conn.executescript(_SCHEMA)

            row = conn.execute("SELECT COUNT(*) AS cnt FROM scans").fetchone()
            if row["cnt"] == 0:
                _seed_demo_data(conn)
                logger.info("Database initialised with demo seed data at %s", DB_PATH)
            else:
                logger.debug("Database already has %d scans", row["cnt"])
    except Exception as exc:
        logger.exception("init_db failed: %s", exc)


def _seed_demo_data(conn: sqlite3.Connection) -> None:
    """Insert historical scan summaries from demo_data as seed rows."""
    try:
        from backend.demo_data import get_historical_scan_summaries
        summaries = get_historical_scan_summaries()
        for s in summaries:
            conn.execute(
                """INSERT INTO scans
                   (scan_date, mode, domain, total_assets, avg_score,
                    fully_safe, pqc_trans, q_vuln, crit_vuln, unknown, results_json)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    s.scan_date, s.mode, "bank.com", s.total_assets,
                    float(s.quantum_safety_score),
                    s.fully_quantum_safe, s.pqc_transition,
                    s.quantum_vulnerable, s.critically_vulnerable,
                    s.unknown, "[]",
                ),
            )
    except Exception as exc:
        logger.warning("Demo seed failed (non-fatal): %s", exc)


# ═══════════════════════════════════════════════════════════════════════════
# Scan CRUD
# ═══════════════════════════════════════════════════════════════════════════

def save_scan(
    *,
    mode: str = "demo",
    domain: str = "",
    total_assets: int = 0,
    avg_score: float = 0.0,
    fully_safe: int = 0,
    pqc_trans: int = 0,
    q_vuln: int = 0,
    crit_vuln: int = 0,
    unknown: int = 0,
    results_json: str = "[]",
    classified_assets: list[dict] | None = None,
) -> int | None:
    """Insert a scan row + optional asset_scores.  Returns scan id."""
    try:
        with _connect() as conn:
            cur = conn.execute(
                """INSERT INTO scans
                   (scan_date, mode, domain, total_assets, avg_score,
                    fully_safe, pqc_trans, q_vuln, crit_vuln, unknown, results_json)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    _now_iso(), mode, domain, total_assets, avg_score,
                    fully_safe, pqc_trans, q_vuln, crit_vuln, unknown,
                    results_json,
                ),
            )
            scan_id = cur.lastrowid

            if classified_assets:
                for ca in classified_assets:
                    conn.execute(
                        """INSERT INTO asset_scores
                           (scan_id, hostname, port, asset_type,
                            best_score, typical_score, worst_score,
                            status, summary, action, agility_score, scored_at)
                           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                        (
                            scan_id,
                            ca.get("hostname", ""),
                            ca.get("port", 443),
                            ca.get("asset_type", "web"),
                            ca.get("best_case_score", 0),
                            ca.get("typical_score", 0),
                            ca.get("worst_case_score", 0),
                            ca.get("status", "UNKNOWN"),
                            ca.get("summary", ""),
                            ca.get("recommended_action", ""),
                            ca.get("agility_score", 0),
                            _now_iso(),
                        ),
                    )

            return scan_id
    except Exception as exc:
        logger.exception("save_scan failed: %s", exc)
        return None


def load_scan(scan_id: int) -> dict | None:
    """Load a single scan by ID."""
    try:
        with _connect() as conn:
            row = conn.execute("SELECT * FROM scans WHERE id=?", (scan_id,)).fetchone()
            if not row:
                return None
            return dict(row)
    except Exception as exc:
        logger.exception("load_scan failed: %s", exc)
        return None


def load_latest_scan() -> dict | None:
    """Load the most recent scan."""
    try:
        with _connect() as conn:
            row = conn.execute(
                "SELECT * FROM scans ORDER BY id DESC LIMIT 1"
            ).fetchone()
            return dict(row) if row else None
    except Exception as exc:
        logger.exception("load_latest_scan failed: %s", exc)
        return None


def load_previous_scan() -> dict | None:
    """Load the second-most-recent scan (for comparison)."""
    try:
        with _connect() as conn:
            row = conn.execute(
                "SELECT * FROM scans ORDER BY id DESC LIMIT 1 OFFSET 1"
            ).fetchone()
            return dict(row) if row else None
    except Exception as exc:
        logger.exception("load_previous_scan failed: %s", exc)
        return None


def list_scans(limit: int = 0) -> list[dict]:
    """List recent scans (newest first). limit=0 means unlimited."""
    try:
        with _connect() as conn:
            query = (
                "SELECT id, scan_date, mode, domain, total_assets, avg_score, "
                "fully_safe, pqc_trans, q_vuln, crit_vuln, unknown "
                "FROM scans ORDER BY id DESC"
            )
            if limit > 0:
                query += " LIMIT ?"
                rows = conn.execute(query, (limit,)).fetchall()
            else:
                rows = conn.execute(query).fetchall()
            return [dict(r) for r in rows]
    except Exception as exc:
        logger.exception("list_scans failed: %s", exc)
        return []


def get_asset_history(hostname: str, limit: int = 10) -> list[dict]:
    """Return score history for a single hostname across scans."""
    try:
        with _connect() as conn:
            rows = conn.execute(
                """SELECT a.*, s.scan_date, s.mode
                   FROM asset_scores a
                   JOIN scans s ON s.id = a.scan_id
                   WHERE a.hostname = ?
                   ORDER BY a.scan_id DESC
                   LIMIT ?""",
                (hostname, limit),
            ).fetchall()
            return [dict(r) for r in rows]
    except Exception as exc:
        logger.exception("get_asset_history failed: %s", exc)
        return []


# ═══════════════════════════════════════════════════════════════════════════
# Label CRUD
# ═══════════════════════════════════════════════════════════════════════════

def save_label(
    *,
    label_id: str,
    hostname: str,
    port: int = 443,
    tier: int = 3,
    label_text: str = "",
    issued_at: str = "",
    valid_until: str = "",
    reason: str = "",
) -> bool:
    """Upsert a PQC label."""
    try:
        with _connect() as conn:
            conn.execute(
                """INSERT INTO labels
                   (label_id, hostname, port, tier, label_text,
                    issued_at, valid_until, reason)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                   ON CONFLICT(label_id) DO UPDATE SET
                       tier=excluded.tier,
                       label_text=excluded.label_text,
                       valid_until=excluded.valid_until,
                       reason=excluded.reason""",
                (label_id, hostname, port, tier, label_text,
                 issued_at or _now_iso(), valid_until, reason),
            )
            return True
    except Exception as exc:
        logger.exception("save_label failed: %s", exc)
        return False


def revoke_label(label_id: str) -> bool:
    """Revoke a label by ID."""
    try:
        with _connect() as conn:
            conn.execute(
                "UPDATE labels SET revoked=1, revoked_at=? WHERE label_id=?",
                (_now_iso(), label_id),
            )
            return True
    except Exception as exc:
        logger.exception("revoke_label failed: %s", exc)
        return False


def verify_label(label_id: str) -> dict | None:
    """Return label details for verification (None if not found)."""
    try:
        with _connect() as conn:
            row = conn.execute(
                "SELECT * FROM labels WHERE label_id=?", (label_id,)
            ).fetchone()
            return dict(row) if row else None
    except Exception as exc:
        logger.exception("verify_label failed: %s", exc)
        return None


def list_labels(include_revoked: bool = False) -> list[dict]:
    """List all active labels (optionally include revoked)."""
    try:
        with _connect() as conn:
            q = "SELECT * FROM labels"
            if not include_revoked:
                q += " WHERE revoked=0"
            q += " ORDER BY issued_at DESC"
            rows = conn.execute(q).fetchall()
            return [dict(r) for r in rows]
    except Exception as exc:
        logger.exception("list_labels failed: %s", exc)
        return []


# ═══════════════════════════════════════════════════════════════════════════
# Alert CRUD
# ═══════════════════════════════════════════════════════════════════════════

def save_alert(
    *,
    scan_id: int | None = None,
    severity: str = "INFO",
    category: str = "",
    message: str = "",
    hostname: str | None = None,
) -> bool:
    """Insert an alert row."""
    try:
        with _connect() as conn:
            conn.execute(
                """INSERT INTO alerts
                   (scan_id, severity, category, message, hostname, created_at)
                   VALUES (?, ?, ?, ?, ?, ?)""",
                (scan_id, severity, category, message, hostname, _now_iso()),
            )
            return True
    except Exception as exc:
        logger.exception("save_alert failed: %s", exc)
        return False


def get_alerts(
    scan_id: int | None = None,
    severity: str | None = None,
    limit: int = 50,
) -> list[dict]:
    """Retrieve alerts with optional filters."""
    try:
        with _connect() as conn:
            q = "SELECT * FROM alerts WHERE 1=1"
            params: list[Any] = []
            if scan_id is not None:
                q += " AND scan_id=?"
                params.append(scan_id)
            if severity:
                q += " AND severity=?"
                params.append(severity)
            q += " ORDER BY id DESC LIMIT ?"
            params.append(limit)
            rows = conn.execute(q, params).fetchall()
            return [dict(r) for r in rows]
    except Exception as exc:
        logger.exception("get_alerts failed: %s", exc)
        return []


# ═══════════════════════════════════════════════════════════════════════════
# Scan Comparison
# ═══════════════════════════════════════════════════════════════════════════

def compare_scans(scan_id_a: int, scan_id_b: int) -> dict:
    """Compare two scans and return a delta summary.

    Returns dict with keys: scan_a, scan_b, delta, new_assets, removed_assets, changed_assets.
    """
    try:
        a = load_scan(scan_id_a)
        b = load_scan(scan_id_b)
        if not a or not b:
            return {"error": "One or both scans not found"}

        with _connect() as conn:
            rows_a = conn.execute(
                "SELECT hostname, port, best_score, typical_score, worst_score, status "
                "FROM asset_scores WHERE scan_id=?", (scan_id_a,)
            ).fetchall()
            rows_b = conn.execute(
                "SELECT hostname, port, best_score, typical_score, worst_score, status "
                "FROM asset_scores WHERE scan_id=?", (scan_id_b,)
            ).fetchall()

        hosts_a = {f"{r['hostname']}:{r['port']}": dict(r) for r in rows_a}
        hosts_b = {f"{r['hostname']}:{r['port']}": dict(r) for r in rows_b}

        new_assets = sorted(set(hosts_b.keys()) - set(hosts_a.keys()))
        removed_assets = sorted(set(hosts_a.keys()) - set(hosts_b.keys()))

        changed = []
        for key in sorted(set(hosts_a.keys()) & set(hosts_b.keys())):
            ha, hb = hosts_a[key], hosts_b[key]
            if ha["worst_score"] != hb["worst_score"] or ha["status"] != hb["status"]:
                changed.append({
                    "asset": key,
                    "old_worst": ha["worst_score"],
                    "new_worst": hb["worst_score"],
                    "delta": hb["worst_score"] - ha["worst_score"],
                    "old_status": ha["status"],
                    "new_status": hb["status"],
                })

        return {
            "scan_a": {
                "id": scan_id_a,
                "date": a["scan_date"],
                "total": a["total_assets"],
                "avg": a["avg_score"],
                "fully_safe": a["fully_safe"],
                "crit_vuln": a["crit_vuln"],
            },
            "scan_b": {
                "id": scan_id_b,
                "date": b["scan_date"],
                "total": b["total_assets"],
                "avg": b["avg_score"],
                "fully_safe": b["fully_safe"],
                "crit_vuln": b["crit_vuln"],
            },
            "delta": {
                "total_assets": b["total_assets"] - a["total_assets"],
                "avg_score": round(b["avg_score"] - a["avg_score"], 1),
                "fully_safe": b["fully_safe"] - a["fully_safe"],
                "crit_vuln": b["crit_vuln"] - a["crit_vuln"],
            },
            "new_assets": new_assets,
            "removed_assets": removed_assets,
            "changed_assets": changed,
        }
    except Exception as exc:
        logger.exception("compare_scans failed: %s", exc)
        return {"error": str(exc)}


# ═══════════════════════════════════════════════════════════════════════════
# Auto-init on import
# ═══════════════════════════════════════════════════════════════════════════

init_db()
