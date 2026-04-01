"""Supabase-backed per-user scan history storage."""

from __future__ import annotations

import json
import logging
import os
from contextlib import contextmanager
from datetime import date, datetime
from typing import Any

from dotenv import load_dotenv

logger = logging.getLogger("qarmor.scan_history")

load_dotenv()

SUPABASE_DB_URL = os.environ.get("SUPABASE_DB_URL", "").strip()

_SCHEMA = """
CREATE TABLE IF NOT EXISTS scans (
    id BIGSERIAL PRIMARY KEY,
    user_id TEXT NOT NULL,
    overall_score INTEGER NOT NULL DEFAULT 0,
    mode TEXT NOT NULL DEFAULT 'live',
    domain TEXT NOT NULL DEFAULT '',
    total_assets INTEGER NOT NULL DEFAULT 0,
    summary JSONB NOT NULL DEFAULT '{}'::jsonb,
    details JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_scans_user_created_at
    ON scans(user_id, created_at DESC);

CREATE TABLE IF NOT EXISTS asset_scores (
    id BIGSERIAL PRIMARY KEY,
    scan_id BIGINT NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    asset TEXT NOT NULL,
    score INTEGER NOT NULL DEFAULT 0,
    status TEXT NOT NULL DEFAULT 'UNKNOWN',
    metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_asset_scores_scan_id
    ON asset_scores(scan_id);

CREATE INDEX IF NOT EXISTS idx_asset_scores_asset
    ON asset_scores(asset);
"""

_schema_ready = False

_MIGRATIONS = (
    "ALTER TABLE scans ADD COLUMN IF NOT EXISTS mode TEXT NOT NULL DEFAULT 'live';",
    "ALTER TABLE scans ADD COLUMN IF NOT EXISTS domain TEXT NOT NULL DEFAULT '';",
    "ALTER TABLE scans ADD COLUMN IF NOT EXISTS total_assets INTEGER NOT NULL DEFAULT 0;",
    "ALTER TABLE scans ADD COLUMN IF NOT EXISTS summary JSONB NOT NULL DEFAULT '{}'::jsonb;",
    "ALTER TABLE scans ADD COLUMN IF NOT EXISTS details JSONB NOT NULL DEFAULT '{}'::jsonb;",
    "ALTER TABLE asset_scores ADD COLUMN IF NOT EXISTS created_at TIMESTAMPTZ NOT NULL DEFAULT NOW();",
)


def is_configured() -> bool:
    return bool(SUPABASE_DB_URL)


@contextmanager
def _connect():
    if not SUPABASE_DB_URL:
        raise RuntimeError("SUPABASE_DB_URL is not configured")

    try:
        import psycopg2
    except ImportError as exc:
        raise RuntimeError("psycopg2 is required for scan history") from exc

    conn = psycopg2.connect(SUPABASE_DB_URL, connect_timeout=10)
    conn.autocommit = True
    try:
        yield conn
    finally:
        conn.close()


def ensure_schema() -> bool:
    global _schema_ready
    if _schema_ready or not is_configured():
        return is_configured()

    try:
        with _connect() as conn:
            with conn.cursor() as cur:
                cur.execute(_SCHEMA)
                for statement in _MIGRATIONS:
                    cur.execute(statement)
        _schema_ready = True
        return True
    except Exception as exc:
        logger.exception("Failed to ensure scan history schema: %s", exc)
        return False


def _result_score(result: dict[str, Any]) -> int:
    q_score = result.get("q_score")
    if isinstance(q_score, dict):
        q_total = q_score.get("total", 0)
    else:
        q_total = q_score or 0
    raw = (
        result.get("score")
        or result.get("worst_case_score")
        or result.get("worst_score")
        or result.get("typical_score")
        or q_total
        or 0
    )
    try:
        return int(float(raw))
    except (TypeError, ValueError):
        return 0


def _result_status(result: dict[str, Any]) -> str:
    q_score = result.get("q_score")
    q_status = q_score.get("status") if isinstance(q_score, dict) else None
    return str(
        result.get("status")
        or result.get("pqc_status")
        or q_status
        or "UNKNOWN"
    )


def _result_asset(result: dict[str, Any]) -> str:
    if result.get("asset"):
        asset = result["asset"]
        if isinstance(asset, dict):
            return str(asset.get("hostname") or asset.get("ip") or asset.get("name") or "")
        return str(asset)
    return str(
        result.get("hostname")
        or result.get("ip")
        or result.get("name")
        or ""
    )


def _normalize_results(results: list[dict[str, Any]] | None) -> list[dict[str, Any]]:
    normalized: list[dict[str, Any]] = []
    for result in results or []:
        if not isinstance(result, dict):
            continue
        normalized.append({
            "asset": _result_asset(result),
            "score": _result_score(result),
            "status": _result_status(result),
            "metadata": result,
        })
    return normalized


def _build_summary(results: list[dict[str, Any]], overall_score: int) -> dict[str, Any]:
    counts = {
        "fully_quantum_safe": 0,
        "pqc_transition": 0,
        "quantum_vulnerable": 0,
        "critically_vulnerable": 0,
        "unknown": 0,
    }

    for result in results:
        status = str(result.get("status") or "").upper()
        if status == "FULLY_QUANTUM_SAFE":
            counts["fully_quantum_safe"] += 1
        elif status == "PQC_TRANSITION":
            counts["pqc_transition"] += 1
        elif status == "QUANTUM_VULNERABLE":
            counts["quantum_vulnerable"] += 1
        elif status == "CRITICALLY_VULNERABLE":
            counts["critically_vulnerable"] += 1
        else:
            counts["unknown"] += 1

    return {
        **counts,
        "average_q_score": overall_score,
    }


def create_scan(
    user_id: str,
    overall_score: int,
    *,
    mode: str = "live",
    domain: str = "",
    total_assets: int = 0,
    summary: dict[str, Any] | None = None,
    details: dict[str, Any] | None = None,
) -> str | None:
    if not ensure_schema():
        return None

    try:
        with _connect() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    insert into scans (user_id, overall_score, mode, domain, total_assets, summary, details)
                    values (%s, %s, %s, %s, %s, %s::jsonb, %s::jsonb)
                    returning id;
                    """,
                    (
                        user_id,
                        overall_score,
                        mode,
                        domain,
                        total_assets,
                        json.dumps(summary or {}),
                        json.dumps(details or {}),
                    ),
                )
                row = cur.fetchone()
                return str(row[0]) if row else None
    except Exception as exc:
        logger.exception("Failed to create scan history row: %s", exc)
        return None


def insert_asset_scores(scan_id: str, results: list[dict[str, Any]]) -> None:
    if not ensure_schema():
        return

    normalized = _normalize_results(results)
    if not normalized:
        return

    try:
        with _connect() as conn:
            with conn.cursor() as cur:
                for result in normalized:
                    cur.execute(
                        """
                        insert into asset_scores (scan_id, asset, score, status, metadata)
                        values (%s, %s, %s, %s, %s::jsonb);
                        """,
                        (
                            scan_id,
                            result["asset"],
                            result["score"],
                            result["status"],
                            json.dumps(result["metadata"]),
                        ),
                    )
    except Exception as exc:
        logger.exception("Failed to insert asset score history: %s", exc)


def save_scan_history(
    *,
    user_id: str,
    results: list[dict[str, Any]] | None,
    mode: str = "live",
    domain: str = "",
    details: dict[str, Any] | None = None,
) -> str | None:
    normalized = _normalize_results(results)
    if not normalized:
        return None

    overall_score = int(round(sum(item["score"] for item in normalized) / len(normalized)))
    summary = _build_summary(normalized, overall_score)
    scan_id = create_scan(
        user_id,
        overall_score,
        mode=mode,
        domain=domain,
        total_assets=len(normalized),
        summary=summary,
        details=details,
    )
    if scan_id is not None:
        insert_asset_scores(scan_id, results or [])
    return scan_id


def _jsonable_value(value: Any) -> Any:
    if isinstance(value, (datetime, date)):
        return value.isoformat()
    return value


def _jsonable_record(columns: list[str], row: Any) -> dict[str, Any]:
    return {
        column: _jsonable_value(value)
        for column, value in zip(columns, row, strict=False)
    }


def list_scans(user_id: str, limit: int = 20) -> list[dict[str, Any]]:
    if not ensure_schema():
        return []

    try:
        with _connect() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    select
                        id,
                        created_at as scan_date,
                        mode,
                        domain,
                        total_assets,
                        overall_score as avg_score,
                        details,
                        coalesce((summary->>'fully_quantum_safe')::int, 0) as fully_safe,
                        coalesce((summary->>'pqc_transition')::int, 0) as pqc_trans,
                        coalesce((summary->>'quantum_vulnerable')::int, 0) as q_vuln,
                        coalesce((summary->>'critically_vulnerable')::int, 0) as crit_vuln,
                        coalesce((summary->>'unknown')::int, 0) as unknown
                    from scans
                    where user_id = %s
                    order by created_at desc
                    limit %s
                    """,
                    (user_id, limit),
                )
                columns = [desc[0] for desc in cur.description]
                return [_jsonable_record(columns, row) for row in cur.fetchall()]
    except Exception as exc:
        logger.exception("Failed to list scan history: %s", exc)
        return []


def load_scan(user_id: str, scan_id: str) -> dict[str, Any] | None:
    if not ensure_schema():
        return None

    try:
        with _connect() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    select
                        id,
                        user_id,
                        created_at as scan_date,
                        mode,
                        domain,
                        total_assets,
                        overall_score as avg_score,
                        summary,
                        details
                    from scans
                    where user_id = %s and id = %s
                    limit 1
                    """,
                    (user_id, scan_id),
                )
                row = cur.fetchone()
                if not row:
                    return None
                columns = [desc[0] for desc in cur.description]
                payload = _jsonable_record(columns, row)

                cur.execute(
                    """
                    select metadata
                    from asset_scores
                    where scan_id = %s
                    order by id asc
                    """,
                    (scan_id,),
                )
                assets = [item[0] for item in cur.fetchall()]
                payload["results_json"] = json.dumps(assets)
                summary = payload.get("summary") or {}
                if isinstance(summary, str):
                    try:
                        summary = json.loads(summary)
                    except json.JSONDecodeError:
                        summary = {}
                payload["fully_safe"] = int(summary.get("fully_quantum_safe", 0) or 0)
                payload["pqc_trans"] = int(summary.get("pqc_transition", 0) or 0)
                payload["q_vuln"] = int(summary.get("quantum_vulnerable", 0) or 0)
                payload["crit_vuln"] = int(summary.get("critically_vulnerable", 0) or 0)
                payload["unknown"] = int(summary.get("unknown", 0) or 0)
                return payload
    except Exception as exc:
        logger.exception("Failed to load scan history row: %s", exc)
        return None


def load_latest_scan(user_id: str) -> dict[str, Any] | None:
    scans = list_scans(user_id, limit=1)
    if not scans:
        return None
    latest_id = scans[0].get("id")
    if latest_id is None:
        return None
    return load_scan(user_id, str(latest_id))


def get_asset_history(user_id: str, asset: str, limit: int = 10) -> list[dict[str, Any]]:
    if not ensure_schema():
        return []

    try:
        with _connect() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    select
                        a.id,
                        a.scan_id,
                        a.asset,
                        a.score,
                        a.status,
                        a.metadata,
                        a.created_at,
                        s.created_at as scan_date,
                        s.mode
                    from asset_scores a
                    join scans s on s.id = a.scan_id
                    where s.user_id = %s and a.asset = %s
                    order by a.id desc
                    limit %s
                    """,
                    (user_id, asset, limit),
                )
                columns = [desc[0] for desc in cur.description]
                return [_jsonable_record(columns, row) for row in cur.fetchall()]
    except Exception as exc:
        logger.exception("Failed to load asset history: %s", exc)
        return []


def get_assets(scan_id: str) -> dict[str, dict[str, Any]]:
    if not ensure_schema():
        return {}

    try:
        with _connect() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    select asset, score, status, metadata
                    from asset_scores
                    where scan_id = %s
                    """,
                    (scan_id,),
                )
                rows = cur.fetchall()
                return {
                    str(row[0]): {
                        "score": int(row[1] or 0),
                        "status": str(row[2] or "UNKNOWN"),
                        "metadata": row[3] or {},
                    }
                    for row in rows
                }
    except Exception as exc:
        logger.exception("Failed to fetch scan assets: %s", exc)
        return {}


def compare_scans(user_id: str, scan_a_id: str, scan_b_id: str) -> dict[str, Any]:
    scan_a = load_scan(user_id, scan_a_id)
    scan_b = load_scan(user_id, scan_b_id)
    if not scan_a or not scan_b:
        return {"error": "One or both scans not found"}

    assets_a = get_assets(scan_a_id)
    assets_b = get_assets(scan_b_id)

    results: dict[str, Any] = {
        "scan_a": {
            "id": scan_a.get("id"),
            "date": scan_a.get("scan_date"),
            "mode": scan_a.get("mode"),
            "domain": scan_a.get("domain"),
            "total": scan_a.get("total_assets", 0),
            "avg": scan_a.get("avg_score", 0),
            "fully_safe": scan_a.get("fully_safe", 0),
            "pqc_trans": scan_a.get("pqc_trans", 0),
            "q_vuln": scan_a.get("q_vuln", 0),
            "crit_vuln": scan_a.get("crit_vuln", 0),
        },
        "scan_b": {
            "id": scan_b.get("id"),
            "date": scan_b.get("scan_date"),
            "mode": scan_b.get("mode"),
            "domain": scan_b.get("domain"),
            "total": scan_b.get("total_assets", 0),
            "avg": scan_b.get("avg_score", 0),
            "fully_safe": scan_b.get("fully_safe", 0),
            "pqc_trans": scan_b.get("pqc_trans", 0),
            "q_vuln": scan_b.get("q_vuln", 0),
            "crit_vuln": scan_b.get("crit_vuln", 0),
        },
        "delta": {
            "total_assets": int(scan_b.get("total_assets", 0) or 0) - int(scan_a.get("total_assets", 0) or 0),
            "avg_score": round(float(scan_b.get("avg_score", 0) or 0) - float(scan_a.get("avg_score", 0) or 0), 1),
            "fully_safe": int(scan_b.get("fully_safe", 0) or 0) - int(scan_a.get("fully_safe", 0) or 0),
            "pqc_trans": int(scan_b.get("pqc_trans", 0) or 0) - int(scan_a.get("pqc_trans", 0) or 0),
            "q_vuln": int(scan_b.get("q_vuln", 0) or 0) - int(scan_a.get("q_vuln", 0) or 0),
            "crit_vuln": int(scan_b.get("crit_vuln", 0) or 0) - int(scan_a.get("crit_vuln", 0) or 0),
        },
        "new_assets": [],
        "removed_assets": [],
        "changed_assets": [],
        "regressions": [],
    }

    for asset in sorted(set(assets_b) - set(assets_a)):
        results["new_assets"].append({
            "asset": asset,
            "score": assets_b[asset]["score"],
            "status": assets_b[asset]["status"],
            "metadata": assets_b[asset]["metadata"],
        })

    for asset in sorted(set(assets_a) - set(assets_b)):
        results["removed_assets"].append({
            "asset": asset,
            "score": assets_a[asset]["score"],
            "status": assets_a[asset]["status"],
            "metadata": assets_a[asset]["metadata"],
        })

    for asset in sorted(set(assets_a) & set(assets_b)):
        old_score = int(assets_a[asset]["score"] or 0)
        new_score = int(assets_b[asset]["score"] or 0)
        if old_score == new_score and assets_a[asset]["status"] == assets_b[asset]["status"]:
            continue

        old_metadata = assets_a[asset].get("metadata") or {}
        new_metadata = assets_b[asset].get("metadata") or {}
        reason = None
        old_tls = old_metadata.get("tls_version") or ((old_metadata.get("fingerprint") or {}).get("tls") or {}).get("version")
        new_tls = new_metadata.get("tls_version") or ((new_metadata.get("fingerprint") or {}).get("tls") or {}).get("version")
        if old_tls and new_tls and old_tls != new_tls:
            reason = f"TLS changed from {old_tls} to {new_tls}"

        change = {
            "asset": asset,
            "old": old_score,
            "new": new_score,
            "delta": new_score - old_score,
            "old_status": assets_a[asset]["status"],
            "new_status": assets_b[asset]["status"],
            "reason": reason,
            "old_metadata": old_metadata,
            "new_metadata": new_metadata,
        }
        results["changed_assets"].append(change)

        if change["delta"] <= -5:
            results["regressions"].append({
                "asset": asset,
                "old": old_score,
                "new": new_score,
                "delta": change["delta"],
                "reason": reason,
            })

    return results


def delete_scan(user_id: str, scan_id: str) -> bool:
    if not ensure_schema():
        return False

    try:
        with _connect() as conn:
            with conn.cursor() as cur:
                cur.execute("delete from scans where user_id = %s and id = %s", (user_id, scan_id))
                return cur.rowcount > 0
    except Exception as exc:
        logger.exception("Failed to delete scan: %s", exc)
        return False
