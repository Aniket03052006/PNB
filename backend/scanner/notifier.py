"""Module 11: Webhook Alert Notifier — Slack/Teams Integration.

Sends real-time alerts to Slack and Microsoft Teams webhook URLs when
critical security conditions are detected:

    1. HNDL (Harvest Now, Decrypt Later) vulnerability detected
    2. Cryptographic downgrade — endpoint moved from PQC to classical
    3. HIGH quantum risk endpoints discovered
    4. Non-compliant endpoints exceeding threshold

Supports both Slack Incoming Webhooks and Microsoft Teams (via Adaptive Cards).
"""

from __future__ import annotations

import json
import logging
import os
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

try:
    import requests
except ImportError:
    requests = None  # type: ignore[assignment]

logger = logging.getLogger("qarmor.notifier")


# ── Configuration ────────────────────────────────────────────────────────────

# Webhook URLs from environment variables
SLACK_WEBHOOK_URL = os.environ.get("QARMOR_SLACK_WEBHOOK", "")
TEAMS_WEBHOOK_URL = os.environ.get("QARMOR_TEAMS_WEBHOOK", "")

# Alert thresholds
HNDL_ALERT_THRESHOLD = 1       # Alert if >= N HNDL-vulnerable endpoints
HIGH_RISK_THRESHOLD = 1        # Alert if >= N HIGH-risk endpoints
NON_COMPLIANT_PCT_THRESHOLD = 50  # Alert if > N% endpoints are non-compliant


# ── Alert Types ──────────────────────────────────────────────────────────────

class AlertType:
    HNDL_DETECTED = "HNDL_VULNERABILITY"
    CRYPTO_DOWNGRADE = "CRYPTOGRAPHIC_DOWNGRADE"
    HIGH_RISK = "HIGH_QUANTUM_RISK"
    NON_COMPLIANT = "NON_COMPLIANT_THRESHOLD"
    SCAN_COMPLETE = "SCAN_COMPLETE"


# ── Alert Detection ──────────────────────────────────────────────────────────

def detect_alerts(
    assessment_results: List[Dict[str, Any]],
    labels: Optional[List[Dict[str, Any]]] = None,
    previous_labels: Optional[List[Dict[str, Any]]] = None,
) -> List[Dict[str, Any]]:
    """Analyze assessment results and detect alert-worthy conditions.

    Parameters
    ----------
    assessment_results : list[dict]
        Per-endpoint assessments from ``analyze_batch()["assessments"]``.
    labels : list[dict], optional
        Phase 4 certification labels from ``evaluate_and_label()``.
    previous_labels : list[dict], optional
        Prior scan labels for downgrade detection.

    Returns
    -------
    list[dict]
        List of alert records, each with ``type``, ``severity``, ``message``,
        ``details``, and ``affected_endpoints``.
    """
    alerts: List[Dict[str, Any]] = []
    now = datetime.now(timezone.utc).isoformat()

    # ── HNDL Vulnerability Detection ─────────────────────────────────
    hndl_endpoints = [
        a for a in assessment_results
        if a.get("hndl_vulnerable", False)
    ]
    if len(hndl_endpoints) >= HNDL_ALERT_THRESHOLD:
        targets = [f"{a['target']}:{a.get('port', 443)}" for a in hndl_endpoints]
        alerts.append({
            "id": f"alert-hndl-{len(hndl_endpoints)}",
            "type": AlertType.HNDL_DETECTED,
            "severity": "CRITICAL",
            "title": "HNDL Vulnerability Detected",
            "message": (
                f"{len(hndl_endpoints)} endpoint(s) are vulnerable to "
                f"Harvest Now, Decrypt Later (HNDL) attacks. "
                f"Nation-state adversaries may be intercepting encrypted traffic "
                f"for future quantum decryption."
            ),
            "affected_endpoints": targets,
            "count": len(hndl_endpoints),
            "timestamp": now,
            "action_required": (
                "Immediately enable hybrid PQC key exchange (X25519+ML-KEM-768) "
                "on all affected endpoints."
            ),
        })

    # ── HIGH Quantum Risk Detection ──────────────────────────────────
    high_risk = [
        a for a in assessment_results
        if a.get("overall_quantum_risk") == "HIGH"
    ]
    if len(high_risk) >= HIGH_RISK_THRESHOLD:
        targets = [f"{a['target']}:{a.get('port', 443)}" for a in high_risk]
        alerts.append({
            "id": f"alert-high-{len(high_risk)}",
            "type": AlertType.HIGH_RISK,
            "severity": "HIGH",
            "title": "High Quantum Risk Endpoints",
            "message": (
                f"{len(high_risk)} endpoint(s) have HIGH quantum risk. "
                f"These endpoints use purely classical cryptography that is "
                f"breakable by quantum computers."
            ),
            "affected_endpoints": targets,
            "count": len(high_risk),
            "timestamp": now,
            "action_required": (
                "Upgrade TLS to 1.3 and enable PQC key exchange. "
                "See Q-ARMOR remediation plan for prioritized actions."
            ),
        })

    # ── Cryptographic Downgrade Detection ────────────────────────────
    if labels and previous_labels:
        prev_map = {f"{l['target']}:{l['port']}": l for l in previous_labels}
        downgraded = []
        for label in labels:
            key = f"{label['target']}:{label['port']}"
            prev = prev_map.get(key)
            if prev and label.get("tier", 3) > prev.get("tier", 3):
                downgraded.append({
                    "endpoint": key,
                    "previous_label": prev.get("label", "Unknown"),
                    "current_label": label.get("label", "Unknown"),
                })

        if downgraded:
            alerts.append({
                "id": f"alert-downgrade-{len(downgraded)}",
                "type": AlertType.CRYPTO_DOWNGRADE,
                "severity": "CRITICAL",
                "title": "Cryptographic Downgrade Detected",
                "message": (
                    f"{len(downgraded)} endpoint(s) have downgraded their "
                    f"cryptographic posture since the previous scan."
                ),
                "affected_endpoints": [d["endpoint"] for d in downgraded],
                "details": downgraded,
                "count": len(downgraded),
                "timestamp": now,
                "action_required": (
                    "Investigate configuration changes. Restore PQC-safe configuration."
                ),
            })

    # ── Non-Compliant Threshold ──────────────────────────────────────
    if labels:
        total = len(labels)
        non_compliant = sum(1 for l in labels if l.get("label") == "Non-Compliant")
        if total > 0:
            pct = round(non_compliant / total * 100, 1)
            if pct > NON_COMPLIANT_PCT_THRESHOLD:
                alerts.append({
                    "id": f"alert-noncompliant-{non_compliant}",
                    "type": AlertType.NON_COMPLIANT,
                    "severity": "HIGH",
                    "title": "Non-Compliance Threshold Exceeded",
                    "message": (
                        f"{pct}% of endpoints ({non_compliant}/{total}) are "
                        f"Non-Compliant — exceeds the {NON_COMPLIANT_PCT_THRESHOLD}% threshold."
                    ),
                    "count": non_compliant,
                    "percentage": pct,
                    "threshold": NON_COMPLIANT_PCT_THRESHOLD,
                    "timestamp": now,
                    "action_required": (
                        "Accelerate PQC migration. Prioritize endpoints with HNDL exposure."
                    ),
                })

    return alerts


# ── Slack Notification ───────────────────────────────────────────────────────

def _build_slack_payload(alerts: List[Dict[str, Any]], scan_summary: Optional[Dict] = None) -> Dict:
    """Build a Slack-compatible webhook payload from alerts."""
    blocks: List[Dict] = [
        {
            "type": "header",
            "text": {
                "type": "plain_text",
                "text": f"🛡️ Q-ARMOR Security Alert ({len(alerts)} issue{'s' if len(alerts) != 1 else ''})",
            },
        },
        {
            "type": "section",
            "text": {
                "type": "mrkdwn",
                "text": f"*Scan Time:* {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}",
            },
        },
        {"type": "divider"},
    ]

    severity_emoji = {
        "CRITICAL": "🔴",
        "HIGH": "🟠",
        "MEDIUM": "🟡",
        "LOW": "🟢",
    }

    for alert in alerts:
        emoji = severity_emoji.get(alert.get("severity", "HIGH"), "⚠️")
        endpoints = alert.get("affected_endpoints", [])
        ep_text = ", ".join(endpoints[:5])
        if len(endpoints) > 5:
            ep_text += f" (+{len(endpoints) - 5} more)"

        blocks.append({
            "type": "section",
            "text": {
                "type": "mrkdwn",
                "text": (
                    f"{emoji} *{alert.get('title', 'Alert')}*\n"
                    f"Severity: `{alert.get('severity', 'UNKNOWN')}`\n"
                    f"{alert.get('message', '')}\n"
                    f"*Affected:* {ep_text}\n"
                    f"*Action:* {alert.get('action_required', 'Review scan results')}"
                ),
            },
        })
        blocks.append({"type": "divider"})

    if scan_summary:
        blocks.append({
            "type": "context",
            "elements": [
                {
                    "type": "mrkdwn",
                    "text": (
                        f"📊 Total: {scan_summary.get('total', 0)} endpoints | "
                        f"✅ Safe: {scan_summary.get('safe', 0)} | "
                        f"🔶 PQC Ready: {scan_summary.get('pqc_ready', 0)} | "
                        f"❌ Non-Compliant: {scan_summary.get('non_compliant', 0)}"
                    ),
                }
            ],
        })

    return {"blocks": blocks}


# ── Teams Notification ───────────────────────────────────────────────────────

def _build_teams_payload(alerts: List[Dict[str, Any]], scan_summary: Optional[Dict] = None) -> Dict:
    """Build a Microsoft Teams Adaptive Card payload from alerts."""
    body: List[Dict] = [
        {
            "type": "TextBlock",
            "size": "Large",
            "weight": "Bolder",
            "text": f"🛡️ Q-ARMOR Security Alert ({len(alerts)} issue{'s' if len(alerts) != 1 else ''})",
        },
        {
            "type": "TextBlock",
            "text": f"Scan Time: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}",
            "isSubtle": True,
        },
    ]

    severity_color = {
        "CRITICAL": "attention",
        "HIGH": "warning",
        "MEDIUM": "accent",
        "LOW": "good",
    }

    for alert in alerts:
        endpoints = alert.get("affected_endpoints", [])
        ep_text = ", ".join(endpoints[:5])
        if len(endpoints) > 5:
            ep_text += f" (+{len(endpoints) - 5} more)"

        body.append({
            "type": "Container",
            "style": severity_color.get(alert.get("severity", "HIGH"), "default"),
            "items": [
                {
                    "type": "TextBlock",
                    "weight": "Bolder",
                    "text": f"{alert.get('severity', 'HIGH')}: {alert.get('title', 'Alert')}",
                },
                {
                    "type": "TextBlock",
                    "text": alert.get("message", ""),
                    "wrap": True,
                },
                {
                    "type": "FactSet",
                    "facts": [
                        {"title": "Affected", "value": ep_text},
                        {"title": "Action", "value": alert.get("action_required", "Review scan results")},
                    ],
                },
            ],
        })

    if scan_summary:
        body.append({
            "type": "TextBlock",
            "text": (
                f"📊 Total: {scan_summary.get('total', 0)} | "
                f"✅ Safe: {scan_summary.get('safe', 0)} | "
                f"🔶 PQC Ready: {scan_summary.get('pqc_ready', 0)} | "
                f"❌ Non-Compliant: {scan_summary.get('non_compliant', 0)}"
            ),
            "isSubtle": True,
            "separator": True,
        })

    return {
        "type": "message",
        "attachments": [
            {
                "contentType": "application/vnd.microsoft.card.adaptive",
                "content": {
                    "$schema": "http://adaptivecards.io/schemas/adaptive-card.json",
                    "type": "AdaptiveCard",
                    "version": "1.4",
                    "body": body,
                },
            }
        ],
    }


# ── Public API ───────────────────────────────────────────────────────────────

def send_alerts(
    assessment_results: List[Dict[str, Any]],
    labels: Optional[List[Dict[str, Any]]] = None,
    previous_labels: Optional[List[Dict[str, Any]]] = None,
    slack_webhook: Optional[str] = None,
    teams_webhook: Optional[str] = None,
    scan_summary: Optional[Dict] = None,
) -> Dict[str, Any]:
    """Detect alerts and send notifications to configured webhooks.

    Parameters
    ----------
    assessment_results : list[dict]
        Per-endpoint assessments from ``analyze_batch()``.
    labels : list[dict], optional
        Phase 4 labels from ``evaluate_and_label()``.
    previous_labels : list[dict], optional
        Labels from prior scan for downgrade detection.
    slack_webhook : str, optional
        Slack webhook URL (overrides env var).
    teams_webhook : str, optional
        Teams webhook URL (overrides env var).
    scan_summary : dict, optional
        Summary stats for context in notification.

    Returns
    -------
    dict
        Result with ``alerts_detected``, ``notifications_sent``, ``alerts``, ``errors``.
    """
    alerts = detect_alerts(assessment_results, labels, previous_labels)

    result: Dict[str, Any] = {
        "alerts_detected": len(alerts),
        "alerts": alerts,
        "notifications_sent": [],
        "errors": [],
    }

    if not alerts:
        logger.info("No alerts detected — no notifications to send.")
        return result

    slack_url = slack_webhook or SLACK_WEBHOOK_URL
    teams_url = teams_webhook or TEAMS_WEBHOOK_URL

    if not slack_url and not teams_url:
        logger.info(
            "%d alert(s) detected but no webhook URLs configured. "
            "Set QARMOR_SLACK_WEBHOOK or QARMOR_TEAMS_WEBHOOK environment variables.",
            len(alerts),
        )
        return result

    if requests is None:
        logger.warning(
            "requests library not installed — cannot send webhook notifications. "
            "Install: pip install requests"
        )
        result["errors"].append("requests library not installed")
        return result

    # Send to Slack
    if slack_url:
        try:
            payload = _build_slack_payload(alerts, scan_summary)
            resp = requests.post(
                slack_url,
                json=payload,
                headers={"Content-Type": "application/json"},
                timeout=10,
            )
            if resp.status_code == 200:
                logger.info("Slack notification sent (%d alerts)", len(alerts))
                result["notifications_sent"].append({
                    "channel": "Slack",
                    "status": "sent",
                    "alerts_count": len(alerts),
                })
            else:
                logger.warning("Slack webhook returned %d: %s", resp.status_code, resp.text)
                result["errors"].append(f"Slack: HTTP {resp.status_code}")
        except Exception as exc:
            logger.error("Slack notification failed: %s", exc)
            result["errors"].append(f"Slack: {exc}")

    # Send to Teams
    if teams_url:
        try:
            payload = _build_teams_payload(alerts, scan_summary)
            resp = requests.post(
                teams_url,
                json=payload,
                headers={"Content-Type": "application/json"},
                timeout=10,
            )
            if resp.status_code in (200, 202):
                logger.info("Teams notification sent (%d alerts)", len(alerts))
                result["notifications_sent"].append({
                    "channel": "Teams",
                    "status": "sent",
                    "alerts_count": len(alerts),
                })
            else:
                logger.warning("Teams webhook returned %d: %s", resp.status_code, resp.text)
                result["errors"].append(f"Teams: HTTP {resp.status_code}")
        except Exception as exc:
            logger.error("Teams notification failed: %s", exc)
            result["errors"].append(f"Teams: {exc}")

    return result


def get_alert_summary(alerts: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Return a concise summary of detected alerts."""
    return {
        "total_alerts": len(alerts),
        "critical": sum(1 for a in alerts if a.get("severity") == "CRITICAL"),
        "high": sum(1 for a in alerts if a.get("severity") == "HIGH"),
        "medium": sum(1 for a in alerts if a.get("severity") == "MEDIUM"),
        "types": list(set(a.get("type", "") for a in alerts)),
        "all_endpoints": list(set(
            ep for a in alerts for ep in a.get("affected_endpoints", [])
        )),
    }
