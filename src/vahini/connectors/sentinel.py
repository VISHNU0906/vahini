"""Microsoft Defender XDR / Sentinel alerts (Graph security API ``alert`` v2) to Vahini alerts.

Pull with ``GET https://graph.microsoft.com/v1.0/security/alerts_v2`` or receive
through a Logic App / Event Hub. Entities arrive in ``evidence[]`` typed by
``@odata.type``.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any

from .common import category_from_text, clean, severity, tactic


def _ts(raw: str | None) -> float:
    if not raw:
        return 0.0
    try:
        return datetime.fromisoformat(raw.replace("Z", "+00:00")).timestamp()
    except ValueError:
        return 0.0


def _evidence(alert: dict[str, Any], kind: str) -> list[dict[str, Any]]:
    return [e for e in alert.get("evidence", []) if e.get("@odata.type", "").endswith(kind)]


def from_graph_alert(alert: dict[str, Any]) -> dict[str, Any]:
    ips = _evidence(alert, "ipEvidence")
    users = _evidence(alert, "userEvidence")
    devices = _evidence(alert, "deviceEvidence")
    procs = _evidence(alert, "processEvidence")
    mails = _evidence(alert, "analyzedMessageEvidence")
    title = alert.get("title", "")
    return clean({
        "id": alert.get("id"),
        "ts": _ts(alert.get("createdDateTime")),
        "source": "defender",
        "rule_id": alert.get("detectorId"),
        "category": category_from_text(title, alert.get("category")),
        "severity": severity(alert.get("severity")),
        "tactic": tactic(alert.get("category")),
        "host": devices[0].get("deviceDnsName", "").split(".")[0] if devices else None,
        "src_ip": ips[0].get("ipAddress") if ips else None,
        "user": (users[0].get("userAccount") or {}).get("accountName") if users else None,
        "description": title,
        "message": alert.get("description"),
        "command_line": procs[0].get("processCommandLine") if procs else None,
        "email_subject": mails[0].get("subject") if mails else None,
    })
