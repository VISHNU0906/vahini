"""Elastic Security (ECS) detection alerts to Vahini alerts.

Works with alerts read from ``.alerts-security.alerts-*`` or sent by an Elastic
webhook connector. Fields may arrive nested or as flat dotted ECS keys.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any

from .common import category_from_text, clean, first, get, severity, tactic


def _ts(raw: Any) -> float:
    if not raw:
        return 0.0
    try:
        return datetime.fromisoformat(str(raw).replace("Z", "+00:00")).timestamp()
    except ValueError:
        return 0.0


def from_elastic(doc: dict[str, Any]) -> dict[str, Any]:
    rule = get(doc, "kibana.alert.rule.name") or get(doc, "signal.rule.name") or ""
    threat = first(get(doc, "kibana.alert.rule.threat") or get(doc, "threat") or [])
    tac = (threat or {}).get("tactic", {}).get("name") if isinstance(threat, dict) else None
    return clean({
        "id": get(doc, "kibana.alert.uuid") or get(doc, "_id"),
        "ts": _ts(get(doc, "@timestamp")),
        "source": "elastic",
        "rule_id": get(doc, "kibana.alert.rule.rule_id"),
        "category": category_from_text(rule, get(doc, "event.category") and str(get(doc, "event.category"))),
        "severity": severity(get(doc, "kibana.alert.severity") or get(doc, "kibana.alert.risk_score", 50), 100),
        "tactic": tactic(tac),
        "host": get(doc, "host.name"),
        "src_ip": get(doc, "source.ip"),
        "dst_ip": get(doc, "destination.ip"),
        "user": get(doc, "user.name"),
        "description": rule,
        "message": get(doc, "message"),
        "command_line": get(doc, "process.command_line"),
        "user_agent": get(doc, "user_agent.original"),
    })
