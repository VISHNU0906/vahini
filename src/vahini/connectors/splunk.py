"""Splunk Enterprise Security notable events to Vahini alerts.

Send with a webhook alert action or read from the ``notable`` index. ES uses
CIM field names (src, dest, user) and MITRE annotations.
"""

from __future__ import annotations

from typing import Any

from .common import category_from_text, clean, first, get, severity, tactic


def from_notable(event: dict[str, Any]) -> dict[str, Any]:
    result = event.get("result", event)          # webhook payloads wrap fields in "result"
    name = result.get("search_name") or event.get("search_name") or result.get("rule_name", "")
    tac = first(get(result, "annotations.mitre_attack.mitre_tactic") or result.get("mitre_tactic"))
    try:
        ts = float(result.get("_time", 0))
    except (TypeError, ValueError):
        ts = 0.0
    return clean({
        "id": result.get("event_id") or result.get("orig_sid") or event.get("sid"),
        "ts": ts,
        "source": "splunk",
        "rule_id": result.get("rule_id"),
        "category": category_from_text(name, result.get("signature")),
        "severity": severity(result.get("urgency") or result.get("severity") or "medium"),
        "tactic": tactic(tac),
        "host": result.get("dest") or result.get("dest_host"),
        "src_ip": result.get("src") or result.get("src_ip"),
        "user": result.get("user") or result.get("src_user"),
        "description": name,
        "message": result.get("_raw"),
        "command_line": result.get("process"),
        "user_agent": result.get("http_user_agent"),
    })
