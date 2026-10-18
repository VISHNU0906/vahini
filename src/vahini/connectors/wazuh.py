"""Wazuh alerts to Vahini alerts.

Wazuh writes one JSON alert per line to ``/var/ossec/logs/alerts/alerts.json``
and can also push them to a webhook through an integration. Each alert
carries ``rule`` (id, level 0-15, description, groups, mitre), ``agent``,
``data`` (decoder fields such as srcip and srcuser) and ``full_log``.
"""

from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path
from typing import Any, Iterator

# Wazuh rule groups -> Vahini playbook category. First match wins.
GROUP_CATEGORY = [
    ({"authentication_failed", "authentication_failures", "sshd", "win_authentication_failed"}, "auth.bruteforce"),
    ({"authentication_success"}, "auth.bruteforce"),
    ({"malware", "virustotal", "yara", "rootcheck", "sysmon_eid1_detections"}, "endpoint.malware"),
    ({"phishing", "office365", "email"}, "email.phishing"),
    ({"ai_agent", "genai"}, "ai.agent"),
]


def severity(level: int) -> str:
    if level >= 12:
        return "critical"
    if level >= 8:
        return "high"
    if level >= 5:
        return "medium"
    return "low"


def _tactic(rule: dict[str, Any]) -> str | None:
    tactics = (rule.get("mitre") or {}).get("tactic") or []
    return tactics[0].strip().lower().replace(" ", "-") if tactics else None


def _ts(raw: str | None) -> float:
    if not raw:
        return 0.0
    try:
        return datetime.strptime(raw, "%Y-%m-%dT%H:%M:%S.%f%z").timestamp()
    except ValueError:
        return 0.0


def from_wazuh(alert: dict[str, Any]) -> dict[str, Any]:
    rule = alert.get("rule") or {}
    data = alert.get("data") or {}
    groups = set(rule.get("groups") or [])
    category = next((cat for keys, cat in GROUP_CATEGORY if groups & keys), "unknown")
    win = (data.get("win") or {}).get("eventdata") or {}

    out: dict[str, Any] = {
        "id": alert.get("id") or f"wazuh-{rule.get('id', '?')}",
        "ts": _ts(alert.get("timestamp")),
        "source": "wazuh",
        "rule_id": str(rule.get("id", "")),
        "category": category,
        "severity": severity(int(rule.get("level", 0))),
        "tactic": _tactic(rule),
        "host": (alert.get("agent") or {}).get("name"),
        "src_ip": data.get("srcip") or win.get("ipAddress"),
        "user": data.get("srcuser") or data.get("dstuser") or win.get("targetUserName") or win.get("user"),
        "description": rule.get("description", ""),
        "message": alert.get("full_log", ""),
        "command_line": win.get("commandLine"),
        "user_agent": data.get("http_user_agent") or data.get("user_agent"),
    }
    if isinstance(out.get("user"), str) and "\\" in out["user"]:
        out["user"] = out["user"].split("\\")[-1]          # DOMAIN\user -> user, so it correlates
    return {k: v for k, v in out.items() if v not in (None, "")}


def iter_alerts(path: str | Path) -> Iterator[dict[str, Any]]:
    """Read Wazuh's NDJSON alerts file, skipping lines that are not JSON."""
    with open(path, encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            try:
                yield from_wazuh(json.loads(line))
            except json.JSONDecodeError:
                continue
