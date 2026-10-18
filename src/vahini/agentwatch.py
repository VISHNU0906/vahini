"""Runtime detection for the organisation's own AI agents.

Consumes agent traces that follow the OpenTelemetry GenAI semantic
conventions (``gen_ai.*`` span attributes) and raises SOC alerts when a tool
call is steered by content the agent read from an untrusted source rather
than by what the user asked for: the signature of indirect prompt injection.

Each alert lands in the same triage queue as SIEM alerts, so one analyst
console covers both classic infrastructure and AI agents.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from typing import Any, Iterable

from .detect import Scanner

_INDICATORS = re.compile(
    r"(https?://[^\s\"'<>]+"
    r"|[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}"
    r"|\b(?:\d{1,3}\.){3}\d{1,3}\b)"
)

# Tools whose arguments can move data out or change state. Anything else is
# treated as read-only.
SENSITIVE_TOOLS = {
    "send_email": "egress",
    "http_post": "egress",
    "create_webhook": "egress",
    "share_file": "egress",
    "run_shell": "exec",
    "write_file": "state",
    "transfer_funds": "state",
    "update_permissions": "state",
}


@dataclass
class AgentAlert:
    rule: str
    severity: str
    trace_id: str
    span_id: str
    summary: str
    evidence: dict[str, Any] = field(default_factory=dict)


def _indicators(text: str) -> set[str]:
    return {m.group(0).rstrip(".,);") for m in _INDICATORS.finditer(text or "")}


def _user_text(attrs: dict[str, Any]) -> str:
    raw = attrs.get("gen_ai.input.messages")
    if not raw:
        return ""
    try:
        msgs = json.loads(raw) if isinstance(raw, str) else raw
    except json.JSONDecodeError:
        return ""
    parts = []
    for m in msgs:
        if m.get("role") == "user":
            for p in m.get("parts", []):
                if p.get("type") == "text":
                    parts.append(p.get("content", ""))
            if isinstance(m.get("content"), str):
                parts.append(m["content"])
    return "\n".join(parts)


def analyse_trace(spans: Iterable[dict[str, Any]], scanner: Scanner | None = None) -> list[AgentAlert]:
    """Walk one trace's spans in start order and flag injection-driven actions."""
    scanner = scanner or Scanner()
    alerts: list[AgentAlert] = []
    user_seen: set[str] = set()
    untrusted_seen: dict[str, str] = {}   # indicator -> span_id that introduced it

    for span in sorted(spans, key=lambda s: s.get("start_time", 0)):
        attrs = span.get("attributes", {})
        op = attrs.get("gen_ai.operation.name")
        trace_id = span.get("trace_id", "?")
        span_id = span.get("span_id", "?")

        if op == "chat":
            user_seen |= _indicators(_user_text(attrs))
            continue

        if op != "execute_tool":
            continue

        tool = attrs.get("gen_ai.tool.name", "")
        args = str(attrs.get("gen_ai.tool.call.arguments", ""))
        result = str(attrs.get("gen_ai.tool.call.result", ""))

        # 1. Did a sensitive call use an indicator that only untrusted content supplied?
        if tool in SENSITIVE_TOOLS:
            steered = sorted(i for i in _indicators(args) if i in untrusted_seen and i not in user_seen)
            if steered:
                alerts.append(AgentAlert(
                    rule="AGENT-001 untrusted-content-steered tool call",
                    severity="high" if SENSITIVE_TOOLS[tool] == "egress" else "medium",
                    trace_id=trace_id,
                    span_id=span_id,
                    summary=f"'{tool}' called with {steered}, which came from tool output, not the user",
                    evidence={"tool": tool, "indicators": steered,
                              "introduced_by": {i: untrusted_seen[i] for i in steered}},
                ))

        # 2. Scan what the tool returned before the model reads it next turn.
        if result:
            scan = scanner.scan(result)
            if scan.flagged:
                alerts.append(AgentAlert(
                    rule="AGENT-002 prompt injection in tool output",
                    severity="medium",
                    trace_id=trace_id,
                    span_id=span_id,
                    summary=f"output of '{tool}' contains instructions aimed at the agent",
                    evidence={"score": round(scan.score, 3),
                              "findings": [f.evidence for f in scan.findings]},
                ))
            for ind in _indicators(result):
                untrusted_seen.setdefault(ind, span_id)

    return alerts
