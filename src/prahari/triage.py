"""Dual-plane triage pipeline.

    alert --> [scan raw text for injection] --> [privacy: keyed pseudonymisation]
          --> [ingest: label as TELEMETRY]
          --> [quarantined extraction: typed IOCs, still untrusted]
          --> [planner: sees alert type + playbook only, never raw text]
          --> [policy engine: allow / approve / deny each action]
          --> [scorer + conformal gate: auto-close / analyst / escalate]

The planner and the scorer are pluggable. The defaults here are small
deterministic stand-ins so the pipeline runs offline; the LLM-backed versions
are described in docs/architecture.md.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any, Callable

from .capability import Labeled, Source, derive, label
from .conformal import ConformalGate, Route
from .detect import ScanResult, Scanner
from .policy import Decision, Policy, ProposedAction, Risk, ToolSpec
from .judge import Judgement, judge
from .ledger import Ledger
from .privacy import Vault, sanitize_alert

TOOLS = {
    "enrich_ip": ToolSpec("enrich_ip", Risk.READ),
    "lookup_user": ToolSpec("lookup_user", Risk.READ),
    "comment": ToolSpec("comment", Risk.LOW),
    "close_alert": ToolSpec("close_alert", Risk.MEDIUM),
    "block_ip": ToolSpec("block_ip", Risk.HIGH),
    "disable_user": ToolSpec("disable_user", Risk.HIGH),
    "isolate_host": ToolSpec("isolate_host", Risk.HIGH),
    "allowlist_ip": ToolSpec("allowlist_ip", Risk.HIGH),
    "notify_customer": ToolSpec("notify_customer", Risk.LOW, egress=True),
}

# Playbooks are SYSTEM-trusted: which tools a given alert category may use.
PLAYBOOKS: dict[str, list[str]] = {
    "auth.bruteforce": ["enrich_ip", "lookup_user", "comment", "block_ip"],
    "endpoint.malware": ["lookup_user", "comment", "isolate_host"],
    "email.phishing": ["lookup_user", "comment", "disable_user"],
    "ai.agent": ["comment", "notify_customer"],
}

# Attack hypotheses the adversary role must see ruled out before a benign verdict.
HYPOTHESES: dict[str, list[str]] = {
    "auth.bruteforce": ["credential compromise followed by a successful login"],
    "endpoint.malware": ["hands-on-keyboard intrusion", "credential theft from memory"],
    "email.phishing": ["user clicked and entered credentials"],
    "ai.agent": ["agent goal hijack via indirect prompt injection"],
}

FREE_TEXT_FIELDS = ("message", "description", "user_agent", "email_subject", "email_body", "command_line")

_IP = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")


@dataclass
class TriageReport:
    alert_id: str
    category: str
    score: float
    route: Route
    injection: dict[str, ScanResult] = field(default_factory=dict)
    actions: list[tuple[ProposedAction, Decision, list[str]]] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)
    model_view: dict[str, Any] = field(default_factory=dict)   # what any LLM is allowed to see
    secrets_removed: dict[str, int] = field(default_factory=dict)
    judgement: Judgement | None = None
    ledger: Ledger | None = None


def ingest(alert: dict[str, Any]) -> dict[str, Labeled]:
    """Every field of an incoming alert is telemetry, i.e. attacker-influenced."""
    return {k: label(v, Source.TELEMETRY) for k, v in alert.items()}


def quarantined_extract(fields: dict[str, Labeled]) -> dict[str, list[Labeled]]:
    """Stand-in for the quarantined LLM: pull typed IOCs out of the alert.

    Outputs are values, never instructions, and they inherit the taint of the
    field they came from plus the quarantined-model source.
    """
    iocs: dict[str, list[Labeled]] = {"ip": [], "user": [], "host": []}
    for key in ("src_ip", "dst_ip"):
        if key in fields and fields[key].value:
            iocs["ip"].append(derive(fields[key].value, fields[key], extra=Source.QUARANTINED_LLM))
    for key in FREE_TEXT_FIELDS:
        if key in fields and isinstance(fields[key].value, str):
            for ip in _IP.findall(fields[key].value):
                iocs["ip"].append(derive(ip, fields[key], extra=Source.QUARANTINED_LLM))
    if "user" in fields:
        iocs["user"].append(derive(fields["user"].value, fields["user"], extra=Source.QUARANTINED_LLM))
    if "host" in fields:
        iocs["host"].append(derive(fields["host"].value, fields["host"], extra=Source.QUARANTINED_LLM))
    return iocs


def plan(category: str, iocs: dict[str, list[Labeled]]) -> list[ProposedAction]:
    """Privileged planner: chooses actions from the playbook for this category.

    It never reads the raw alert text, so injected instructions cannot add
    tools to the plan. IOC values are passed through as opaque, still-tainted
    arguments.
    """
    allowed = PLAYBOOKS.get(category, ["comment"])
    actions: list[ProposedAction] = []
    note = label(f"Prahari triage for {category}", Source.SYSTEM)
    for name in allowed:
        tool = TOOLS[name]
        if name in ("enrich_ip", "block_ip"):
            for ip in iocs["ip"][:1]:
                actions.append(ProposedAction(tool, {"ip": ip}))
        elif name in ("lookup_user", "disable_user"):
            for u in iocs["user"][:1]:
                actions.append(ProposedAction(tool, {"user": u}))
        elif name == "isolate_host":
            for h in iocs["host"][:1]:
                actions.append(ProposedAction(tool, {"host": h}))
        elif name == "comment":
            actions.append(ProposedAction(tool, {"text": note}))
    return actions


def default_scorer(alert: dict[str, Any], injection_score: float, intel: set[str]) -> float:
    """Toy stand-in for the LLM verdict model (self-consistency vote share)."""
    sev = {"low": 0.15, "medium": 0.4, "high": 0.7, "critical": 0.85}.get(str(alert.get("severity")), 0.3)
    hit = 0.25 if alert.get("src_ip") in intel else 0.0
    # Someone trying to talk the SOC out of an alert is itself evidence.
    tamper = 0.35 * injection_score
    return min(1.0, sev + hit + tamper)


@dataclass
class Prahari:
    gate: ConformalGate
    policy: Policy = field(default_factory=Policy)
    scanner: Scanner = field(default_factory=Scanner)
    intel: set[str] = field(default_factory=set)
    scorer: Callable[[dict[str, Any], float, set[str]], float] = default_scorer
    vault: Vault | None = None
    # Hosts with an approved change ticket right now (SYSTEM-trusted).
    change_tickets: set[str] = field(default_factory=set)

    def triage(self, alert: dict[str, Any]) -> TriageReport:
        category = str(alert.get("category", "unknown"))

        # Scan the raw text first: hidden characters must be seen before anything rewrites it.
        injection: dict[str, ScanResult] = {}
        for key in FREE_TEXT_FIELDS:
            v = alert.get(key)
            if isinstance(v, str):
                res = self.scanner.scan(v)
                if res.findings:
                    injection[key] = res
        inj_score = max((r.score for r in injection.values()), default=0.0)

        # Intel matching happens on raw values inside the tenant boundary.
        score = self.scorer(alert, inj_score, self.intel)

        # From here on, only pseudonymised data moves toward any model.
        removed: dict[str, int] = {}
        view = alert
        if self.vault is not None:
            view, removed = sanitize_alert(alert, self.vault)
        fields = ingest(view)

        iocs = quarantined_extract(fields)
        actions = plan(category, iocs)
        route = self.gate.route(score)

        alert_id = str(alert.get("id", "?"))
        ledger = Ledger(alert_id)
        ts = float(alert.get("ts", 0))
        ledger.append("ingest", "observation", {"category": category, "secrets_removed": removed}, ts)
        for key, res in injection.items():
            ledger.append("scanner", "finding", {"field": key, "score": round(res.score, 3),
                                                 "evidence": [f.evidence for f in res.findings]}, ts)

        # Adversary: raise the attack hypotheses for this category.
        for i, text in enumerate(HYPOTHESES.get(category, []), 1):
            ledger.append("adversary", "hypothesis", {"id": f"H{i}", "text": text}, ts)
        # Executor stand-in: the only benign evidence it can produce is a trusted change ticket.
        host = alert.get("host")
        if host and host in self.change_tickets:
            for i, _ in enumerate(HYPOTHESES.get(category, []), 1):
                ledger.append("executor", "result", {"query": f"change_ticket({host})", "rebuts": f"H{i}",
                                                     "trusted": True}, ts)
        else:
            ledger.append("executor", "result", {"query": f"change_ticket({host})", "empty": True}, ts)

        verdict = judge(ledger)
        report = TriageReport(alert_id, category, round(score, 3), route, injection,
                              model_view=view, secrets_removed=removed, judgement=verdict, ledger=ledger)
        if inj_score >= 0.5:
            report.notes.append("log-borne prompt injection detected; alert cannot be auto-closed")
            if report.route == Route.AUTO_CLOSE:
                report.route = Route.ANALYST
        if report.route == Route.AUTO_CLOSE and not verdict.benign_allowed:
            report.notes.append("judge: attack hypotheses still open, auto-close withheld")
            report.route = Route.ANALYST
        for a in actions:
            v = self.policy.evaluate(a)
            report.actions.append((a, v.decision, v.reasons))
            ledger.append("policy", "decision", {"tool": a.tool.name, "decision": v.decision.value,
                                                 "reasons": v.reasons}, ts)
        ledger.append("judge", "verdict", {"score": report.score, "route": report.route.value,
                                           "open_hypotheses": verdict.open_hypotheses}, ts)
        return report

    def evaluate_injected_action(self, action: ProposedAction) -> tuple[Decision, list[str]]:
        """What happens if a compromised or naive planner proposes ``action``."""
        v = self.policy.evaluate(action)
        return v.decision, v.reasons
