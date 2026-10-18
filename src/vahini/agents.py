"""The always-on agent mesh: where scripts used to be.

A SOAR script fires one fixed step when a rule matches. The mesh instead keeps
running, takes every alert and every AI-agent trace as it arrives, triages it
through all of Vahini's layers, correlates it with what came before, and then:

* runs the actions the policy gate allows (low risk, trusted inputs),
* parks everything else in an approval queue for an analyst, with the reason,
* and writes every step to the case's ledger.

Execution happens through an ``Executor`` that lives inside the customer's
network and is the only component able to turn tokens back into real names.
"""

from __future__ import annotations

import asyncio
import itertools
import time
from dataclasses import dataclass, field
from typing import Any, Protocol

from .agentwatch import AgentAlert, analyse_trace
from .correlate import Incident, correlate
from .policy import Decision, ProposedAction
from .privacy import Vault
from .triage import TriageReport, Vahini


class Executor(Protocol):
    def run(self, tool: str, args: dict[str, str]) -> str: ...


@dataclass
class DryRunExecutor:
    """Customer-side executor that records what it would do.

    Swap for real connectors (EDR isolate, IdP reset, firewall block) in
    production; the contract is the same.
    """

    vault: Vault | None = None
    log: list[tuple[str, dict[str, str]]] = field(default_factory=list)

    def run(self, tool: str, args: dict[str, str]) -> str:
        real = {k: (self.vault.reveal(v) or v) if self.vault else v for k, v in args.items()}
        self.log.append((tool, real))
        return f"dry-run: {tool}({', '.join(f'{k}={v}' for k, v in real.items())})"


@dataclass
class PendingApproval:
    id: str
    case_id: str
    action: ProposedAction
    reasons: list[str]
    created: float = field(default_factory=time.time)

    def summary(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "case": self.case_id,
            "tool": self.action.tool.name,
            "args": {k: v.value for k, v in self.action.args.items()},
            "provenance": {k: sorted(s.value for s in v.sources) for k, v in self.action.args.items()},
            "reasons": self.reasons,
        }


class AgentMesh:
    def __init__(self, vahini: Vahini, executor: Executor, window_s: float = 3600) -> None:
        self.vahini = vahini
        self.executor = executor
        self.window_s = window_s
        self.cases: dict[str, TriageReport] = {}
        self.approvals: dict[str, PendingApproval] = {}
        self.agent_alerts: list[AgentAlert] = []
        self._recent: list[dict[str, Any]] = []
        self._ids = itertools.count(1)
        self.queue: asyncio.Queue[tuple[str, Any]] | None = None

    # --- one step ----------------------------------------------------------------
    def handle_alert(self, alert: dict[str, Any]) -> TriageReport:
        report = self.vahini.triage(alert)
        self.cases[report.alert_id] = report
        for action, decision, reasons in report.actions:
            if decision == Decision.ALLOW:
                result = self.executor.run(action.tool.name, {k: str(v.value) for k, v in action.args.items()})
                report.ledger.append("respond", "action", {"tool": action.tool.name, "result": result})
            elif decision == Decision.REQUIRE_APPROVAL:
                pid = f"apr-{next(self._ids)}"
                self.approvals[pid] = PendingApproval(pid, report.alert_id, action, reasons)
                report.ledger.append("respond", "approval_requested", {"id": pid, "tool": action.tool.name})
        self._recent.append(report.model_view or alert)
        cutoff = float(alert.get("ts", 0)) - self.window_s
        self._recent = [a for a in self._recent if float(a.get("ts", 0)) >= cutoff]
        return report

    def handle_trace(self, spans: list[dict[str, Any]]) -> list[AgentAlert]:
        found = analyse_trace(spans, self.vahini.scanner)
        self.agent_alerts.extend(found)
        for a in found:
            self.handle_alert({
                "id": f"{a.rule.split()[0]}-{a.trace_id}-{a.span_id}",
                "ts": time.time(),
                "category": "ai.agent",
                "severity": a.severity,
                "tactic": "exfiltration" if "001" in a.rule else "execution",
                "host": f"agent-trace-{a.trace_id}",
                "description": a.summary,
            })
        return found

    def incidents(self) -> list[Incident]:
        return correlate(self._recent, self.window_s)

    # --- people in the loop -----------------------------------------------------------
    def approve(self, approval_id: str, analyst: str) -> str:
        p = self.approvals.pop(approval_id)
        result = self.executor.run(p.action.tool.name, {k: str(v.value) for k, v in p.action.args.items()})
        self.cases[p.case_id].ledger.append(f"analyst:{analyst}", "approved",
                                            {"id": approval_id, "by": analyst, "result": result})
        return result

    def deny(self, approval_id: str, analyst: str, note: str = "") -> None:
        p = self.approvals.pop(approval_id)
        self.cases[p.case_id].ledger.append(f"analyst:{analyst}", "denied", {"id": approval_id, "by": analyst, "note": note})

    # --- always on ----------------------------------------------------------------------
    async def submit(self, kind: str, payload: Any) -> None:
        if self.queue is None:
            self.queue = asyncio.Queue()
        await self.queue.put((kind, payload))

    async def run(self, stop: asyncio.Event) -> None:
        """Consume alerts and traces until ``stop`` is set."""
        if self.queue is None:
            self.queue = asyncio.Queue()
        while not stop.is_set():
            try:
                kind, payload = await asyncio.wait_for(self.queue.get(), timeout=0.2)
            except asyncio.TimeoutError:
                continue
            if kind == "alert":
                self.handle_alert(payload)
            elif kind == "trace":
                self.handle_trace(payload)
            self.queue.task_done()
