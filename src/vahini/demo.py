"""End-to-end offline demo: `python -m vahini.demo`.

Runs the sample alert storm and agent trace in examples/ through every plane.
Calibration scores are synthetic (seeded) so the demo is reproducible; on
hackathon day they come from a labelled set such as Microsoft GUIDE.
"""

from __future__ import annotations

import json
import random
from pathlib import Path

from .agentwatch import analyse_trace
from .capability import Source, label
from .conformal import ConformalGate
from .correlate import correlate
from .policy import Policy, ProposedAction, Risk
from .privacy import Vault, sanitize_alert
from .triage import TOOLS, Vahini

ROOT = Path(__file__).resolve().parents[2]
EX = ROOT / "examples"


def _rule(title: str) -> None:
    print(f"\n=== {title} " + "=" * max(0, 66 - len(title)))


def main() -> None:
    alerts = json.loads((EX / "alerts.json").read_text(encoding="utf-8"))
    spans = json.loads((EX / "agent_trace.json").read_text(encoding="utf-8"))

    rng = random.Random(42)
    malicious = [rng.betavariate(6, 2) for _ in range(500)]
    benign = [rng.betavariate(2, 6) for _ in range(2000)]
    gate = ConformalGate.calibrate(malicious, benign, alpha=0.01, beta=0.05)
    vault = Vault("acme-bank", b"tenant-key-held-in-customer-vault")

    pr = Vahini(gate=gate, policy=Policy(auto_max_risk=Risk.LOW, crown_jewels=frozenset({"FIN-DB-01"})),
                 intel={"198.51.100.7"}, vault=vault,
                 change_tickets={"WEB-01"})   # CHG-2231: quarterly ASV scan of WEB-01

    _rule("1. Assurance plane: conformal gate (synthetic calibration)")
    print(f"auto-close below {gate.close_below:.3f}  (<= 1% of real attacks can land here)")
    print(f"escalate above   {gate.escalate_above:.3f}  (<= 5% of benign alerts page on-call)")

    _rule("2. Privacy plane: what the model is allowed to see")
    clean, removed = sanitize_alert(alerts[3], vault)
    print("raw  :", alerts[3]["message"])
    print("model:", clean["message"])
    print("user :", alerts[3]["user"], "->", clean["user"], "| secrets removed:", removed)

    _rule("3. Triage with provenance enforcement")
    for a in alerts:
        rep = pr.triage(a)
        print(f"\n[{rep.alert_id}] {rep.category:18s} score={rep.score:.2f} route={rep.route.value}")
        for field, res in rep.injection.items():
            print(f"   ! injection in '{field}' (p={res.score:.2f}): {res.findings[0].evidence}")
        for note in rep.notes:
            print(f"   ! {note}")
        for act, decision, reasons in rep.actions:
            print(f"   - {act.tool.name:13s} -> {decision.value:16s} {reasons[0]}")
        if rep.judgement and rep.judgement.open_hypotheses:
            print(f"   ? open: {rep.judgement.open_hypotheses[0]}")
        ok, _ = rep.ledger.verify()
        print(f"   ledger: {len(rep.ledger.entries)} entries, chain {'intact' if ok else 'BROKEN'}, "
              f"head {rep.ledger.head[:12]}")

    _rule("4. Worst case: the planner was fooled")
    bad = ProposedAction(TOOLS["allowlist_ip"], {"ip": label("198.51.100.7", Source.TELEMETRY)})
    decision, reasons = pr.evaluate_injected_action(bad)
    print(f"allowlist_ip(198.51.100.7 from telemetry) -> {decision.value}: {reasons[0]}")

    _rule("5. Correlation on pseudonymised data")
    tokenised = [sanitize_alert(a, vault)[0] for a in alerts]
    for inc in correlate(tokenised):
        print(f"incident {inc.alert_ids}  kill-chain stages={inc.progression} {inc.tactics}")

    _rule("6. AgentWatch: the customer's own AI agent")
    for al in analyse_trace(spans):
        print(f"[{al.severity}] {al.rule}: {al.summary}")


if __name__ == "__main__":
    main()
