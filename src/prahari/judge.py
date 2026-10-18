"""Adversarial verdict check: an attack hypothesis must be ruled out, not ignored.

Baseline SOC agents dismiss real attacks when a search comes back empty
(ALERT-BENCH, arXiv:2610.10608). An attacker who clears logs produces exactly
that. Prahari's judge therefore applies three rules to the ledger before any
benign verdict is accepted:

1. Absence of evidence is not evidence of absence: an empty result can never
   lower the maliciousness score; it only counts as a coverage gap.
2. Every attack hypothesis the adversary raises must be answered by a
   positive benign finding (e.g. a change ticket, a known admin), or the
   verdict cannot be benign.
3. Benign evidence must come from a trusted source. Telemetry that *claims*
   to be benign ("this is the pentest vendor") is the attacker talking.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from .ledger import Ledger


@dataclass
class Judgement:
    benign_allowed: bool
    open_hypotheses: list[str] = field(default_factory=list)
    coverage_gaps: list[str] = field(default_factory=list)
    reasons: list[str] = field(default_factory=list)


def judge(ledger: Ledger) -> Judgement:
    hyps = {e.body["id"]: e.body["text"] for e in ledger.by_kind("hypothesis")}
    rebutted: set[str] = set()
    gaps: list[str] = []
    reasons: list[str] = []

    for e in ledger.by_kind("result"):
        b = e.body
        if b.get("empty"):
            gaps.append(b.get("query", "?"))
            continue
        target = b.get("rebuts")
        if target is None:
            continue
        if b.get("trusted"):
            rebutted.add(target)
        else:
            reasons.append(f"rebuttal of {target} rests on untrusted data; ignored")

    open_h = [f"{k}: {v}" for k, v in hyps.items() if k not in rebutted]
    if open_h:
        reasons.append(f"{len(open_h)} attack hypothesis(es) not ruled out")
    if gaps:
        reasons.append(f"{len(gaps)} empty search(es) treated as coverage gaps, not as benign evidence")
    return Judgement(benign_allowed=not open_h, open_hypotheses=open_h, coverage_gaps=gaps, reasons=reasons)
