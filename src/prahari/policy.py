"""Deterministic policy engine that sits between the planner and any tool.

The planner model may *propose* response actions, but nothing executes until
this engine returns ALLOW. Rules are plain code, so a prompt injection hidden
in a log line can change what the model says but cannot change what the
engine permits.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum

from .capability import Labeled


class Risk(int, Enum):
    READ = 0        # enrichment lookups, queries
    LOW = 1         # tagging, commenting on a ticket
    MEDIUM = 2      # closing an alert, suppressing a rule
    HIGH = 3        # isolate host, disable account, block IP, allowlist


class Decision(str, Enum):
    ALLOW = "allow"
    REQUIRE_APPROVAL = "require_approval"
    DENY = "deny"


@dataclass(frozen=True)
class ToolSpec:
    name: str
    risk: Risk
    # Tools that send data out of the SOC (email, webhook, ticket to a third
    # party). Their payload readers are checked against the recipient.
    egress: bool = False


@dataclass
class ProposedAction:
    tool: ToolSpec
    args: dict[str, Labeled]
    rationale: str = ""


@dataclass
class Verdict:
    decision: Decision
    reasons: list[str] = field(default_factory=list)


@dataclass
class Policy:
    # Highest risk an action may have and still run without a human, provided
    # every argument is trusted.
    auto_max_risk: Risk = Risk.LOW
    # Assets that always need a human before any non-read action touches them.
    crown_jewels: frozenset[str] = frozenset()

    def evaluate(self, action: ProposedAction, recipient: str | None = None) -> Verdict:
        reasons: list[str] = []
        tool = action.tool
        untrusted = [k for k, v in action.args.items() if not v.trusted]

        # 1. Exfiltration guard: egress payloads must be readable by the recipient.
        if tool.egress:
            if recipient is None:
                return Verdict(Decision.DENY, [f"{tool.name}: egress tool with no recipient"])
            for k, v in action.args.items():
                if v.readers is not None and recipient not in v.readers:
                    return Verdict(
                        Decision.DENY,
                        [f"{tool.name}: arg '{k}' may not be sent to '{recipient}'"],
                    )

        if tool.risk == Risk.READ:
            return Verdict(Decision.ALLOW, ["read-only"])

        # 2. Crown-jewel assets always go to a human.
        for k, v in action.args.items():
            if isinstance(v.value, str) and v.value in self.crown_jewels:
                reasons.append(f"arg '{k}' targets crown-jewel asset '{v.value}'")
        if reasons:
            return Verdict(Decision.REQUIRE_APPROVAL, reasons)

        # 3. Control/data-flow rule: untrusted data may not steer a state change
        #    on its own.
        if untrusted:
            return Verdict(
                Decision.REQUIRE_APPROVAL,
                [f"args {untrusted} derive from untrusted sources"],
            )

        # 4. Risk ceiling for autonomous execution.
        if tool.risk > self.auto_max_risk:
            return Verdict(
                Decision.REQUIRE_APPROVAL,
                [f"risk {tool.risk.name} above autonomous ceiling {self.auto_max_risk.name}"],
            )

        return Verdict(Decision.ALLOW, ["trusted args, within risk ceiling"])
