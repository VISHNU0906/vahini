"""Settings, read from the environment (see ``.env.example``)."""

from __future__ import annotations

import os
from dataclasses import dataclass, field


def _list(name: str) -> frozenset[str]:
    return frozenset(x.strip() for x in os.environ.get(name, "").split(",") if x.strip())


@dataclass(frozen=True)
class Settings:
    tenant: str = field(default_factory=lambda: os.environ.get("VAHINI_TENANT", "default"))
    tenant_key: str = field(default_factory=lambda: os.environ.get("VAHINI_TENANT_KEY", ""))
    crown_jewels: frozenset[str] = field(default_factory=lambda: _list("VAHINI_CROWN_JEWELS"))
    alpha: float = field(default_factory=lambda: float(os.environ.get("VAHINI_ALPHA", "0.01")))
    beta: float = field(default_factory=lambda: float(os.environ.get("VAHINI_BETA", "0.05")))
    model: str = field(default_factory=lambda: os.environ.get("VAHINI_MODEL", "claude-opus-5-5"))
    ledger_path: str = field(default_factory=lambda: os.environ.get("VAHINI_LEDGER_DB", "vahini-ledger.db"))
    dry_run: bool = field(default_factory=lambda: os.environ.get("VAHINI_DRY_RUN", "true").lower() != "false")

    def validate(self) -> list[str]:
        problems = []
        if len(self.tenant_key) < 32:
            problems.append("VAHINI_TENANT_KEY should be at least 32 characters of randomness")
        if not 0 < self.alpha < 1 or not 0 < self.beta < 1:
            problems.append("VAHINI_ALPHA and VAHINI_BETA must be between 0 and 1")
        return problems
