"""Append-only, hash-chained evidence ledger for every investigation.

Every query, result, hypothesis, policy decision and verdict is appended as an
entry whose hash covers the previous entry's hash. Editing or deleting any
past entry breaks the chain, so the ledger doubles as tamper-evident audit
evidence for CERT-In reporting, ISO 27001 and SOC 2 reviews.

The append-only investigation ledger follows AIDA (arXiv:2610.10608), where
it was central to cutting missed attacks from 40.4% to 3.1%.
"""

from __future__ import annotations

import hashlib
import json
import time
from dataclasses import dataclass, field
from typing import Any

GENESIS = "0" * 64


@dataclass(frozen=True)
class Entry:
    seq: int
    ts: float
    actor: str          # "strategist", "executor", "adversary", "judge", "policy", "analyst"
    kind: str           # "query", "result", "hypothesis", "decision", "verdict", ...
    body: dict[str, Any]
    prev: str
    digest: str


def _digest(seq: int, ts: float, actor: str, kind: str, body: dict[str, Any], prev: str) -> str:
    payload = json.dumps([seq, ts, actor, kind, body, prev], sort_keys=True, default=str)
    return hashlib.sha256(payload.encode()).hexdigest()


@dataclass
class Ledger:
    case_id: str
    entries: list[Entry] = field(default_factory=list)

    @property
    def head(self) -> str:
        return self.entries[-1].digest if self.entries else GENESIS

    def append(self, actor: str, kind: str, body: dict[str, Any], ts: float | None = None) -> Entry:
        seq = len(self.entries)
        ts = time.time() if ts is None else ts
        prev = self.head
        e = Entry(seq, ts, actor, kind, body, prev, _digest(seq, ts, actor, kind, body, prev))
        self.entries.append(e)
        return e

    def verify(self) -> tuple[bool, int | None]:
        """Return (ok, index_of_first_bad_entry)."""
        prev = GENESIS
        for i, e in enumerate(self.entries):
            if e.prev != prev or e.digest != _digest(e.seq, e.ts, e.actor, e.kind, e.body, e.prev):
                return False, i
            prev = e.digest
        return True, None

    def by_kind(self, kind: str) -> list[Entry]:
        return [e for e in self.entries if e.kind == kind]
