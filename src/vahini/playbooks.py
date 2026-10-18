"""Data-driven playbooks.

Each file in ``playbooks/`` says, for one alert category, which tools the
planner may pick from and which attack theories the judge must see ruled out.
Playbooks are SYSTEM-trusted: they are reviewed in code review, never written
by a model or taken from an alert.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path

from .triage import TOOLS

DEFAULT_DIR = Path(__file__).resolve().parents[2] / "playbooks"


@dataclass(frozen=True)
class Playbook:
    category: str
    description: str
    tools: tuple[str, ...]
    hypotheses: tuple[str, ...]
    mitre: tuple[str, ...] = ()


def load(path: str | Path) -> Playbook:
    raw = json.loads(Path(path).read_text(encoding="utf-8"))
    unknown = [t for t in raw["tools"] if t not in TOOLS]
    if unknown:
        raise ValueError(f"{path}: unknown tools {unknown}")
    if not raw.get("hypotheses"):
        raise ValueError(f"{path}: a playbook needs at least one attack hypothesis")
    return Playbook(raw["category"], raw.get("description", ""), tuple(raw["tools"]),
                    tuple(raw["hypotheses"]), tuple(raw.get("mitre", [])))


def load_all(directory: str | Path = DEFAULT_DIR) -> dict[str, Playbook]:
    books = [load(p) for p in sorted(Path(directory).glob("*.json"))]
    return {b.category: b for b in books}
