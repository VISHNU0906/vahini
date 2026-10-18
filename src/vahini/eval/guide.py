"""Microsoft GUIDE dataset loader (Kaggle: "Microsoft Security Incident Prediction").

GUIDE holds alert evidence rows graded by real customer analysts as
TruePositive, BenignPositive or FalsePositive. We use it to calibrate the
autonomy ceiling: scores of TruePositive incidents set ``t_alpha``; scores of
the rest set ``t_beta``.
"""

from __future__ import annotations

import csv
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable

from ..conformal import ConformalGate

GRADES = {"TruePositive": True, "BenignPositive": False, "FalsePositive": False}


@dataclass
class Incident:
    incident_id: str
    grade: str
    categories: set[str] = field(default_factory=set)
    techniques: set[str] = field(default_factory=set)
    alert_titles: set[str] = field(default_factory=set)
    entity_types: set[str] = field(default_factory=set)

    @property
    def is_attack(self) -> bool:
        return GRADES.get(self.grade, False)


def load_incidents(path: str | Path, limit: int | None = None) -> list[Incident]:
    incidents: dict[str, Incident] = {}
    with open(path, newline="", encoding="utf-8") as fh:
        for i, row in enumerate(csv.DictReader(fh)):
            if limit is not None and i >= limit:
                break
            grade = row.get("IncidentGrade") or ""
            if grade not in GRADES:
                continue
            key = f"{row.get('OrgId', '')}:{row.get('IncidentId', '')}"
            inc = incidents.setdefault(key, Incident(key, grade))
            inc.categories.add(row.get("Category", ""))
            inc.alert_titles.add(row.get("AlertTitle", ""))
            inc.entity_types.add(row.get("EntityType", ""))
            inc.techniques.update(t for t in (row.get("MitreTechniques") or "").split(";") if t)
    return list(incidents.values())


def calibrate(incidents: list[Incident], scorer: Callable[[Incident], float],
              alpha: float = 0.01, beta: float = 0.05) -> ConformalGate:
    by_label: dict[bool, list[float]] = defaultdict(list)
    for inc in incidents:
        by_label[inc.is_attack].append(scorer(inc))
    return ConformalGate.calibrate(by_label[True], by_label[False], alpha=alpha, beta=beta)
