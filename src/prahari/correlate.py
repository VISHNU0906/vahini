"""Entity-graph correlation: collapse an alert storm into incidents.

Alerts are nodes; two alerts are linked when they share an entity (host,
user, IP) within a time window. Connected components become incidents, and
each incident is ranked by how far it advances along the ATT&CK kill chain,
so a quiet three-stage intrusion outranks a loud single-stage scan.

Works on pseudonymised alerts unchanged: keyed tokens are stable per tenant,
so correlation never needs the raw identifiers.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Iterable

TACTIC_ORDER = [
    "reconnaissance", "initial-access", "execution", "persistence",
    "privilege-escalation", "defense-evasion", "credential-access",
    "discovery", "lateral-movement", "collection", "exfiltration", "impact",
]
_RANK = {t: i for i, t in enumerate(TACTIC_ORDER)}
ENTITY_KEYS = ("host", "user", "src_ip")


@dataclass
class Incident:
    alert_ids: list[str]
    entities: set[str]
    tactics: list[str]
    progression: int = 0
    first_seen: float = 0.0
    last_seen: float = 0.0
    alerts: list[dict[str, Any]] = field(default_factory=list, repr=False)


class _DSU:
    def __init__(self, n: int) -> None:
        self.p = list(range(n))

    def find(self, x: int) -> int:
        while self.p[x] != x:
            self.p[x] = self.p[self.p[x]]
            x = self.p[x]
        return x

    def union(self, a: int, b: int) -> None:
        ra, rb = self.find(a), self.find(b)
        if ra != rb:
            self.p[rb] = ra


def correlate(alerts: Iterable[dict[str, Any]], window_s: float = 3600) -> list[Incident]:
    items = sorted(alerts, key=lambda a: a.get("ts", 0))
    dsu = _DSU(len(items))
    last_by_entity: dict[str, int] = {}
    for i, a in enumerate(items):
        for key in ENTITY_KEYS:
            val = a.get(key)
            if not val:
                continue
            ent = f"{key}:{val}"
            j = last_by_entity.get(ent)
            if j is not None and a.get("ts", 0) - items[j].get("ts", 0) <= window_s:
                dsu.union(i, j)
            last_by_entity[ent] = i

    groups: dict[int, list[int]] = {}
    for i in range(len(items)):
        groups.setdefault(dsu.find(i), []).append(i)

    incidents = []
    for idxs in groups.values():
        group = [items[i] for i in idxs]
        tactics = sorted({a["tactic"] for a in group if a.get("tactic") in _RANK}, key=_RANK.__getitem__)
        ents = {f"{k}:{a[k]}" for a in group for k in ENTITY_KEYS if a.get(k)}
        incidents.append(Incident(
            alert_ids=[str(a.get("id")) for a in group],
            entities=ents,
            tactics=tactics,
            progression=len(tactics),
            first_seen=group[0].get("ts", 0),
            last_seen=group[-1].get("ts", 0),
            alerts=group,
        ))
    incidents.sort(key=lambda inc: (inc.progression, len(inc.alert_ids)), reverse=True)
    return incidents
