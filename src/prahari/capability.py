"""Provenance labels for every value that flows through the triage pipeline.

Each value carries the set of sources it was derived from. A value is
*trusted* only if every one of its sources is trusted. Deriving a new value
from labelled parents unions their sources, so taint can never be laundered
by passing data through an intermediate step (including an LLM call).

This is the data-flow half of the dual-plane design described in
docs/architecture.md (after CaMeL, Debenedetti et al., 2025).
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Any, Iterable


class Source(str, Enum):
    ANALYST = "analyst"            # typed by a human analyst in the console
    SYSTEM = "system"              # Prahari config, playbooks, asset inventory
    TELEMETRY = "telemetry"        # raw log / alert fields from SIEM or EDR
    EXTERNAL = "external"          # threat intel feeds, web lookups, emails
    QUARANTINED_LLM = "q_llm"      # anything the quarantined model produced
    AGENT_TRACE = "agent_trace"    # spans captured from a monitored AI agent


TRUSTED_SOURCES = frozenset({Source.ANALYST, Source.SYSTEM})


@dataclass(frozen=True)
class Labeled:
    """A value plus where it came from and who may read it."""

    value: Any
    sources: frozenset[Source]
    # None means "no reader restriction". Otherwise the set of principals
    # (e.g. "soc", "customer:acme") allowed to receive this value.
    readers: frozenset[str] | None = None

    @property
    def trusted(self) -> bool:
        return bool(self.sources) and self.sources <= TRUSTED_SOURCES

    def __repr__(self) -> str:  # pragma: no cover - debugging aid
        tag = "T" if self.trusted else "U"
        srcs = ",".join(sorted(s.value for s in self.sources))
        return f"<{tag}:{srcs} {self.value!r}>"


def label(value: Any, source: Source, readers: Iterable[str] | None = None) -> Labeled:
    return Labeled(value, frozenset({source}), frozenset(readers) if readers is not None else None)


def derive(value: Any, *parents: Labeled, extra: Source | None = None) -> Labeled:
    """Create a value computed from ``parents``.

    Sources are unioned; reader sets are intersected (the most restrictive
    parent wins). ``extra`` adds a source for the step itself, e.g.
    ``Source.QUARANTINED_LLM`` when a model produced the value.
    """
    sources: set[Source] = set()
    readers: frozenset[str] | None = None
    for p in parents:
        sources |= p.sources
        if p.readers is not None:
            readers = p.readers if readers is None else readers & p.readers
    if extra is not None:
        sources.add(extra)
    return Labeled(value, frozenset(sources), readers)
