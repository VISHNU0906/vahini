# ADR 0003: No proof, no close

**Status:** accepted

## Context
AI triage agents tend to call an alert harmless when a search comes back empty. An attacker who wipes logs gets exactly that result.

## Decision
For every alert, an adversary step lists the ways it could be a real attack. A judge allows a benign verdict only when trusted evidence rules out each one. An empty search is recorded as a blind spot, never as proof. A claim that comes from the logs themselves ("this is our pentest vendor") never counts. Every step is written to a hash-chained ledger and signed by the layer, or the analyst, that took it. That makes each case non-repudiable.

## Consequences
- Fewer alerts close on their own, but the ones that do have a reason someone can check.
- The ledger doubles as audit evidence.
