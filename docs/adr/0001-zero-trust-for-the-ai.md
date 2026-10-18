# ADR 0001: Treat our own AI as untrusted

**Status:** accepted

## Context
The SOC's AI reads text that attackers can write: usernames, browser strings, emails, command lines, tickets. Published adaptive attacks get past every prompt filter they were tested against. A model can also hallucinate a verdict and sound sure of it.

## Decision
The AI is never trusted by default. It can read anything, but nothing it reads can decide an action. A plain-code policy gate makes that call, using provenance tags that travel with every value. The model that reads raw text (the reader) and the model that picks steps (the planner) are separate, and the planner never sees raw text.

## Consequences
- Safety doesn't depend on catching the attack. A fooled planner still can't run an attacker-chosen action without a human.
- Some useful automation waits for a person. We accept that, and show the analyst exactly why.
