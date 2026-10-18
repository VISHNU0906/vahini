# Hackathon-day build plan (31 Oct – 1 Nov 2026, Mitigata Bengaluru)

The core planes already run offline (`python -m prahari.demo`). Hackathon day turns them into a live product against a real SIEM, with measured numbers.

## Work split (2 people)

| Track | Owner | Deliverable |
|---|---|---|
| A: Live pipeline | Member 1 | Wazuh docker stack → alert webhook → Prahari → actions back through a customer-side executor |
| B: Models and evaluation | Member 2 | LLM quarantined extractor and planner; Prompt Guard 2 layer; GUIDE calibration; metrics |
| C: Console | Shared | Analyst queue with approve/deny, taint provenance per argument, ledger viewer |

## Timeline

| Hours | A: Pipeline | B: Models and eval |
|---|---|---|
| 0–2 | Wazuh single-node in Docker; sample agents emitting auth, FIM and process events | Pull the GUIDE subset; baseline scorer features |
| 2–6 | FastAPI ingest webhook; tenant vault service; executor with dry-run SOAR actions | Quarantined extractor (JSON schema plus canary) on Claude and on a local model; planner over playbooks |
| 6–10 | Attack replay: brute force → login → encoded PowerShell → LSASS access, with planted-payload fields in user-agent and email | Self-consistency scorer (k = 5 votes); conformal calibration per category; Prompt Guard 2 as an L2 detector |
| 10–14 | Console: queue, approve/deny, "why tainted" view, ledger chain check | Evaluation: miss rate at α ∈ {1, 2, 5}%, auto-close share, unsafe-action count with and without the policy engine |
| 14–18 | OTel GenAI collector; demo support-bot agent; AgentWatch alerts into the same queue | Latency profiling; cost per 1,000 alerts |
| 18–22 | Hardening, failure drills (LLM down, malformed output, vault unreachable) | Results table and charts for the presentation |
| 22–24 | Demo rehearsal | Demo rehearsal |

## Live demo script (5 minutes)

1. **Alert storm.** 50 alerts replayed into Wazuh. Prahari collapses them into 3 incidents, and the top one shows a 4-stage kill chain.
2. **Steering attempt.** One alert's user-agent tells the AI to close it as a pentest. Prahari flags it, raises the score, and refuses to auto-close.
3. **Fooled planner.** We force the planner to propose allowlisting the attacker IP. The policy engine sends it to the console with the provenance chain `ip ← TELEMETRY.src_ip`.
4. **Privacy.** Side-by-side of the raw alert and what the model received. Zero raw identifiers, zero secrets.
5. **The dial.** Move α from 5% to 1% and watch the auto-close share and the measured miss rate on held-out data.
6. **AgentWatch.** A support bot reads a poisoned ticket and tries to email the customer list. AGENT-001 fires in the same queue.
7. **Audit.** Tamper with one ledger entry. `verify()` points to it.

## Stack
Python 3.11, FastAPI, Wazuh 4.x, OpenTelemetry Collector, SQLite (ledger and vault for the demo), a React or HTMX console, the Claude API and a local Qwen/Llama via vLLM or Ollama, and `meta-llama/Llama-Prompt-Guard-2-86M`.

## Risks and fallbacks

| Risk | Fallback |
|---|---|
| Venue Wi-Fi or LLM API down | Local model via Ollama; deterministic stand-ins already in `triage.py` |
| Wazuh setup time | Replay alerts from JSON directly into the ingest webhook |
| GUIDE too large | Stratified 50k-alert sample |
