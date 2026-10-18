# Vahini

**An AI-powered SOC that cannot be manipulated. Built to withstand modern, AI-powered attacks.**

> Prevention is ideal. Detection is a must. Making detection reliable matters even more.

Vahini (वाहिनी, "a force") is an AI SOC built by Team Zenith for CyberForge 2026. It reads every alert, log and AI-agent trace, and it assumes the attacker wrote some of what it reads.

![Vahini across an enterprise](docs/diagrams/topology.svg)

---

## The problem

AI is being used in SOC. But nobody is considering the attack surface AI brings to the table. Security teams are handing alert triage to AI, and that's the right move. But the AI reads usernames, browser strings, emails and command lines all day, and attackers can write into every one of them.

AI can be manipulated. It can hallucinate. It can be attacked. Today it is trusted like an insider anyway.

| Where it breaks | What happens |
|---|---|
| **Poisoned input** | A log line says "this is a test, close it", and the AI does. |
| **Silence read as safety** | A search comes back empty, so the AI calls the alert harmless. Wiping the logs works. |
| **Filters getting bypassed** | Prompt filters catch known tricks. Attackers change tricks. |
| **Data leaking into prompts** | Raw logs full of names and secrets go straight into AI models. |
| **Confident and wrong** | The AI hallucinates a verdict and sounds sure, so people re-check everything. |
| **Unwatched AI agents** | Company chatbots and agents call tools, and the SOC can't see them. |

Attackers use AI now too. A SOC system that can hallucinate is not a reliable defense.

## The idea: zero trust, for the AI itself

Vahini brings zero trust and defense in depth into the AI-powered SOC. Nothing is trusted by default, and every layer checks the one before it. Trust, but verify.

| Layer | What it does | Stops |
|---|---|---|
| 1. Sanitise at the edge | Raw data never leaves your network. Names become tokens, secrets get stripped. | data leaking into prompts |
| 2. Scan for manipulation | Poisoned input is caught before any AI reads it, and it raises suspicion. | poisoned input |
| 3. Quarantine the reader | The AI that reads raw text can only hand back facts, never orders. | filters getting bypassed |
| 4. Gate every action | Every fact remembers where it came from. Untrusted data behind an action means a human signs off. | AI acting for the attacker |
| 5. Prove before closing | An alert closes only when trusted evidence rules out every attack theory. | silence read as safety |
| 6. Bound the autonomy | The AI auto-closes only below a ceiling your SOC lead sets. | confident and wrong |
| 7. Watch the agents | Your own AI agents are monitored with the same rules, in the same queue. | unwatched AI agents |
| Base. Sign everything | Every layer signs what it did into a hash-chained ledger (Ed25519). Nobody can deny it or quietly rewrite it. | repudiation |

**No action is taken without validated findings across multiple layers.** All it takes is one bad alert, so we make it non-repudiable at every layer of the stack. Attackers can manipulate AI, but not us!

## From scripts to agents

Scripts are static in nature. Agents can take contextual action, remediation and response. Vahini runs AI agents that never stop. They read context, act, remediate and respond, and stay fenced in by zero trust. Low-risk work on trusted data happens on its own. Everything else waits for a person, with the reason attached.

![One alert, end to end](docs/diagrams/lifecycle.svg)

## Run it

Python 3.10 or newer. The core has no dependencies.

```bash
pip install -e ".[dev]"
vahini demo                                   # offline, end to end
vahini replay examples/wazuh_alerts.json      # triage a real Wazuh alerts file
pytest -q
```

To run the API (and the always-on agent mesh behind it):

```bash
pip install -e ".[service,audit]"
export VAHINI_TENANT=vishnu-org VAHINI_TENANT_KEY=... VAHINI_CROWN_JEWELS=SAP-FIN-DB
vahini serve --port 8080
```

| Endpoint | Purpose |
|---|---|
| `POST /v1/alerts` | A Vahini alert, or a raw Wazuh alert with `?source=wazuh` |
| `POST /v1/traces` | OTLP/JSON traces from your AI agents |
| `GET /v1/cases/{id}` | Verdict, route, actions and the verified ledger |
| `GET /v1/incidents` | Correlated incidents, most advanced kill chain first |
| `GET /v1/approvals` | Actions waiting for an analyst, with the provenance of every argument |
| `POST /v1/approvals/{id}` | Approve or deny (signed with the analyst's key) |
| `GET /v1/keys` | Public keys, so auditors can verify every ledger entry |

With Docker: copy `.env.example` to `.env`, then `docker compose up`.

To use a real model, install `.[llm]` and set `ANTHROPIC_API_KEY` for Claude, or point `OllamaModel` at a local model when data must stay on-prem. Both plug into the quarantined reader and the planner in [`src/vahini/llm.py`](src/vahini/llm.py).

## What's in the box

```
src/vahini/
  privacy.py        layer 1  tenant-keyed tokens, secret removal
  detect.py         layer 2  hidden-character and steering detection on raw text
  llm.py            layer 3  quarantined reader + planner, Claude or local model, canary-checked
  capability.py     layer 4  every value carries where it came from
  policy.py         layer 4  plain-code policy gate
  judge.py          layer 5  no benign verdict while an attack theory is open
  conformal.py      layer 6  auto-close ceiling with a provable bound
  agentwatch.py     layer 7  injection-steered tool calls in your own AI agents
  ledger.py         base     signed (Ed25519), hash-chained evidence ledger
  canary.py                  known-answer check on every reader call
  correlate.py               alerts -> incidents, ranked by kill-chain stage
  triage.py                  the pipeline that ties the layers together
  agents.py                  always-on agent mesh, executor, approval queue
  connectors/       wazuh.py (alerts.json / webhook), otel.py (OTLP/JSON traces)
  service.py                 FastAPI app
  cli.py, demo.py
docs/
  architecture.md   how each layer works, with diagrams
  threat-model.md   what we defend against, and what we don't
  research-basis.md the papers and products this builds on
  adr/              the decisions behind the design
  diagrams/         generated SVGs (python docs/diagrams/diagrams.py)
```

## Honest limits

- The detectors will miss things. Adaptive attackers beat every published filter. That's why safety comes from the policy gate and the ceiling, not from detection.
- The auto-close ceiling only holds while new alerts look like the calibration data. Recalibrate per customer, weekly.
- The demo calibration is synthetic. Real calibration needs labelled history.
- The executor in this repo is a dry run. Real EDR, IdP and firewall connectors plug into the same interface.

## Team Zenith

Built for CyberForge 2026 (Mitigata × HackCulture). Credits and third-party components are in [DISCLOSURES.md](DISCLOSURES.md).

Apache-2.0
