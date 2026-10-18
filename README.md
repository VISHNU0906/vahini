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

**Who backs this up.** Researchers from OpenAI, Anthropic and Google DeepMind showed that adaptive attacks get past every published prompt-injection defense ([arXiv:2510.09023](https://arxiv.org/abs/2510.09023)). Log poisoning hijacks AI log analysis ([LogInject](https://arxiv.org/abs/2607.14493), [Sygnia](https://www.sygnia.co/blog/log-prompt-poisoning-xdr-ai-risks)), and malware already targets AI analysts ([Check Point Research](https://research.checkpoint.com/2025/ai-evasion-prompt-injection)). AI triage agents dismiss real attacks when evidence is missing ([ALERT-BENCH](https://arxiv.org/abs/2610.10608)). The fix the labs point to is architecture, not filters: Google DeepMind's [CaMeL](https://arxiv.org/abs/2503.18813), Microsoft's [FIDES](https://arxiv.org/abs/2505.23643) and Meta's Rule of Two. Every claim, with sources: [docs/research/evidence.md](docs/research/evidence.md).

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

## Integrations

| Plug in | How |
|---|---|
| Wazuh | `deploy/wazuh/custom-vahini` integration, or replay `alerts.json` |
| Elastic Security | ECS detection alerts (`connectors/elastic.py`) |
| Microsoft Defender XDR / Sentinel | Graph security `alerts_v2` (`connectors/sentinel.py`) |
| Splunk Enterprise Security | Notable events via webhook (`connectors/splunk.py`) |
| Firewalls, proxies, EDRs | CEF over syslog (`connectors/cef.py`) |
| Your AI agents | OpenTelemetry GenAI traces through `deploy/otel/collector.yaml` |

| Respond through | Action |
|---|---|
| CrowdStrike Falcon, Defender for Endpoint | contain the host |
| Entra ID, Okta | disable the account, revoke sessions |
| Palo Alto / Fortinet / Check Point | block via an External Dynamic List |
| Jira, ServiceNow | open the case |

Every executor builds the exact API request first and stays in dry run until you switch it on.

## Deploy

```bash
docker compose up --build                     # single node
helm install vahini deploy/helm/vahini        # Kubernetes, with network policy and a persistent signed ledger
```

The analyst console is served at `/` by the API.

## Repository map

```
src/vahini/
  privacy.py          layer 1  tenant-keyed tokens, secret removal
  detect.py           layer 2  hidden-character and steering detection on raw text
  promptguard.py      layer 2  Llama Prompt Guard 2 classifier
  llm.py              layer 3  quarantined reader + planner, Claude or local model, canary-checked
  canary.py           layer 3  known-answer check on every reader call
  capability.py       layer 4  every value carries where it came from
  policy.py           layer 4  plain-code policy gate
  judge.py            layer 5  no benign verdict while an attack theory is open
  conformal.py        layer 6  auto-close ceiling with a provable bound
  agentwatch.py       layer 7  injection-steered tool calls in your own AI agents
  ledger.py           base     Ed25519-signed, hash-chained evidence ledger
  triage.py                    the pipeline that ties the layers together
  correlate.py                 alerts -> incidents, ranked by kill-chain stage
  agents.py                    always-on agent mesh and approval queue
  playbooks.py                 loads reviewed playbooks from playbooks/
  connectors/                  wazuh, elastic, sentinel, splunk, cef, otel
  executors/                   edr, identity, firewall, ticketing (dry run by default)
  storage/                     append-only SQLite ledger store
  eval/                        scorecard metrics, Microsoft GUIDE loader and calibration
  service.py, console/         FastAPI app and analyst console
  config.py, cli.py, demo.py
playbooks/                     one reviewed JSON file per alert category
deploy/                        helm chart, wazuh integration, otel collector
examples/                      real-format samples from every connector
docs/
  architecture.md              how each layer works, with diagrams
  threat-model.md              what we defend against
  adr/                         the decisions behind the design
  research/                    papers, reports and BibTeX we build on
  diagrams/                    generated SVGs
tests/                         62 tests
```
