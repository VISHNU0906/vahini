# Architecture

Prahari is a pipeline of five planes. One rule ties them together: **untrusted data may inform a decision, but it may never make one.**

## 1. Trust model

| Source | Trusted? | Examples |
|---|---|---|
| `ANALYST` | yes | What a human types in the console |
| `SYSTEM` | yes | Playbooks, asset inventory (CMDB), change tickets, Prahari config |
| `TELEMETRY` | **no** | Every SIEM/EDR alert field, including the "harmless" ones (user-agent, username, command line, email subject) |
| `EXTERNAL` | **no** | Threat-intel feeds, web lookups |
| `QUARANTINED_LLM` | **no** | Anything a model produced after reading untrusted data |
| `AGENT_TRACE` | **no** | Spans captured from a monitored AI agent |

Values are wrapped in `Labeled(value, sources, readers)` (`capability.py`). Taint propagates through derivation: sources are unioned and reader sets are intersected. That includes derivation by an LLM, so no step can launder attacker data into trusted data.

## 2. The planes

### 2.1 Detection, layer 1 (`detect.py`)
This layer runs on **raw** text before anything rewrites it. It has two detectors:

- **Hidden characters.** It decodes the Unicode tag block (ASCII smuggling) and counts zero-width and bidi-override characters.
- **Steering phrases.** It flags text addressed to an AI reader: overriding instructions, steering the verdict ("mark … false positive"), creating suppressions, blocking escalation, chat-template tokens.

Scores combine by noisy-OR. Layers 2 and 3 plug into the same `Detector` protocol:

- **L2: Llama Prompt Guard 2 (86M).** 97.5% recall at 1% FPR on Meta's evaluation, about 92 ms on an A100. The 22M variant is used where CPU latency matters.
- **L3: activation-delta probes on the quarantined model**, after TaskTracker. They are hardened with adversarial-suffix training, because a universal GCG suffix bypasses vanilla probes (arXiv:2602.00750).

**Design stance.** *The Attacker Moves Second* (arXiv:2510.09023) broke 12 published detectors and model-level defenses at 71–100% ASR. Detection here is therefore **evidence**, not the security boundary. A detected injection does two things: it raises the alert's score (tampering with an alert is itself a sign of intrusion), and it forbids auto-close. Safety does not depend on catching it.

### 2.2 Privacy (`privacy.py`)
- **Identifiers become tenant-keyed tokens.** Users, hosts, IPs and emails are replaced with `HMAC-SHA256(tenant_key, kind‖value)` tokens.
  - IPv4 tokens carry a /24 prefix token, so subnet relationships survive.
  - Identifiers from structured fields are also replaced wherever they appear in free text.
- **Secrets are removed, not tokenised.** AWS keys, JWTs, bearer tokens, passwords, API keys, Luhn-valid card numbers, Indian PAN and Aadhaar shapes all become typed markers (`[SECRET:jwt]`). No model needs a secret's value, only the fact that one was present.
- **The vault stays with the tenant.** It holds the key and the reverse map, and lives inside the customer's boundary. Executors de-tokenise only at action time, inside that boundary.
- **Why this works for an MSSP.** The same person gets different tokens at different customers, so tenants never link up. And the models (cloud or local) never receive personal data in clear, which is a concrete technical measure under the DPDP Act / Rules 2025.

### 2.3 Provenance (`triage.py`, `policy.py`, `canary.py`)
This plane follows the dual-LLM / CaMeL pattern:

- **Quarantined LLM.** It reads sanitised untrusted text and returns *typed values only* (IPs, users, hosts, hashes), validated against a JSON schema. Every call carries a fresh **canary** token that must come back intact in a dedicated field. A missing, altered or leaked canary quarantines the output.
- **Privileged planner.** It sees the alert *category*, the playbook, and opaque references to the extracted values. It never sees raw text, so injected instructions cannot add tools to the plan.
- **Policy engine.** Deterministic code, not a model. For each proposed action it checks these rules in order:
  1. Egress payloads must be readable by their recipient. This is the cross-tenant exfiltration guard.
  2. Read-only tools are allowed.
  3. Crown-jewel assets always go to a human.
  4. Any argument derived from untrusted sources means human approval. This is Meta's *Rule of Two*, enforced in code: an agent that reads untrusted input cannot also change state without a human.
  5. The risk ceiling for autonomous actions applies.

This is the plane that carries the guarantee. The worst case is a fully fooled planner proposing `allowlist_ip(attacker_ip)`. The engine sees that `ip` derives from `TELEMETRY` and routes it to an analyst.

### 2.4 Investigation (`judge.py`, `ledger.py`)
Following AIDA (Strategist / Executor / Adversary / Judge), Prahari works in four steps:

1. **Adversary.** For each alert category, the adversary raises attack hypotheses from a SYSTEM-trusted list. On hackathon day an LLM extends this list.
2. **Executor.** It runs queries: SIEM, EDR, CMDB, change management.
3. **Judge.** It accepts a benign verdict only when **every** hypothesis has been rebutted by **trusted** evidence. An empty result is logged as a coverage gap and never lowers the score. A "rebuttal" sourced from telemetry ("this is our pentest vendor") is ignored.
4. **Ledger.** Every observation, finding, hypothesis, query, policy decision and verdict is appended to a SHA-256 hash chain. `Ledger.verify()` pinpoints the first tampered entry. The ledger is the audit trail for CERT-In incident reports, ISO 27001 A.5.25–5.28 and SOC 2 CC7.

### 2.5 Assurance (`conformal.py`)
The scorer is, on hackathon day, an LLM verdict vote share over k samples, combined with intel and asset criticality. It produces `s ∈ [0,1]`. Prahari calibrates two thresholds on labelled history:

- **`close_below = s₍ₖ₎`.** Here k = ⌊α(n+1)⌋ over n known-malicious scores. For any new true positive exchangeable with that history, `P(s < close_below) ≤ α`.
- **`escalate_above`.** This is the same construction on benign scores at level β, which bounds how many benign alerts page on-call.

Everything in between goes to an analyst. This gives the SOC lead a dial with a written guarantee ("at most 1% of real attacks are auto-closed"), not a vendor accuracy claim. The guarantee needs exchangeability, so the gate is recalibrated weekly per tenant per category, and drift monitoring (score distribution shift) triggers recalibration early.

### 2.6 AgentWatch (`agentwatch.py`)
This plane consumes OTel GenAI spans (`chat`, `execute_tool`; `gen_ai.tool.name`, `gen_ai.tool.call.arguments`, `gen_ai.tool.call.result`, `gen_ai.input.messages`). It tracks which indicators (URLs, emails, IPs) entered the trace through **user** messages and which through **tool output**, and raises two rules:

- **AGENT-001.** A sensitive tool (egress, exec, state change) is called with an indicator that only untrusted tool output supplied. Maps to OWASP ASI01 Goal Hijack / ASI02 Tool Misuse and ATLAS AML.T0086 (exfiltration via agent tool invocation).
- **AGENT-002.** Tool output contains instructions aimed at the agent.

These alerts enter the same triage pipeline. To Prahari, an AI agent is just another monitored asset.

## 3. Correlation (`correlate.py`)
Alerts that share an entity (host, user, source IP) within a window are grouped with union-find. Each incident is ranked by kill-chain progression (distinct ATT&CK tactics) before volume, so a quiet three-stage intrusion outranks a loud scan. Correlation runs on tokens, so it never needs raw identifiers.

## 4. Deployment shape (target)

```
customer site / VPC                     Prahari cloud (or same VPC)
┌──────────────────────────┐            ┌────────────────────────────┐
│ Wazuh / Elastic / M365   │──alerts──▶ │ L1 scan ▶ sanitize ▶ queue │
│ OTel collector (agents)  │──spans───▶ │ quarantined LLM  planner   │
│ Vault: key + reverse map │◀──actions──│ policy ▶ judge ▶ gate      │
│ Executor (SOAR actions)  │            │ ledger store, console      │
└──────────────────────────┘            └────────────────────────────┘
```

- Wazuh integration uses its REST API / an MCP server. Actions go back through the customer-side executor, the only component that holds the vault.
- Model backends are pluggable: Claude, GPT, or local (Qwen / Llama via vLLM) for customers that require on-prem.

## 5. What we measure on hackathon day

| Metric | How |
|---|---|
| Attack-alert miss rate at the auto-close gate | Conformal α vs. empirical, on a held-out GUIDE split |
| Analyst workload | % of alerts auto-closed at α = 1%, 2%, 5% |
| Injection-driven unsafe actions | A fixed set of planted-payload alerts, measured with and without the policy engine (target: 0 unsafe actions executed without approval) |
| PII exposure | Count of raw identifiers reaching the model (target: 0) |
| Latency | p50 / p95 per alert |
