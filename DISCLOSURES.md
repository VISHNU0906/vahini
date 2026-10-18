# Third-party disclosures

CyberForge rule 1 asks participants to disclose third-party tools, APIs, datasets and open-source components. This repository's code was written for CyberForge 2026. The ideas it builds on are listed here.

## Research and products that inspired the design
| Item | Used for |
|---|---|
| CaMeL, Google DeepMind (arXiv:2503.18813) | Privileged/quarantined split, capability labels |
| FIDES, Microsoft (arXiv:2505.23643) | Information-flow labels, deterministic policy checks |
| Progent (arXiv:2504.11703) | Per-tool privilege policy |
| Meta, "Agents Rule of Two" (Oct 2025) | Approval rule for tainted state changes |
| Beurer-Kellner et al., Design Patterns (arXiv:2506.08837) | Plan-then-execute / action-selector |
| AIDA / ALERT-BENCH (arXiv:2610.10608) | Adversary/Judge roles, append-only ledger |
| LogInject (arXiv:2607.14493); Sygnia "When Your Logs Lie" | Problem evidence, threat model |
| DataSentinel / known-answer detection (arXiv:2504.11358) | Canary checks |
| TaskTracker (arXiv:2406.00799) | Planned layer-3 activation probes |
| SOC Prime LogTotal sanitizer (Aug 2026) | Keyed pseudonymisation that keeps correlation |
| Split conformal prediction (Angelopoulos & Bates, arXiv:2107.07511) | Auto-close threshold |
| OpenTelemetry GenAI semantic conventions | Agent trace schema |
| OWASP Top 10 for Agentic Applications; MITRE ATT&CK / ATLAS | Detection mapping, kill-chain ordering |

## Prior work by the team
Vishnu Kosuri has earlier public research repositories on related topics: prompt-injection provenance detection (`taint`), alert correlation (`triage`) and LLM endpoint scanning (`promptstrike`). No code from them is copied here; Prahari is a fresh implementation.

## Planned for hackathon day
| Component | License |
|---|---|
| Wazuh | GPLv2 |
| OpenTelemetry Collector | Apache-2.0 |
| FastAPI | MIT |
| Llama Prompt Guard 2 (`meta-llama/Llama-Prompt-Guard-2-86M`) | Llama 4 Community License |
| Microsoft GUIDE dataset (Kaggle) | CDLA-2.0 |
| Claude API (Anthropic) and/or a local open-weight model | Provider terms |

## AI tools
AI coding assistants were used during development, as the CyberForge rules permit.
