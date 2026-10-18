# Research sources

The papers, reports and industry write-ups Vahini is built on, grouped by the layer they inform. BibTeX for every paper is in [references.bib](references.bib).

We link to the originals instead of committing PDFs. Most are under publisher or author copyright, and links always point to the latest version.

## The problem: AI in the SOC is an attack surface

| Source | Year | Link | What we take from it |
|---|---|---|---|
| LogInject: Context Contamination in LLM Analysis of Network Security Logs | 2026 | [arXiv:2607.14493](https://arxiv.org/abs/2607.14493) | Text planted in log fields steers LLM log analysis; layered filters still leave a residual. Motivates layers 2–4. |
| From Investigation Failures to Reliable SOC Agents (ALERT-BENCH / AIDA) | 2026 | [arXiv:2610.10608](https://arxiv.org/abs/2610.10608) | Triage agents dismiss attacks when searches return empty. Motivates layer 5 and the ledger. |
| Sygnia, "When Your Logs Lie" | 2025 | [sygnia.co](https://www.sygnia.co/blog/log-prompt-poisoning-xdr-ai-risks) | An XDR's AI summary repeated the attacker's cover story. |
| Check Point Research, AI evasion via prompt injection in malware | 2025 | [research.checkpoint.com](https://research.checkpoint.com/2025/ai-evasion-prompt-injection) | Malware now carries instructions aimed at AI analysts. |
| The Attacker Moves Second (Nasr, Carlini, Tramèr et al.) | 2025 | [arXiv:2510.09023](https://arxiv.org/abs/2510.09023) | Adaptive attacks beat published detectors and model-level defenses. Detection is evidence, not the boundary. |
| EchoLeak, CVE-2025-32711 (Aim Labs) | 2025 | [arXiv:2509.10540](https://arxiv.org/abs/2509.10540) | Zero-click prompt injection in a production assistant. |

## Zero trust for the agent (layers 3–4)

| Source | Year | Link | What we take from it |
|---|---|---|---|
| Defeating Prompt Injections by Design (CaMeL), Google DeepMind | 2025 | [arXiv:2503.18813](https://arxiv.org/abs/2503.18813) | Separate the model that reads from the code that acts; capabilities on every value. |
| Securing AI Agents with Information-Flow Control (FIDES), Microsoft | 2025 | [arXiv:2505.23643](https://arxiv.org/abs/2505.23643) | Labels and deterministic checks before consequential tool calls. |
| Progent: Programmable Privilege Control for LLM Agents | 2025 | [arXiv:2504.11703](https://arxiv.org/abs/2504.11703) | Per-tool least-privilege policy enforced in code. |
| Design Patterns for Securing LLM Agents against Prompt Injections | 2025 | [arXiv:2506.08837](https://arxiv.org/abs/2506.08837) | Plan-then-execute, dual LLM and action-selector patterns. |
| Meta AI, "Agents Rule of Two" (via Simon Willison's write-up) | 2025 | [simonw.substack.com](https://simonw.substack.com/p/new-prompt-injection-papers-agents) | Untrusted input plus state change means a human approves. |
| AgentDojo benchmark (ETH Zurich) | 2024 | [arXiv:2406.13352](https://arxiv.org/abs/2406.13352) | Standard environment for measuring injection defenses. |

## Detection (layer 2)

| Source | Year | Link | What we take from it |
|---|---|---|---|
| LlamaFirewall / Prompt Guard 2, Meta | 2025 | [arXiv:2505.03574](https://arxiv.org/abs/2505.03574) | The layer-2 classifier. |
| DataSentinel: known-answer detection of prompt injection | 2025 | [arXiv:2504.11358](https://arxiv.org/abs/2504.11358) | The canary check on every reader call. |
| Get my drift? Catching LLM Task Drift with Activation Deltas (TaskTracker), Microsoft | 2024 | [arXiv:2406.00799](https://arxiv.org/abs/2406.00799) | Planned activation-probe detector. |
| Universal adversarial suffixes against activation probes | 2026 | [arXiv:2602.00750](https://arxiv.org/abs/2602.00750) | Why probes need adversarial hardening. |

## Investigation and evidence (layer 5, base)

| Source | Year | Link | What we take from it |
|---|---|---|---|
| ALERT-BENCH / AIDA | 2026 | [arXiv:2610.10608](https://arxiv.org/abs/2610.10608) | Adversary and judge roles; append-only investigation ledger. |
| ExCyTIn-Bench, Microsoft | 2025 | [arXiv:2507.14201](https://arxiv.org/abs/2507.14201) | Benchmark for LLM threat investigation over Sentinel logs. |
| CyberSOCEval, Meta and CrowdStrike | 2025 | [arXiv:2509.20166](https://arxiv.org/abs/2509.20166) | SOC-task evaluation for LLMs. |
| RFC 8032, Edwards-Curve Digital Signature Algorithm (EdDSA) | 2017 | [rfc-editor.org](https://www.rfc-editor.org/rfc/rfc8032) | Ed25519 signatures on every ledger entry. |

## Privacy (layer 1)

| Source | Year | Link | What we take from it |
|---|---|---|---|
| SOC Prime, LogTotal public preview | 2026 | [socprime.com](https://socprime.com/blog/logtotal-public-preview-free-private-security-log-analysis/) | Keyed pseudonymisation that keeps correlation. |
| India Digital Personal Data Protection Rules | 2025 | [meity.gov.in](https://www.meity.gov.in/) | Why customer PII must not reach model providers. |
| RFC 2104, HMAC | 1997 | [rfc-editor.org](https://www.rfc-editor.org/rfc/rfc2104) | Keyed hashing for tokens. |

## Bounded autonomy (layer 6)

| Source | Year | Link | What we take from it |
|---|---|---|---|
| A Gentle Introduction to Conformal Prediction (Angelopoulos and Bates) | 2021 | [arXiv:2107.07511](https://arxiv.org/abs/2107.07511) | Distribution-free thresholds for the auto-close ceiling. |
| GUIDE: Microsoft security incident dataset | 2024 | [arXiv:2407.09017](https://arxiv.org/abs/2407.09017) | Analyst-graded alerts for calibration. |

## AI agents and telemetry (layer 7)

| Source | Year | Link | What we take from it |
|---|---|---|---|
| OpenTelemetry GenAI semantic conventions | 2026 | [github.com/open-telemetry](https://github.com/open-telemetry/semantic-conventions-genai) | The `gen_ai.*` span attributes AgentWatch reads. |
| OWASP Top 10 for Agentic Applications | 2025 | [genai.owasp.org](https://genai.owasp.org/) | ASI01 goal hijack, ASI02 tool misuse. |
| MITRE ATLAS | 2025 | [atlas.mitre.org](https://atlas.mitre.org/) | AML.T0051 prompt injection, AML.T0086 exfiltration via agent tool. |
| MCPTox: tool poisoning on real MCP servers | 2025 | [arXiv:2508.14925](https://arxiv.org/abs/2508.14925) | Tool-use attack surface of agents. |

## Industry reports

| Source | Year | Link |
|---|---|---|
| IBM, Cost of a Data Breach Report | 2025 | [ibm.com](https://www.ibm.com/reports/data-breach) |
| CERT-In annual incident figures (PIB release) | 2026 | [pib.gov.in](https://www.pib.gov.in/PressReleasePage.aspx?PRID=2217537) |
| SANS SOC Survey | 2025 | [sans.org](https://www.sans.org/white-papers/) |
| ISC2 Cybersecurity Workforce Study | 2025 | [isc2.org](https://www.isc2.org/Insights/2025/12/2025-ISC2-Cybersecurity-Workforce-Study) |
| Gartner, Innovation Insight: AI SOC Agents | 2025 | [gartner.com](https://www.gartner.com/en/documents/7075998) |
| CrowdStrike Global Threat Report | 2026 | [crowdstrike.com](https://www.crowdstrike.com/en-us/global-threat-report) |
