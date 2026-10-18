# The evidence behind every claim

Each line we say in the pitch, and who backs it: peer-reviewed or preprint research, AI labs, and security companies. Full references are in [README.md](README.md) and [references.bib](references.bib).

## "AI is being used in SOC. But nobody is considering the attack surface AI brings to the table."

| Who | What they found | Source |
|---|---|---|
| LogInject (research, 2026) | Text planted in ordinary log fields (user-agents, usernames) hijacks LLM log analysis across production models; even layered filters leave a residual. | [arXiv:2607.14493](https://arxiv.org/abs/2607.14493) |
| Sygnia (security company, 2025) | An XDR's AI summary repeated the attacker's planted cover story. A fully automated SOC "would have closed the ticket." | [When Your Logs Lie](https://www.sygnia.co/blog/log-prompt-poisoning-xdr-ai-risks) |
| Check Point Research (security company, 2025) | First malware found in the wild carrying a prompt injection aimed at AI malware analysis. | [AI evasion via prompt injection](https://research.checkpoint.com/2025/ai-evasion-prompt-injection) |
| Aim Labs, EchoLeak, CVE-2025-32711 (security company, 2025) | Zero-click prompt injection in a production AI assistant led to data exfiltration. | [arXiv:2509.10540](https://arxiv.org/abs/2509.10540) |
| IBM, Cost of a Data Breach (2025) | Organisations are now reporting breaches of their own AI models and apps, and most of them had no AI access controls. | [IBM report](https://www.ibm.com/reports/data-breach) |
| OWASP Top 10 for Agentic Applications (2025) | Agent goal hijack and tool misuse are the top agentic risks. | [genai.owasp.org](https://genai.owasp.org/) |
| MITRE ATLAS (2025) | Added agent-specific techniques with Zenity Labs, including exfiltration through agent tool calls. | [atlas.mitre.org](https://atlas.mitre.org/) |

## "AI can be manipulated, it can hallucinate, and it can be attacked." / "Filters getting bypassed."

| Who | What they found | Source |
|---|---|---|
| OpenAI, Anthropic, Google DeepMind, ETH Zurich and others: *The Attacker Moves Second* (2025) | Adaptive attacks broke every published prompt-injection defense they tested, filters and classifiers included. | [arXiv:2510.09023](https://arxiv.org/abs/2510.09023) |
| OpenAI (AI lab, 2025) | Treats prompt injection as a long-term problem to keep defending against, not one that will be solved. | [Hardening Atlas against prompt injection](https://openai.com/index/hardening-atlas-against-prompt-injection) |
| Google DeepMind (AI lab, 2025) | Defends Gemini with layers: adversarial training, classifiers, user confirmation. No single layer is enough. | [arXiv:2505.14534](https://arxiv.org/abs/2505.14534), [Google security blog](https://blog.google/security/mitigating-prompt-injection-attacks/) |
| Anthropic (AI lab, 2025) | Builds prompt-injection defenses for its own agents as a core safety problem. | [Prompt injection defenses](https://www.anthropic.com/research/prompt-injection-defenses) |
| Gray Swan IPI Arena, with OpenAI, Meta, Anthropic, UK AISI and US CAISI (2026) | Every frontier model tested was breached by indirect prompt injection. | [arXiv:2603.15714](https://arxiv.org/abs/2603.15714) |

## "A SOC system that can hallucinate is not a reliable defense." / "No proof, no close."

| Who | What they found | Source |
|---|---|---|
| ALERT-BENCH / AIDA (research, 2026) | AI triage agents replayed through a live Wazuh SIEM dismissed real attacks, mostly when a search came back empty. An adversary-plus-judge design with an append-only ledger fixed most of it. | [arXiv:2610.10608](https://arxiv.org/abs/2610.10608) |
| Microsoft, ExCyTIn-Bench (AI lab, 2025) | Even the best models struggle with multi-step threat investigation over real SIEM tables. | [arXiv:2507.14201](https://arxiv.org/abs/2507.14201) |
| Meta and CrowdStrike, CyberSOCEval (2025) | SOC tasks are far from solved by today's LLMs. | [arXiv:2509.20166](https://arxiv.org/abs/2509.20166) |
| Gartner (analyst firm, 2025) | Named "AI SOC Agents" as a new category; adoption is still early. | [Innovation Insight: AI SOC Agents](https://www.gartner.com/en/documents/7075998) |

## "Zero trust and defense in depth, for the AI itself." / "Attackers can manipulate AI, but not us!"

| Who | What they found | Source |
|---|---|---|
| Google DeepMind, CaMeL (AI lab, 2025) | Separating the model that reads untrusted data from the code that acts gives security by design. | [arXiv:2503.18813](https://arxiv.org/abs/2503.18813) |
| Microsoft, FIDES (AI lab, 2025) | Labels on every value plus deterministic checks before any consequential tool call. | [arXiv:2505.23643](https://arxiv.org/abs/2505.23643) |
| Meta, Agents Rule of Two (AI lab, 2025) | An agent that reads untrusted input and can change state must have a human in the loop. | [write-up](https://simonw.substack.com/p/new-prompt-injection-papers-agents) |
| ETH Zurich, Google, Microsoft, IBM, Invariant Labs: Design Patterns for Securing LLM Agents (2025) | Once untrusted input is read, it must not be able to trigger consequential actions. | [arXiv:2506.08837](https://arxiv.org/abs/2506.08837) |
| Progent (research, 2025) | Least-privilege policies enforced in code sharply cut successful injections. | [arXiv:2504.11703](https://arxiv.org/abs/2504.11703) |
| Google Chrome security (2025) | Production agentic browsing uses a separate critic model and origin isolation, not filters alone. | [Chrome agentic security](https://blog.google/security/architecting-security-for-agentic/) |

## "Scripts are static in nature. Agents can take contextual action, remediation and response."

| Who | What they found | Source |
|---|---|---|
| Microsoft (randomized controlled trial, 2025) | Analysts working with an AI triage agent found more true positives and were more accurate, without rubber-stamping it. | [arXiv:2511.13860](https://arxiv.org/abs/2511.13860) |
| Cloud Security Alliance with Dropzone AI (2025) | In a randomized study, AI-assisted analysts were faster and more accurate. | [CSA press release](https://cloudsecurityalliance.org/press-releases/2025/10/07/new-csa-study-finds-ai-improves-analyst-accuracy-speed-and-consistency-in-security-investigations) |
| Palo Alto Networks, Cortex AgentiX (2025) | Replaced its SOAR product with agents, keeping human approval for high-impact actions. | [announcement](https://channelbuzz.ca/2025/10/palo-alto-networks-launches-cortex-agentix-as-next-gen-cortex-xsoar-to-build-deploy-and-govern-the-agentic-workforce-of-the-future-45103/) |
| CrowdStrike, Charlotte AI (2025) | Agentic triage that works within "bounded autonomy". | [CrowdStrike](https://ir.crowdstrike.com/news-releases/news-release-details/crowdstrike-delivers-next-breakthrough-ai-powered-agentic) |

## "All it takes is one bad alert, so we make it non-repudiable at every layer of the stack."

| Who | What they found | Source |
|---|---|---|
| ALERT-BENCH / AIDA (2026) | An append-only investigation ledger is central to reliable SOC agents. | [arXiv:2610.10608](https://arxiv.org/abs/2610.10608) |
| IETF RFC 8032 | Ed25519 signatures: whoever signed an entry cannot later deny it. | [RFC 8032](https://www.rfc-editor.org/rfc/rfc8032) |

## "Your data stays in-house."

| Who | What they found | Source |
|---|---|---|
| SOC Prime, LogTotal (security company, 2026) | Keyed pseudonymisation keeps logs correlatable without exposing identities to AI. | [LogTotal](https://socprime.com/blog/logtotal-public-preview-free-private-security-log-analysis/) |
| India DPDP Rules (2025) | Personal data in logs is regulated; sending it to model providers is a compliance risk. | [MeitY](https://www.meity.gov.in/) |

## "Your agents are finally accountable and auditable."

| Who | What they found | Source |
|---|---|---|
| MCPTox (research, 2025) | Tool poisoning succeeds against agents on real MCP servers. | [arXiv:2508.14925](https://arxiv.org/abs/2508.14925) |
| Invariant Labs / Snyk (security company, 2025) | A malicious GitHub issue made an agent leak private repository data. | [GitHub MCP exploit](https://invariantlabs.ai/blog/mcp-github-vulnerability) |
| OpenTelemetry GenAI semantic conventions | A standard way to trace what agents do, which is what makes them auditable. | [semantic-conventions-genai](https://github.com/open-telemetry/semantic-conventions-genai) |
