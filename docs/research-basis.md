# Research basis

What each part of Prahari takes from the 2025–26 literature, and what is new in combining them. Preprints marked † are recent and not yet peer-reviewed.

## The two findings Prahari is built around

| Finding | Source | Number |
|---|---|---|
| Triage agents dismiss attacks when searches return empty | ALERT-BENCH / AIDA, arXiv:2610.10608† (Oct 2026); 1,247 alerts replayed through live Wazuh via MCP | Every baseline missed **≥40.4%** of attack alerts. AIDA (Strategist/Executor/Adversary/Judge plus an append-only ledger) cut that to **3.1%**, F1 0.958 |
| Attacker-written log fields steer LLM log analysis | LogInject, arXiv:2607.14493† (Jul 2026) | ASR up to **88.2%** (83.4% avg) on 3 production LLMs. Layered filters leave **8.4%** |
| Same, observed in an MDR | Sygnia, "When Your Logs Lie" (Aug 2025) | The AI summary repeated the attacker's cover story. A human caught it |
| Malware carrying injections aimed at AI analysts | Check Point Research (Jun 2025) | First in-the-wild sample |

## Why detection cannot be the boundary

| Result | Source |
|---|---|
| 12 published defenses broken by adaptive attacks at 71–100% ASR. Human red-teamers beat 100% of scenarios | *The Attacker Moves Second*, Nasr, Carlini, Tramèr et al., arXiv:2510.09023 |
| A universal GCG suffix fools TaskTracker probes at 93.9–99.6% | arXiv:2602.00750† |
| MELON 76–95% and MetaSecAlign 96% under adaptive attack | arXiv:2510.09023 |
| Frontier models still breached in an open competition (0.5–8.5% ASR) | Gray Swan IPI Arena, arXiv:2603.15714 |

## What each plane borrows

| Plane | Source | What we take | What we change |
|---|---|---|---|
| Provenance | **CaMeL**, Debenedetti et al., arXiv:2503.18813. AgentDojo 77% utility with provable security vs 84% undefended | Privileged/quarantined split; capabilities (provenance + readers) checked at each tool call | Applied to SOC triage. The planner works off the alert *category* and a playbook, so it needs no code-generating interpreter |
| Provenance | **FIDES**, Costa et al. (Microsoft), arXiv:2505.23643 | Integrity/confidentiality labels, deterministic checks before consequential calls | Reader sets keyed to tenants, giving cross-tenant exfiltration control for MSSPs |
| Provenance | **Progent**, Shi et al., arXiv:2504.11703. AgentDojo ASR 41.2% → 2.2% | Per-tool least-privilege policy, deterministic enforcement | Risk tiers matched to SOAR actions; crown-jewel list |
| Provenance | **Agents Rule of Two**, Meta (Oct 2025) | At most two of: untrusted input / sensitive systems / state change | Enforced in code: tainted args plus a state change means a human |
| Provenance | **Design Patterns for Securing LLM Agents**, Beurer-Kellner et al., arXiv:2506.08837 | Action-selector and plan-then-execute | — |
| Detection | **LlamaFirewall / Prompt Guard 2**, arXiv:2505.03574 | Layer-2 classifier (`meta-llama/Llama-Prompt-Guard-2-86M`) | Used as a score input, not a gate |
| Detection | **DataSentinel**, Liu et al., IEEE S&P 2025, arXiv:2504.11358; known-answer detection | Canary that must survive the quarantined call | Fresh per call, plus a leak check across output fields |
| Detection | **TaskTracker**, Abdelnabi et al., arXiv:2406.00799 | Activation-delta probes (layer 3) | Hardened with adversarial-suffix training per arXiv:2602.00750 |
| Detection | Tamper-as-signal | — | **New:** a detected injection *raises* maliciousness and blocks auto-close |
| Investigation | **AIDA**, arXiv:2610.10608† | Adversary/Judge roles; append-only ledger | Judge rules made explicit and deterministic; ledger hash-chained for audit evidence |
| Privacy | **SOC Prime LogTotal** sanitizer (Aug 2026) | Keyed pseudonymisation that keeps correlation; local sanitisation before analysis | Tenant-scoped keys for multi-tenant MSSPs; /24-preserving IP tokens; Indian identifiers (PAN, Aadhaar); free-text propagation of structured identifiers |
| Assurance | Split conformal prediction (Vovk et al.; Angelopoulos & Bates tutorial, arXiv:2107.07511) | Distribution-free quantile thresholds | **New in this setting:** a bounded *miss rate* on auto-closed alerts, recalibrated per tenant/category |
| AgentWatch | **OpenTelemetry GenAI semantic conventions** (development status, 2026) | `gen_ai.*` span schema | Taint-flow rule: sensitive tool args that came from tool output, not the user |
| AgentWatch | OWASP Top 10 for Agentic Applications (Dec 2025); MITRE ATLAS agent techniques (Oct 2025) | Detection mapping (ASI01, ASI02, AML.T0086) | — |

## What is new in the combination

1. **Provenance enforcement inside the SOC itself.** Published CaMeL/FIDES/Progent work protects assistants and coding agents. Prahari applies it to the security analyst agent, where the adversary writes the input by definition.
2. **Privacy and provenance in one label.** The same `Labeled` value carries taint *and* tenant readers, so one engine stops both injection-driven actions and cross-tenant leaks.
3. **Statistical autonomy.** Commercial AI SOCs claim "98% accuracy". Prahari gives the SOC lead a dial with a distribution-free bound on missed attacks, and abstains when that bound can't be met.
4. **Injection as a detection signal.** An alert that argues for its own dismissal is treated as more suspicious, not less.
5. **One queue for infrastructure and AI agents.** AgentWatch makes the customer's LLM agents just another monitored asset, using the same taint logic.

## Supporting market and policy data

- **CERT-In:** 29,44,248 incidents handled in 2025, vs 20,41,360 in 2024 (PIB).
- **IBM Cost of a Data Breach 2025:** global average USD 4.44M; India USD 2.51M. Organisations with extensive security AI averaged USD 3.62M vs 5.52M without.
- **Prophet, State of AI in SecOps 2026:** 28% of alerts never investigated; 75-minute average investigation; 57% review every AI decision; 0% allow full autonomy.
- **DPDP Rules 2025:** notified Nov 2025; most obligations by May 2027; penalties up to ₹250 crore.
- **Gartner:** "AI SOC Agents" sits at the Peak of Inflated Expectations in the 2026 Hype Cycle, with 1–5% penetration.
- **M&A, 2025–26:** Protect AI → Palo Alto; Lakera → Check Point; Prompt Security → SentinelOne; Aim → Cato; Pangea → CrowdStrike; CalypsoAI → F5 (USD 180M); Invariant → Snyk.
