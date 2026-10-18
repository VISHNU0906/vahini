# Changelog

## 0.3.0
- Every ledger entry is signed (Ed25519) by the layer or analyst that wrote it. Cases are non-repudiable.
- Connectors for Elastic Security, Microsoft Defender XDR / Sentinel, Splunk ES and CEF.
- Executors for CrowdStrike, Defender for Endpoint, Entra ID, Okta, firewall EDLs, Jira and ServiceNow (dry run by default).
- Data-driven playbooks, append-only SQLite ledger store, evaluation scorecard, GUIDE dataset loader.
- Layer-2 Prompt Guard 2 detector, analyst console, Helm chart, Wazuh integration, OTel collector config.

## 0.2.0
- Always-on agent mesh, quarantined reader and planner (Claude or local model), Wazuh and OTLP connectors, HTTP API, CLI.

## 0.1.0
- Core layers: provenance tags, policy gate, privacy plane, judge, hash-chained ledger, autonomy ceiling, AgentWatch.
