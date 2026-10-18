# ADR 0002: Tokenise at the customer edge

**Status:** accepted

## Context
An MSSP serves many customers from one AI service. Sending raw logs to a model leaks personal data and secrets, and the DPDP Act makes that a legal problem as well as a security one.

## Decision
The edge sanitiser runs inside the customer network. It scans raw text for manipulation first, then swaps identities for HMAC tokens under a per-customer key and removes secrets outright. The key and the reverse map stay in the customer's vault. Only the customer-side executor turns tokens back into real names, and only when it runs an approved action.

## Consequences
- Models and Vahini's own service never see a person's name, a host name or a secret.
- Correlation still works, because the same identity always maps to the same token within one customer.
- Tokens from two customers can never be linked.
