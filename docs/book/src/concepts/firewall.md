# Action Firewall

`vigil-firewall::Firewall::evaluate(invocation, decision) → FirewallOutcome`

A fail-closed effect-gating API with three outcomes:

- **Allow** — policy, privacy, and scope checks all pass.
- **ApprovalRequired** — a risky effect is queued for a human.
- **Deny** — policy block, PII detected, or scope outside the allowlist.

## Policy DSL

OAuth scope allowlists are enforced at the firewall layer (see ADR 0011): a request whose
granted scopes fall outside the configured allowlist is denied by default.

## PII scanner integration

Two layers of defense — hard fingerprint rules plus an optional ONNX ensemble. See
[Privacy Filter](./privacy-filter.md) and ADR 0013.
