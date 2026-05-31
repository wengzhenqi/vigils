# Action Firewall

`vigil-firewall::Firewall::evaluate(invocation, decision) → FirewallOutcome`

Fail-closed effect gating 3-decision API:
- **Allow** — policy + privacy + scope all pass
- **ApprovalRequired** — risky → queue for human
- **Deny** — policy block / PII / scope outside allowlist

## Policy DSL

per ADR 0011 + I10c-β2:OAuth scope allowlist 在 firewall 层强制。

## PII Scanner 集成(ADR 0013)

Hard rules(13 kinds)+ optional ONNX ensemble 双层。详见 [Privacy Filter](./privacy-filter.md)。
