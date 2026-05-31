# Architecture Overview

Vigil 5-layer 控制平面(T0 → T4):

```
T4 — Desktop UI / Browser Ext / CLI
T3 — MCP Hub(server registry, descriptor pinning)
T2 — Action Firewall + Approval Queue + Policy + Audit Ledger
T1 — Privacy Filter + Sandbox Runner(Wasm + Native)
T0 — Types + Schemas(vigil-types)
```

## Crate 布局(v0.13)

### SDK boundary(publishable,10 crates)

| Layer | Crate |
|---|---|
| T0 | `vigil-types` |
| T0 | `vigil-redaction`(hard rules + optional ORT)|
| T0 | `vigil-runner-types`(ADR 0018,v0.13 NEW)|
| T2 | `vigil-policy` / `vigil-audit` / `vigil-lease` / `vigil-firewall` |
| T3 | `vigil-ui-protocol` / `vigil-mcp` |
| — | **`vigil-sdk`**(facade) |

### Internal(not publishable)

- `vigil-runner` concrete(wasmtime + sandbox-linux + vigil-redaction deps)
- `vigil-sandbox-linux`(Linux-only target-gated)
- `vigil-http-auth` / `vigil-http-transport` / `vigil-browser`
- `apps/desktop` / `apps/native-host` / `apps/vigil-hub-cli`

## Key invariants

per ADR 0007 + 0011 + 0015:

- Fail-closed errors → DENY
- No-plaintext audit
- DecisionRecord mandatory
- inherit_env=false(Native)+ fuel/epoch dual limit(Wasm)+ Landlock(Linux)
- preopen allowlist only / per-run independent Engine

## Data flow(typical action)

```
1. AI Agent → MCP request → vigil-hub stdio
2. vigil-hub::descriptor_lookup → drift check
3. vigil-firewall::evaluate → policy + scope + PII
4. (if approval needed) → ApprovalBroker → Desktop UI
5. (on approve) vigil-runner::spawn_native/wasm → sandbox
6. vigil-audit::append → SQLite ledger
7. result → AI Agent
```

每步 fail-closed:错误 → DENY + ledger event。

详见 [ADR Index](../adr/index.md)。
