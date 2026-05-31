# vigil-sdk Reference

[![crates.io](https://img.shields.io/crates/v/vigil-sdk.svg)](https://crates.io/crates/vigil-sdk)
[![docs.rs](https://docs.rs/vigil-sdk/badge.svg)](https://docs.rs/vigil-sdk)

公开稳定 SDK facade(`vigil-types` / `vigil-firewall` / `vigil-redaction` / `vigil-mcp` re-export)。

## 公开 surface

```rust
use vigil_sdk::prelude::*;

// vigil-types
pub use vigil_types::{DecisionRecord, AuditEvent, EffectVector,
    ApprovalRequest, ApprovalResolution, ApprovalScope, ApprovalStatus,
    ToolInvocation, EffectKind, DecisionKind};

// vigil-firewall
pub use vigil_firewall::{Firewall, FirewallConfig, FirewallError, FirewallOutcome,
    EngineStatusReport, PiiScanner, OAuthScopeContext};

// vigil-redaction
pub use vigil_redaction::{scan_text, RedactionResult, Finding, FindingKind, FindingSource};

// vigil-mcp
pub use vigil_mcp::descriptor_hash;
```

## 不在 SDK Phase 1

- Server runtime(Hub / oracle internals)
- Backend impl(`NoopEngine` / `MockEngine` / `OrtEngine`)
- Ops infra(bootstrap / model 分发)
- `vigil-runner` concrete(`WasmRunner` / `spawn_native`)

详见 [Invariants](./invariants.md) + [docs.rs/vigil-sdk](https://docs.rs/vigil-sdk)。
