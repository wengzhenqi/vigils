# vigil-sdk Reference

[![crates.io](https://img.shields.io/crates/v/vigil-sdk.svg)](https://crates.io/crates/vigil-sdk)
[![docs.rs](https://docs.rs/vigil-sdk/badge.svg)](https://docs.rs/vigil-sdk)

A stable public facade that re-exports the `vigil-types`, `vigil-firewall`,
`vigil-redaction`, and `vigil-mcp` surfaces.

## Public surface

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

## Out of scope (not exported)

- Server runtime (Hub / oracle internals).
- Backend implementations (`NoopEngine` / `MockEngine` / `OrtEngine`).
- Ops infrastructure (bootstrap / model distribution).
- The concrete `vigil-runner` (`WasmRunner` / `spawn_native`).

See [Invariants](./invariants.md) and [docs.rs/vigil-sdk](https://docs.rs/vigil-sdk).
