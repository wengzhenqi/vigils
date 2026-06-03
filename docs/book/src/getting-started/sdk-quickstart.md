# SDK Quickstart

```toml
[dependencies]
vigil-sdk = "0.1"
```

## Hello, redaction

Hard-fingerprint PII detection — zero model dependencies:

```rust
use vigil_sdk::prelude::*;

fn main() {
    let result: RedactionResult = scan_text(
        "API: ghp_0123456789abcdefghijklmnopqrstuvwxyz12"
    ).unwrap();
    for f in &result.findings {
        println!("{:?} @ {:?}", f.kind, f.span);
    }
    // Output: github_token @ (5, 45)
}
```

## Firewall + approval

```rust
use vigil_sdk::prelude::*;

let firewall = Firewall::new(FirewallConfig::default());
match firewall.evaluate(&invocation, &decision) {
    Ok(FirewallOutcome::Allow) => proceed(),
    Ok(FirewallOutcome::ApprovalRequired(req)) => queue(req),
    Err(e) => return Err(e),  // FAIL CLOSED
}
```

## Invariants

1. **Fail-closed** — errors → DENY.
2. **No-plaintext audit**.
3. **`DecisionRecord` mandatory**.
4. **API stability** — 0.x minor evolution allowed; v1.0 freezes the surface.

See [Invariants](../sdk/invariants.md).

## Feature flags

| Feature | Default | Description |
|---|---|---|
| `ort` | off | ONNX-Runtime PII scanner (3-engine ensemble) |
