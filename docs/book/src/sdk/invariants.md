# SDK Invariants

The SDK boundary is defined by ADR 0015. Consumers can rely on these guarantees.

## 1. Fail-closed

```rust
match firewall.evaluate(..) {
    Ok(FirewallOutcome::Allow) => proceed(),
    Ok(_) => other_handling(),
    Err(e) => return Err(e),  // NEVER default to allow
}
```

## 2. No-plaintext audit

Raw text passed to the SDK is **never** persisted. Audit records go through `DecisionRecord` /
`AuditEvent` (a hash plus a redacted body).

## 3. `DecisionRecord` mandatory

Every effect must first produce a `DecisionRecord`. No SDK API lets a consumer skip it.

## 4. API stability

- 0.x: additive improvements are allowed (each behind review + an ADR).
- After v1.0: additive only — no removals, no signature changes.
- Adding a variant/field to a `#[non_exhaustive]` enum/struct is not a breaking change.

## 5. Reviewed surface changes

Every change to the SDK's public surface is reviewed before release.
