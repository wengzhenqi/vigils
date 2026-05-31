# SDK Invariants(ADR 0015)

## 1. Fail-closed
```rust
match firewall.evaluate(..) {
    Ok(FirewallOutcome::Allow) => proceed(),
    Ok(_) => other_handling(),
    Err(e) => return Err(e),  // ❌ NEVER default to allow
}
```

## 2. No-plaintext audit
SDK 接收的 raw 文本 **永不**持久化。Audit 走 `DecisionRecord` / `AuditEvent`(hash + redacted body)。

## 3. DecisionRecord mandatory
任何 effect 必先产 `DecisionRecord`。无 SDK API 让 consumer skip。

## 4. API stability
- 0.x:小改进允许(必经 codex review + ADR)
- v1.0 freeze 后:仅可加,不可删 / 不可改签名
- `#[non_exhaustive]` enum/struct 加新 variant/field 不视为 breaking

## 5. Codex review chain

每轮 SDK 公开 surface 改动经 Codex collaborative review session 兜底
(per `feedback_iteration_scope`)。
