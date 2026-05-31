# Audit Ledger

`vigil-audit` — append-only ledger with SHA256 hash chain。

```
event_n.hash = sha256(event_{n-1}.hash || serde_jcs(event_n) || timestamp_n)
```

`serde_jcs` canonical JSON 保证跨实现 hash 一致。

## Storage

SQLite WAL + FTS5。schema:`vigil-audit/migrations/`。

## Invariants

- append-only(无 UPDATE/DELETE)
- no-plaintext(raw secret 不入)
- sha256 chain(tamper-evident)
- FTS5 search by event_type / session_id

详见 ADR 0001 + ADR 0005。
