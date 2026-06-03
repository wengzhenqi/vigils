# Audit Ledger

`vigil-audit` — an append-only ledger protected by a SHA-256 hash chain:

```
event_n.hash = sha256(event_{n-1}.hash || serde_jcs(event_n) || timestamp_n)
```

`serde_jcs` (RFC 8785 canonical JSON) keeps the hash consistent across implementations.

> Since the 2026-06 security audit the chain digest is **versioned (v2)** and additionally
> binds `session_id`, `event_type`, and `redacted_text`, so a local actor with database write
> access can no longer rewrite those columns undetected. Historical v1 events stay verifiable,
> and `verify_chain` enforces version monotonicity (a v2→v1 downgrade is rejected). See the
> [ADR Index](../adr/index.md) and the
> [security advisory](https://github.com/duncatzat/vigils/blob/main/docs/security/SECURITY-AUDIT-2026-06-03.md).

## Storage

SQLite (WAL) + FTS5. Schema: `vigil-audit/migrations/`.

## Invariants

- Append-only (no `UPDATE` / `DELETE`).
- No-plaintext (raw secrets are never stored).
- SHA-256 chain (tamper-evident).
- FTS5 search by `event_type` / `session_id`.

See ADR 0001 and ADR 0005.
