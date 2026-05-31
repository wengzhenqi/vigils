# Approval Queue

Human-in-the-loop for risky effects(per `FirewallOutcome::ApprovalRequired`)。

```
firewall::evaluate → ApprovalRequired(req)
  → ApprovalBroker(SQLite persistent)
  → Desktop UI Approval Queue tab
  → user: Approve / Reject / Delegate / Defer
  → ledger event
  → vigil-runner spawn(if approved)
```

## ApprovalScope

per ADR 0014 α5(I10c-β2):
- server_id + tool_name
- effect_kind(read / write / network / etc)
- resource_path
- duration(once / session / forever)

`delegate` 转 super-user / batch approval。

详见 ADR 0003 + ADR 0014。
