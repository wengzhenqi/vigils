# ADR 0004 — MCP Hub + Outbox + I02+I03 Follow-ups(I04)

- 状态:Accepted
- 日期:2026-04-20
- 适用迭代:I04 及以后
- 相关:ADR 0001(控制平面)、ADR 0002(账本)、ADR 0003(firewall + approval)
- AGENTS.md §1 §3 §5 §7 §8

## 背景

I02+I03 已经把"决策 → 审批 → 解析"闭环打通,但 firewall 是孤立的 —— 没有入口
把它接到真实 MCP 流量。I04 把 `vigil-mcp` 从骨架抬升为 **Vigil Hub**:一个
stdio MCP server,在 agent client(Cursor / Claude Desktop 等)看来是**唯一入口**,
内部聚合并把 tools/list / tools/call 流量转发到上游真实 server,经 firewall 裁决、
approval 阻塞、outbox 可回滚副作用。

本轮**不**做 descriptor drift / 远程 HTTP / lease 真实注入(留给 I05 / I10 / I06)。

## 决策

### D1 MCP 协议子集

实装 MCP 2025-06-18 最小必要子集:`initialize` / `initialized` / `shutdown` /
`tools/list` / `tools/call` / `ping` / `notifications/cancelled`(本轮 stub)。
不实装:`resources/*` / `prompts/*` / `sampling/*` / `roots/*` —— 留 I10 远程 MCP。

### D2 stdio transport + JSON-RPC framer

- **帧协议**:newline-delimited JSON(NDJSON),UTF-8,无 BOM,每条 message 末尾 `\n`
- **日志通道**:Hub 自身 log 只能走 `stderr`(stdout 是 JSON-RPC 通道)
- **并发模型**:**同步 + thread**,不引入 tokio。每个上游 server 一对 reader/writer
  thread + pending-request HashMap(`id → Sender<Response>`,std::sync::mpsc)
- **子进程启动**:`env_clear() + 仅注入已审批环境`(AGENTS.md §7)
- **stderr 捕获**:独立 thread 消费 stderr 写到 audit 以便回放时调查

### D3 Descriptor hash(独立 domain tag)

```text
descriptor_hash = SHA-256(
  b"vigil.descriptor.tool.v1"                        (24 bytes 常量)
  ‖ u32_be(len) ‖ JCS({
      "server_id": ..., "tool_name": ...,
      "schema": ..., "description": ..., "annotations": ...
    })
)
→ hex-lower 64 字符
```

独立 domain tag 防与 `event_hash` 交叉碰撞(ADR 0002 §D3 同原则)。TV 测试向量落
`crates/vigil-mcp/tests/descriptor_hash_vectors.rs`,与 event_hash TV 同级契约。

### D4 Tool namespacing

- 公开名 = `<server_id>__<upstream_tool_name>`(双下划线,方案 §4.4)
- `server_id` 合法字符集 `[a-z0-9_-]+`,Hub 入参校验
- 反向路由 `ToolRoute { public, server_id, upstream_tool_name }` 存内存 HashMap
  (I04);I05 持久化到 server_profiles

### D5 Firewall 集成 + tool call 生命周期

```text
tools/call 流程:
  1. parse public_tool_name → (server_id, upstream_tool_name)
  2. 构造 ToolInvocation(含 descriptor_hash)
  3. 查 ThisSession scope 缓存(F1):命中 → 直接走 4d
  4. firewall.evaluate(call, &oracle) → FirewallOutcome
     a. Allow   → 进 4d
     b. Deny    → JSON-RPC 返安全拒绝错误
     c. Approve → ledger.wait_for_resolution(id, ttl) 阻塞
                    - Approved(scope=Once)         → 进 4d,仅本次放行
                    - Approved(scope=ThisSession)  → 写 approvals.scope 列,进 4d
                    - Denied / Expired / Cancelled → JSON-RPC 返错
  4d. ToolCallSpan:opened → decided → executed / execute_failed
      - 若效应含 CommSend / NetOutbound → 先 draft outbox,待批准后才调上游
      - 否则直接调上游
  5. 结果脱敏后返回 agent client
```

Hub 阻塞等待**是设计** —— agent client 必须感受到延迟(人审暂停)。

### D6 Server Registry(I04 最小版)

- SQLite 新表 `server_profiles`(字段对齐 `vigil_types::ServerProfile`)
- 状态机 I04 范围:`Unapproved → Approved`;**不做** `Approved → DriftPending →
  Approved`(留 I05)
- I04 无 UI,`Ledger::register_server(profile, approve_immediately)` API 登记;
  真实 UI 接入 I08
- `tools/list` 对未登记 / 未审批 server 的 tool 默认**不暴露**(§4.5 step 6)

### D7 Outbox(实装 ADR 0003 §D7 延期项)

SQLite 新表:

```sql
CREATE TABLE outbox_items (
  outbox_id     TEXT PRIMARY KEY,
  invocation_id TEXT NOT NULL,
  session_id    TEXT NOT NULL,
  kind          TEXT NOT NULL,       -- http_post | email | browser_submit
  preview_json  TEXT NOT NULL,       -- 已脱敏的预览
  approval_id   TEXT,
  status        TEXT NOT NULL,       -- Drafted | PendingApproval | Approved | Denied | Expired | Executed | Cancelled | Failed
  created_at    INTEGER NOT NULL,
  approved_at   INTEGER,
  executed_at   INTEGER
);
```

状态机:
```
Drafted ──submit──→ PendingApproval ──approve──→ Approved ──execute──→ Executed
   │                     │                           │                    │
   │                     ├─deny/expire──→ Denied     │                    └─fail──→ Failed
   └──cancel──→ Cancelled
```

**I04 只实装 `kind = http_post`** 的 draft → approve → execute 全流程;email /
browser_submit 留作 I09+。

Outbox 与 approval 的关系:outbox 的 `PendingApproval` 状态**引用** approvals
表的 `approval_id`;这条 approval 有同步 resolved 后,outbox 自动转 `Approved`
(由 Hub 在 wait_for_resolution 返回后触发)。不引入独立的 TTL。

### D8 DescriptorOracle trait(实装 F2)

```rust
pub trait DescriptorOracle: Send + Sync {
    fn status(&self, server_id: &str, tool_name: &str, descriptor_hash: &str)
        -> DescriptorStatus;
}
```

- `Firewall::evaluate` 签名改为 `(call, oracle: &dyn DescriptorOracle)`(破坏性)
- 老的 `DescriptorStatus` 参数直接传入不再支持;调用方必须提供一个 oracle
- 现有 firewall 测试用 `StaticDescriptorOracle(status)` 小工具快速修复
- `ServerRegistry` 实现 `DescriptorOracle` —— 把"我该不该相信这个工具描述"决策
  的唯一来源定在 registry 上,防 firewall 与 pinning 两边语义漂移

## I02+I03 Follow-ups

### F1 `ApprovalScope::ThisSession` 持久化 + 消费

- `approvals` 表新增 `scope` 列(TEXT,nullable,默认 NULL 对应 Once)
- `approve(id, scope)` 时写入
- 新 API `Ledger::find_session_scope_allow(session, server, tool, args_hash)`
  返回 `Option<ApprovalResolution>`;Hub 在 firewall.evaluate **之前** 调
- 命中 → 跳过 firewall,直接走 ToolCallSpan + 上游调用(审计事件类型
  `tool_call.allowed_by_session_scope`,仍然走 typed API)
- args_hash 算法:对 `ToolInvocation.args` 先过 JCS,再 SHA-256 hex-lower
  (与 invocations.args_hash 同源)

### F2 DescriptorOracle(见 D8)

### F3 Outbox(见 D7)

## 影响

- `vigil-mcp` 不再是空骨架
- `vigil-firewall::Firewall::evaluate` 签名变更(破坏性,I04 一次过)
- `vigil-audit` 新增 `outbox_items` 表与 API;`approvals.scope` 列
- 跨 crate 依赖图(I04 后):
  ```
  vigil-types ← vigil-redaction
  vigil-types ← vigil-policy
  vigil-types ← vigil-audit ← vigil-redaction
  vigil-types ← vigil-firewall ← vigil-policy, vigil-audit
  vigil-types ← vigil-mcp ← vigil-firewall, vigil-audit
  ```
  顶点仍是 vigil-types,无环。

## 取舍

| 放弃 | 理由 |
|------|------|
| tokio 异步 stdio | 保持与 I01-I03 的 std 线程一致;I08 Tauri 再引入 tokio 也不迟 |
| 完整 MCP method 集合 | §resources/prompts/sampling/roots 不在 AGENTS 不变量路径上,I10 再扩 |
| 真实 lease 注入 | I06 专门做 OS Keychain 适配;I04 内 SecretUse 仍走 approval 然后调用方手动环境变量 |
| descriptor drift 实时检测 | I05 专做;I04 内 hash 已算,drift 对比在 I05 加 |
| Outbox 三种 kind 全实装 | I04 只做 http_post 证闭环;email/browser_submit 属 I09+ 范畴 |

## 验收(方案 §4.x + §6.6)

| # | 验收 | 对应测试 |
|---|------|---------|
| §12.3 I04-1 | client sees namespaced tools | `hub_lists_namespaced_tools_after_approve` |
| §12.3 I04-2 | tool call creates DecisionRecord | `tools_call_appends_decision_record` |
| §12.3 I04-3 | deny blocks upstream execution | `tools_call_deny_does_not_invoke_upstream` |
| §12.3 I04-4 | approve pauses | `tools_call_approve_blocks_until_resolution` |
| §6.7-6 | 高危外发类动作先进入 outbox | `commsend_tool_call_enters_outbox_first` |
| §4.5-6 | 未批准 server 的 tool 不暴露 | `unapproved_server_hides_tools` |
