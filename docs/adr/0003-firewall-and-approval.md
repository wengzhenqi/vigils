# ADR 0003 — Firewall Core + Approval Queue(I02+I03 合并)

- 状态:Accepted
- 日期:2026-04-20
- 适用迭代:I02+I03 及以后
- 相关:ADR 0001(控制平面语义)、ADR 0002(审计账本)、AGENTS.md §1 §5 §6

## 背景

I01 完成了"说了算的账本"。I02+I03 要落"谁说了算":在每次 tool call 产生真实副作用
之前,用**确定性规则**推断 `EffectVector`,算风险分,经策略引擎产生
`DecisionRecord`,对高风险动作进入审批队列等待人工裁决。

合并原因:firewall 的 `Approve` 分支直接生产 `ApprovalRequest`,若拆成两轮迭代会
导致 I02 内部只能 Mock 审批 API;合并后一次性把"决策 → 审批 → 解析"闭环打通。

## 决策

### D1 路径规范化(PathExtractor)

- 相对路径基于 session 配置的 `project_roots` 解析为绝对
- `..` 与符号链接必须由 `dunce::canonicalize`(Windows 友好)真实解析 —— **防** `../../etc/passwd` 跳出 project
- Windows:大小写不敏感比较;统一剥除 `\\?\` 长路径前缀
- `~` 展开不支持:视为字面路径,避免跨用户假设
- 输出:绝对 POSIX 风格(`/`)字符串,供 `paths_read` / `paths_write`

### D2 Shell 破坏性识别(ShellExtractor)

- 只解析 **argv**(由 caller 提供结构化数组,或由 `shlex` 从 POSIX 字符串分词);**不**做完整 shell 脚本解析
- **破坏性二进制**:`rm -rf` / `rm -r` / `del /f` / `rmdir /s` / `format` / `mkfs` / `dd if=* of=/dev/*` / `fdisk` / `shred`
- **保护路径**:`/`、`/etc`、`/usr`、`/var`、`$HOME`、`~`、`~/.ssh`、`~/.config`、`C:\`、`C:\Windows`、`%SystemRoot%`
- **Shell metacharacter**(`&& || ; | > >> < $() ` + `` ` ``):设 `requires_shell=true`,直接让策略判 **Deny**(模糊路径 I02 不落 Layer 3 模型)
- 管道 / 命令替换 / 重定向 → Deny(留 I05+ 扩展时配合 sandbox 再放开)

### D3 Policy DSL(vigil-policy)

```rust
struct PolicyRule {
    id: String,
    match_effects: Vec<EffectKind>,
    conditions: Vec<Condition>,
    action: PolicyAction,   // Allow / Deny / Approve
    priority: i32,          // 越大越先
}

enum Condition {
    Inside  { field: EffectField, roots_key: String },     // paths_write ⊂ ${project_roots}
    Outside { field: EffectField, roots_key: String },
    Eq      { field: EffectField, value: PolicyValue },
    HostInAllowList { allowlist_key: String },             // network_hosts ⊆ ${allowed_hosts}
    DestructiveShellOp,
    SecretRefMatches { pattern: String },
    RiskScoreAtLeast(u8),
}

enum PolicyAction { Allow, Deny, Approve }
```

**评估顺序**:
1. 按 `priority` 降序匹配规则
2. 同 priority 多条匹配时采用 **fail-closed 偏序**:`Deny > Approve > Allow`
3. **无规则命中时兜底 `Deny`**(AGENTS.md §6)

占位:`${project_roots}` / `${allowed_hosts}` 由 `PolicyContext` 在 evaluate 时绑定。

**内置默认策略**(对应方案 §3.5 八条验收):
- allow-repo-read、approve-repo-write、deny-outside-project、deny-destructive-shell、
  deny-destructive-sql、approve-comm-send、approve-secret-use、approve-descriptor-drift

### D4 RiskScorer

权重表(方案 §3.4 的精确落地):

| 事件 | 权重 | reason 模板 |
|------|------|-------------|
| 新 server(descriptor 首次见) | +15 | "first-seen MCP server: <id>" |
| descriptor drift | +25 | "descriptor hash changed for <tool>" |
| FsWrite 效应 | +20 | "writes local files: <count>" |
| FsWrite 越过 project_roots | +30 | "writes OUTSIDE project: <path>" |
| NetOutbound | +15 | "outbound network: <hosts>" |
| NetOutbound 未知 host | +20 | "unknown host: <h>" |
| SecretUse | +25 | "uses credential lease: <alias>" |
| ExecNative | +30 | "runs native subprocess" |
| destructive keyword 命中 | +35 | "destructive shell: <bin>" |
| CommSend | +25 | "sends to recipients: <count>" |
| 用户历史同类 allow 次数 ≥ N(I05+) | -15 | "similar action previously approved" |

输出范围 clamp 到 `0..=100`;reasons 列表按权重降序。

### D5 Approval 并发模型

- 纯 `std` 同步:不引入 tokio 依赖;broker 内部用 `Mutex<HashMap<id, Arc<Condvar + Mutex<Option<Resolution>>>>>`
- TTL:提供 `Ledger::sweep_expired() -> Result<Vec<ApprovalResolution>>` 供 UI 定时调用 / 测试直接触发
- 进程重启:pending 行保留;`wait_for_resolution` 在重启后重新绑定 Condvar,无需人为干预
- API 返回统一 `ApprovalResolution` 类型

### D6 ApprovalScope

I02+I03 落地:
- `Once`:绑 `invocation_id`,消费一次 `resolved_at` 冻结
- `ThisSession`:同 session 下,相同 `(server_id, tool_name, args_hash)` 自动 allow

占位(`#[non_exhaustive]` 后续放):
- `ForToolWithSameArgsHash`(跨 session)→ I05
- `ForPolicyTemplate`(派生临时规则)→ I05+

### D7 Outbox 延后

方案 §6.6 的 Outbox 模式(draft → preview → approve → execute)**不落本轮**,推到
I04 Hub + I06 Lease。

### D8 vigil-audit 系统事件 API 收口(实装 F3)

新公开 API(全部走 `pub(crate) append_event_internal`):
- `record_decision(&DecisionRecord, &EffectVector) -> AppendedEvent`  → `decision.recorded`
- `record_approval_created(&ApprovalRequest) -> AppendedEvent`        → `approval.created`
- `record_approval_resolved(&ApprovalRequest, new_status, resolved_by)` → `approval.resolved`
- `record_lease_minted / record_lease_revoked`(I06 用,本轮只 skeleton)

`RESERVED_EVENT_PREFIXES`(单一真相源)扩为:

```rust
pub const RESERVED_EVENT_PREFIXES: &[&str] = &[
    "tool_call.", "decision.", "approval.", "lease.",
];
```

Public `append_event` 命中任一前缀 → `InvalidInput` 拒绝。

## I01 Follow-ups(合并实装)

### F1 `by_key` 字符集与 marker 单一真相

- 常量 `BY_KEY_SAFE_CHARS = "[A-Za-z0-9_-]"` 定义于 `vigil-redaction::lib`
- `KNOWN_REDACTED_MARKER` 与 `redact_value` 的 `by_key=<k>` normalization 共用此常量
- `redact_value` 对 JSON key 做 ASCII normalization:非安全字符 → `_`
- 测试覆盖"带点/带斜杠/中文"的 key

### F2 Replay 默认走 verified

- 新 `Ledger::replay_session_verified(session_id) -> Result<Vec<ReplayEvent>>`:
  - 内部先调 `verify_chain()`;失败直接返 `ChainBroken`,调用方不会拿到半损坏数据
- 原 `replay_session` 保留但 rustdoc 标注 "unverified, prefer `replay_session_verified`"

### F3 `RESERVED_EVENT_PREFIXES` 集合化(D8 已覆盖)

## 影响

- 新 workspace 依赖:
  - `dunce = "1"`:Windows-friendly canonicalize
  - `shlex = "1"`:POSIX shell 分词
  - `url = "2"`:URL 解析
- `vigil-policy` 不再是空骨架;对外暴露 `PolicyEngine` + 默认规则集
- `vigil-firewall` 不再是空骨架;对外暴露 `Firewall` 组合器 + 7 个 extractors
- `vigil-audit` 增加 approval state machine 与 decision/approval/lease 系统事件 API
- `vigil-types` 新增 `ApprovalScope` / `ApprovalResolution`
- 跨 crate 依赖图(I02+I03 后):
  ```
  vigil-types ← vigil-redaction
  vigil-types ← vigil-policy
  vigil-types ← vigil-audit ← vigil-redaction
  vigil-types ← vigil-firewall ← vigil-policy, vigil-audit
  ```
  无环,顶点仍是 vigil-types。

## 取舍

| 放弃 | 理由 |
|------|------|
| 引入 tokio 到 vigil-audit | 同步 Condvar 足够简单,避免运行时依赖蔓延;I04 MCP Hub 自带 tokio 时再由 hub 侧包装 async 版 |
| 完整 shell 脚本解析 | 跨 shell 语法差异大,自己写易错;unsafe parse 不如直接对含 metacharacter 的 argv 统一 Deny |
| 在 I02 做 Layer 3 模型分类 | MVP 三层架构里 Layer 3 是可选项,不阻塞验收;先让 Layer 1+2 打通闭环 |
| OPA / Rego | 对桌面个人版太重;Rust DSL 足够表达当前规则,团队版再做 Rego export/import |

## 验收对照(方案 §3.5 + §6.7)

| # | 方案验收 | 对应测试 / 规则 |
|---|---------|----------------|
| §3.5-1 | repo 内读 → allow | allow-repo-read(Inside project_roots + effects∋FsRead) |
| §3.5-2 | repo 内写 → approve | approve-repo-write(Inside + FsWrite) |
| §3.5-3 | repo 外写 → deny | deny-outside-project(Outside + FsWrite,priority 最高) |
| §3.5-4 | rm -rf → deny | deny-destructive-shell(DestructiveShellOp) |
| §3.5-5 | DELETE / DROP → deny | deny-destructive-sql(Eq destructive=true) |
| §3.5-6 | 发邮件 / 外部消息 → approve | approve-comm-send(effects∋CommSend) |
| §3.5-7 | 使用 secret:// → approve | approve-secret-use(effects∋SecretUse) |
| §3.5-8 | descriptor drift → approve | approve-descriptor-drift(由 caller 标记后走 Approve 路径) |
| §6.7-1 | approve 跨重启存在 | pending 行由 I01 schema 保证 |
| §6.7-2 | 过期 approval 不可执行 | sweep_expired 将状态置 Expired |
| §6.7-3 | deny 后安全错误 | DecisionEngine 返回 Err(Denied) |
| §6.7-4 | allow once 只对当前 invocation | scope=Once 消费即冻结 |
| §6.7-5 | allow this session 不跨 session | scope=ThisSession 仅匹配同 session_id |
| §6.7-6 | 高危外发走 outbox | **延后 I04**(ADR 显式记录) |
