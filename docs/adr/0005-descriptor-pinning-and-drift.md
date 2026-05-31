# ADR 0005 — Descriptor Pinning + Drift 状态机(I05)

- 状态:Accepted
- 日期:2026-04-20
- 适用迭代:I05 及以后
- 相关:ADR 0001 / 0002 / 0003 / 0004(I04 tool_descriptors 首次引入)
- AGENTS.md §5 §7

## 背景

I04 落地了 per-tool pinning 的 **gate**:`approved_at IS NULL` 时不暴露。但:
- Drift 检测只是让 `pin_tool_descriptor` 报 `RegistryConflict`,没有 pending/re-approval 闭环
- Server command drift 完全没处理:用户批准 `uvx mcp-server-fs /proj` 后,若下次 argv 变成 `uvx mcp-server-fs /home/alice`,Hub 会静默继续用新 argv 启动
- UI 侧的"首次接入 server"展示数据(exact command + env 请求列表 + sandbox hint)没被结构化

I05 填齐这三块。

## 决策

### D1 Tool descriptor drift 状态机(扩 `tool_descriptors` schema)

新增列:
- `pending_hash TEXT` — tools/list 见到的**新 hash**(若与 `descriptor_hash` 不等)
- `last_drift_at INTEGER` — 首次发现漂移时间
- `last_seen_hash TEXT NOT NULL DEFAULT ''` — 每次 tools/list 更新
- `last_seen_at INTEGER NOT NULL DEFAULT 0`

状态由字段派生(无额外枚举列):

```text
approved_at  descriptor_hash  last_seen_hash  pending_hash  │ 状态
NULL         H1               H1               NULL         │ PinnedUntrusted(等首次 approve)
H1_at        H1               H1               NULL         │ Approved
H1_at        H1               H2               H2           │ Drifted(等 re-approve)
```

写入语义:
- `pin_tool_descriptor(server, tool, hash)`:
  - 首次见(记录不存在):insert 一条 `approved_at=NULL, descriptor_hash=last_seen_hash=hash`
  - 同 hash 幂等:刷新 `last_seen_at / last_seen_hash=hash`
  - 旧 hash 与新 hash 不等:**不再返 `Conflict`**,改为 UPDATE 记录
    - `pending_hash = new_hash`,`last_drift_at = now`(仅首次 drift 时设,后续 drift 只更新 last_seen)
    - `last_seen_hash = new_hash`,`last_seen_at = now`
    - `Ok(drifted=true)` 让 caller 知情

### D2 Server command drift(`server_profiles` schema)

新增列:
- `pending_command_hash TEXT`
- `last_drift_at INTEGER`

Hub 在 `StdioUpstream::spawn` 前调 `Ledger::check_server_command_drift(server, new_argv_hash)`:
- 若等于 `command_hash` → Ok
- 若 `server_profiles.command_hash != new_argv_hash` → 写 `pending_command_hash` + `last_drift_at` + 返 `CommandDrift` 错,**拒绝启动**
- caller(I08 UI)需调 `approve_server_command_drift(server)` 把 `command_hash = pending_command_hash` 后才能启动

### D3 UI 渲染契约(DTO)

在 `vigil-audit` 中新增(`vigil-types` 不引入依赖,只从 audit 层 re-export):

```rust
pub struct ServerOnboardingData {
    pub server_id: String,
    pub transport: TransportKind,
    pub command: Option<Vec<String>>,    // exact argv
    pub command_hash: Option<String>,
    pub pending_command_hash: Option<String>,
    pub requested_env_keys: Option<Vec<String>>, // env key 清单;**值永不出现**
                                                 // None=I05 未知(lease 层尚未接入);
                                                 // Some(vec)=I06 后 lease 给出的显式清单(空 vec=明确无 env 需求)
    pub sandbox_profile_id: Option<String>,
    pub first_seen_at: i64,
    pub trust_level: TrustLevel,
}

pub struct ToolApprovalCard {
    pub server_id: String,
    pub tool_name: String,
    pub current_hash: String,            // 目前 DB 里的 descriptor_hash
    pub proposed_hash: Option<String>,   // None=首次 pin;Some=drift 后的新 hash
    pub first_seen_at: i64,
    pub approved_at: Option<i64>,
    pub last_drift_at: Option<i64>,
}
```

Ledger 新 API:
- `list_pending_server_onboardings() -> Vec<ServerOnboardingData>`(trust_level=Untrusted)
- `list_pending_tool_approvals() -> Vec<ToolApprovalCard>`(approved_at IS NULL)
- `list_drifted_tools() -> Vec<ToolApprovalCard>`(pending_hash IS NOT NULL)
- `list_drifted_servers() -> Vec<ServerOnboardingData>`(pending_command_hash IS NOT NULL)
- `get_onboarding_data(server) -> Option<ServerOnboardingData>`

`requested_env_keys` 字段保留给 I06 lease 接入时由 lease 层计算;I05 统一返 `None`
(R1 Codex 审查指出:空 `vec` 和"未知"语义无法区分,故改为 `Option<Vec<String>>`,
`None`=未知,`Some(vec![])`=显式无 env 需求)。

### D4 Re-approval API

```rust
Ledger::approve_tool_descriptor_to(server, tool, new_hash) -> Result<()>
// Drifted → Approved(新 hash);清 pending_hash;写 audit: tool_approval.re_approved

Ledger::reject_tool_descriptor_drift(server, tool) -> Result<()>
// 清 pending_hash,descriptor_hash 不变;写 audit: tool_approval.drift_rejected

Ledger::approve_server_command_drift(server) -> Result<()>
// command_hash = pending_command_hash;清 pending;写 audit: server.command_re_approved

Ledger::reject_server_command_drift(server) -> Result<()>
// 清 pending_command_hash;写 audit: server.command_drift_rejected
```

所有事件使用 `approval.*` 前缀之外的新前缀 `tool_approval.*` / `server.*` —— 不与 I02+I03
的 approval(即"tool call 审批")语义混淆。**`RESERVED_EVENT_PREFIXES` 不扩展**;
这些前缀的专用 API 收口由语义约束保证(非前缀技术约束)。

### D5 Hub 行为(向 I04 基础上叠加)

- `tools/list`:
  - 调 `pin_tool_descriptor`,得到 drifted flag
  - drifted → 写审计 `tool_descriptor.drifted`(payload 含 old/new hash)+ **不暴露**
  - 非 drifted + 未批准 → 维持 I04 行为(不暴露)
  - 批准 + 非 drifted → 暴露
- `StdioUpstream::spawn`:调用前 Hub 算出 `new_argv_hash = SHA-256(JCS(argv))`,调
  `check_server_command_drift`;返 drift 即拒绝启动,不调 `StdioUpstream::spawn`
- RegistryDescriptorOracle:不变(已基于 `get_pinned_tool_hash`,drift 时返 `Drifted`,但由于
  drifted tool 不会被暴露,oracle 这层主要是为"手动注入 route 的测试"兜底)

### D6 FU1:`inject_route_for_test` / `set_session_id_for_test` 收口

**最初方案**(Codex I04 review 建议):用 `#[cfg(any(test, feature = "test-helpers"))]` 做
完整 gate,生产 build 不可见。

**实施选择**:因 Cargo 不允许自依赖(integration test 在 `tests/` 下是独立 crate,
启用父 crate feature 需要自引用 + 循环依赖),完整 cfg gate 无法与 integration test
共存。折衷方案:
- 保留 `pub fn`(integration test 可用)
- `#[doc(hidden)]`(rustdoc 不展示,工具链层不可见)
- 方法名保留 `..._for_test` 后缀作为肉眼警示
- 注释明确"仅 Hub 内部集成测试使用,不在 AGENTS.md 不变量 API 范围内"

完整 cfg gate 延后到:
- I08 UI 接入时把 Hub 拆为 `HubCore`(内部) + `Hub`(公共 facade),core 直接承载
  test helpers;或
- 抽独立 `vigil-mcp-test-helpers` crate 作为 workspace 成员

本决策已记录在代码注释里,I08 接手时需同步更新。

## 影响

- `vigil-audit`:
  - `tool_descriptors` 表加 4 列
  - `server_profiles` 表加 2 列
  - 新 API:`check_tool_drift` / `check_server_command_drift` / re-approval 四个 / list_* 四个
  - 新 DTO:`ServerOnboardingData` / `ToolApprovalCard`(re-export 到 `vigil-types` 保持
    I08 UI 的依赖方向清晰)
- `vigil-mcp`:
  - Hub tools/list 对 drifted tool 写 `tool_descriptor.drifted` 审计
  - Hub attach_upstream / 未来的 spawn 路径加 command drift 检查
  - `inject_route_for_test` / `set_session_id_for_test` 收 cfg gate
- 跨 crate 依赖图**不变**

## 取舍

| 放弃 | 理由 |
|------|------|
| 用一个 `DescriptorState` enum 列持久化状态 | 字段派生避免额外迁移;同时让 SQL WHERE 更直观(`approved_at IS NULL`) |
| 给 drift 加 `RESERVED_EVENT_PREFIXES` 成员 | 前缀收口是 API 语义的 fail-safe,不宜无限扩张;`tool_approval.*` / `server.*` 用专用 API 写即可 |
| 自动 re-approve(基于 schema 兼容规则) | 安全价值为零;drift 必须人审 |

## 验收(§12.3 I05 四条 + 本轮扩展)

| # | 验收 | 对应测试 |
|---|------|---------|
| §12.3 I05-1 | 新 server locked(trust=Untrusted 时不暴露) | `unapproved_server_does_not_expose_tools`(I04 已有,I05 保留) |
| §12.3 I05-2 | 已批准 server 可见 | `approved_server_exposes_approved_tools_only` |
| §12.3 I05-3 | descriptor 变化触发再审批 | `tool_descriptor_drift_triggers_reapproval` |
| §12.3 I05-4 | command hash 变化触发再审批 | `server_command_drift_blocks_spawn` |
| D3 DTO | onboarding / approval-card 数据可查 | `dto_shapes_persisted_and_readable` |
| D6 FU1 | `inject_route_for_test` 文档明确"仅测试用" | `pub + #[doc(hidden)]` + 模块文档警示(完整 `#[cfg(test)]` gate 延至 I08 Hub facade 重构,因 Cargo 不允许 integration test 通过 self-dep + feature gate 访问 `pub fn`) |
