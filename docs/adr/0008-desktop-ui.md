# ADR 0008 — Desktop UI(I08a:协议层 + CLI 闭环)

- 状态:**Proposed**
- 日期:2026-04-20
- 依赖:ADR 0001 / 0002 / 0003 / 0004 / 0005 / 0006 / 0007

## 1. 背景与范围

主方案 §9:桌面 UI 是**用户对 Vigil 的信任来源**(不仅是配置页)。§12.3 I08 四条验收:
1. UI 批准能 resolve approval
2. Session replay 加载
3. Server command 可见
4. Secret value 永不可见

**当前状态**:`apps/desktop` 是 I00 `println!` 占位,`vigil-ui-protocol` 是 I00 空骨架。

## 2. 分段交付(D1 决策)

I08 拆为三段,本 ADR 只承诺 **I08a**:

| 段 | 交付 | 本轮验收? |
|----|------|---------|
| **I08a** | `vigil-ui-protocol` 完整 typed enum 协议;`vigil-desktop` 改 CLI 入口;`sandbox_profiles` 持久化 + CRUD + `server_profiles.sandbox_profile_id` 真消费;§12.3 I08 四条由 CLI 闭环 | **是** |
| I08b | Tauri 2 app shell + 最小 invoke 适配 + capabilities 双分组 | 后续 |
| I08c | 4 页真 frontend(Activity / Approvals / Replay / Registry + SandboxProfile 编辑面板) | 后续 |

**不在本 ADR 范围**:
- Tauri 2 集成(D2:Node 工具链未定,不把验收绑给外部依赖)
- 前端 4 页 UI
- SandboxProfile 图形编辑器
- Hash chain 可视化

## 3. 关键决策(Codex 协作)

### D1 — I08 三段式,本轮只 I08a
理由:I08a 足以满足 §12.3 I08 四条验收(CLI 可 resolve approval / 渲染 replay / 打印 argv / SENTINEL 红线);不绑 Tauri / Node。

### D2 — 本轮不接 Tauri
理由:Tauri 2 依赖 Node + tauri-cli + 前端 bundler,当前纯 Rust workspace,验收不应绑外部工具链。Tauri 放 I08b,前置"Node toolchain 可用确认"。

### D3 — 协议形状:typed enum,框架无关
```rust
pub enum UiCommand {
    // --- Read (capability: ui.read) ---
    ListRecentEvents(ListRecentEventsReq),
    GetEventDetail(GetEventDetailReq),
    FtsSearch(FtsSearchReq),
    ListPendingApprovals(ListPendingApprovalsReq),
    GetApprovalDetail(GetApprovalDetailReq),
    ListSessions(ListSessionsReq),
    ReplaySession(ReplaySessionReq),
    VerifyChain,
    ListServers,
    GetServerOnboarding(GetServerOnboardingReq),
    ListPendingToolApprovals,
    ListDriftedTools,
    ListDriftedServers,
    ListSandboxProfiles,
    GetSandboxProfile(GetSandboxProfileReq),
    // --- Write (capability: ui.write) ---
    ResolveApproval(ResolveApprovalReq),
    ApproveTool(ApproveToolReq),
    ApproveToolDrift(ApproveToolDriftReq),
    RejectToolDrift(RejectToolDriftReq),
    ApproveServerCommandDrift(ApproveServerCommandDriftReq),
    RejectServerCommandDrift(RejectServerCommandDriftReq),
    UpsertSandboxProfile(UpsertSandboxProfileReq),
}

pub enum UiResponse {
    Ack,
    EventList(Vec<EventSummary>),
    EventDetail(EventDetail),
    SearchHits(Vec<EventHitDto>),
    ApprovalList(Vec<ApprovalSummary>),
    ApprovalDetail(ApprovalDetailDto),
    SessionList(Vec<SessionSummary>),
    ReplayDump(SessionReplay),
    ChainVerification(ChainVerifyReport),
    ServerList(Vec<StoredServerProfileDto>),
    ServerOnboarding(ServerOnboardingData),
    ToolApprovalList(Vec<ToolApprovalCard>),
    DriftList(Vec<ToolApprovalCard>),
    DriftedServerList(Vec<ServerOnboardingData>),
    SandboxProfileList(Vec<SandboxProfile>),
    SandboxProfileOpt(Option<SandboxProfile>),
    ApprovalResolution(ApprovalResolutionDto),
    ToolDriftResolution(ToolDriftResolutionDto),
    ServerDriftResolution(ServerDriftResolutionDto),
    SandboxProfileUpserted(SandboxProfileUpsertDto),
    ToolApproved(ToolApprovedDto),
}

pub enum UiError {
    NotFound(String),
    Invalid(&'static str),
    CapabilityDenied { required: &'static str },
    LedgerError(String),      // audit error to_string(已脱敏)
    SecretInArgv { server_id: String, rule: &'static str },  // D5
}
```

### D4 — 权限模型
协议层定义每条命令的 `capability: &'static str`(`ui.read` / `ui.write`)。
CLI 在 dispatch 时根据环境变量 `VIGIL_UI_CAPABILITY` 或 CLI flag 判定;Tauri(I08b)从 Tauri capabilities 注入。

### D5 — secret-in-argv 边界
exact argv 原样展示(§4.7);**但** `register_server` / `ApproveTool*` 入口必须拒绝 argv 含
硬指纹 secret-like literal(通过 `vigil_redaction::detect_hard_secret`)。发现 → 返
`UiError::SecretInArgv`;UI 显示红色"Non-compliant binding: use env_lease"。

### D6 — SandboxProfile 持久化
```sql
CREATE TABLE sandbox_profiles (
  profile_id       TEXT PRIMARY KEY,
  profile_json     TEXT NOT NULL,   -- JCS 规范化
  profile_hash     TEXT NOT NULL,   -- sha256(profile_json)
  created_at       INTEGER NOT NULL,
  updated_at       INTEGER NOT NULL
);
```
`server_profiles.sandbox_profile_id` 改为外键语义(应用层校验,SQLite FK 默认不启用)。
新 API:`Ledger::upsert_sandbox_profile / get_sandbox_profile / list_sandbox_profiles /
bind_server_sandbox_profile`。

### D7 — Activity Feed 数据源
后端保留全量查询,`ListRecentEvents` 可选 `event_type_filter`。默认过滤集(前端/CLI 默认)见 I08a 实现注释。

### D8 — Replay 数据模型
```rust
pub struct SessionReplay {
    pub session_id: String,
    pub event_count: usize,
    pub events: Vec<EventDetail>,
    pub chain_verified: Option<bool>,  // None=未验;Some(true/false)=verify_chain 结果
}
```

### D9 — CLI 验收通路
`vigil-desktop` 改为 clap-based CLI。子命令一对一映射 UiCommand:
```
vigil-desktop activity --session <sid> --limit 50
vigil-desktop approvals list
vigil-desktop approvals resolve <approval_id> --approve --scope Once --user <u>
vigil-desktop session replay <sid> [--verify]
vigil-desktop servers list
vigil-desktop servers show <server_id>
vigil-desktop servers approve-tool <sid> <tool_name>
vigil-desktop servers approve-drift <sid> <tool_name> --to <new_hash>
vigil-desktop sandbox upsert --id <id> --read <path> --write <path> --wall-ms 30000 --memory-mb 512
vigil-desktop sandbox bind --server <sid> --profile <pid>
```

## 4. 安全不变量

- **I-8.1**:UI 协议层**不直接持 SQLite handle**;协议 dispatcher(CLI / Tauri)持 `Arc<Ledger>`,
  前端永不看到 raw SQL
- **I-8.2**:`UiError` 所有变种**不得**包含真实 secret / 原始后端错误字符串(keyring / SQLite 底层原文)
- **I-8.3**:argv 展示前必经 `detect_hard_secret` gate,命中 → `SecretInArgv` 拒展示并审计
- **I-8.4**:写命令(Resolve / Approve* / Reject* / Upsert)必须 capability=`ui.write`;
  协议层静态检查,dispatcher 运行时二次校验
- **I-8.5**:`SandboxProfile.profile_json` 必须用 `serde_jcs` 规范化后再 hash;profile_hash
  与 I04/I05 的 command_hash / descriptor_hash 算法口径一致
- **I-8.6**:Session replay 返 `SessionReplay` 前,所有 payload 必须已经是 vigil-audit 写入时的
  脱敏形态(由 ADR 0002 §D1 的 `append_event` hard-secret gate 保证 —— 本 ADR 不重复检)

## 5. 测试与验收

### §12.3 I08 四条(CLI 闭环)

| # | 验收 | CLI 用例 | 测试 |
|---|------|---------|------|
| 1 | approval can be resolved | `vigil-desktop approvals resolve <id> --approve` | `cli_resolves_approval_updates_ledger` |
| 2 | session replay loads | `vigil-desktop session replay <sid>` | `cli_replay_prints_events_and_verifies_chain` |
| 3 | server command visible | `vigil-desktop servers show <sid>` → stdout 含 argv | `cli_server_show_prints_exact_argv` |
| 4 | secret never visible | SENTINEL 注入 `secret_refs` + tool_secret_bindings + env lease + audit,全路径 CLI 输出**无** | `cli_redline_sentinel_never_in_any_output` |

### D5 红线

- `server_register_rejects_secret_in_argv`(binding lint)
- `ui_error_secret_in_argv_does_not_leak_value`

### D6 持久化

- `sandbox_profile_upsert_idempotent`
- `bind_server_sandbox_profile_roundtrip`
- `sandbox_profile_hash_is_jcs_canonical`

### D8 replay

- `replay_session_returns_verified_chain_report`
- `replay_nonexistent_session_returns_empty`

## 6. 跨版本契约

- `UiCommand` / `UiResponse` / `UiError` 作为 I08-I10 稳定 API
- `Ledger::upsert_sandbox_profile / get_sandbox_profile / list_sandbox_profiles /
  bind_server_sandbox_profile` 签名稳定
- `SandboxProfile.profile_hash` 算法:sha256(serde_jcs(profile_json))

## 7. 延后项

| 延后项 | 目标 |
|--------|------|
| Tauri 2 shell + capabilities 双分组 | I08b |
| 4 页前端 UI(React/Svelte/…) | I08c |
| SandboxProfile 图形编辑(文件夹选择 / host allowlist) | I08c |
| Hash chain 可视化 | I08c |
| Node + tauri-cli toolchain 准备 | I08b 启动前置 |

## Revised 2026-04-22 (I08b α 全段 + β1/β3/β5 追加决策)

本 ADR 原文定稿于 I08a 阶段（2026-04-20）。I08b 四页 Desktop UI 落地 + β 技术债清理期间，以下决策在实装中固化 / 细化 / 修正，**在此追加**（不改动原文 §1-§7，保护审计链）。

### R1. I08b 四页 α 序列 — MVP 四页全部实装

**α 系列全部通过 Codex ACCEPT**（交付详情见 `docs/iterations/I08b.md`）：

| α | 页面 | Codex 轨迹 |
|---|------|-----------|
| α1 | Tauri 2 + Vue 3 + Naive UI + Tailwind 脚手架 | R1 REJECT → R2 CONDITIONAL → R3 ACCEPT |
| α2 | Approval Queue（3 新 handler + Drawer + scope modal + 双层 confirm） | R1 REJECT → R2 ACCEPT |
| α3 | Activity Feed（3 handler + NTimeline + FTS5 + EventDetailModal） | R1 REJECT → R2 REJECT → R3 ACCEPT |
| α4 | Server Registry（10 handler + 3 Tab + argv 逐元素 + drift diff） | R1 ACCEPT（一轮通过） |
| α5 | Session Replay（2 handler + NTimeline 事件流 + ledger-wide chain badge） | R1 REJECT → R2 ACCEPT |

**实装相对原 ADR 的差异**：
1. **原 §3 UI 栈 "React/Svelte/…" 开放选择** → 实装锁定 **Vue 3 + Naive UI + Tailwind**（i08b brainstorm ACCEPT）
2. **原 §5 ApprovalQueue 展示 `effects_json`** → 实装改为 `effect_vector: EffectVector`（真实字段；α2 R1 修正协议漂移）
3. **Server 级 approve/reject 有意不在 protocol/UI 暴露**：原 ADR §4.2 `UiCommand` 列表仅有 `ApproveServerCommandDrift` / `RejectServerCommandDrift`（command drift 级，已实装），**并无** server 整体的 `ApproveServer` / `RejectServer` variant。底层 `vigil-audit::registry::approve_server` 能力存在（`registry.rs:217`），但 I08b 有意**不通过 UiCommand 暴露** server 级批准 —— tool 级 + command drift 已满足 MVP
4. **α3 EVENT_TYPE_OPTIONS 白名单**：Codex R2 REJECT 后确认"UI 事件名白名单必须 grep 真实 `append_event` 字面量"；`runner.*` 从原设想中移除（vigil-runner 只在注释声明，无实际写入）
5. **α5 `ListSessionsReq.limit`**：原 α1 TS `limit?: number` 是协议漂移（Rust `limit: u32` 必填），**α5 期间**（而非 β3）顺手修正，与新增 Session Replay 一批交付

### R2. β 技术债清理（R2026-04-22 后完成）

三件套让 I08b Desktop UI **生产可用**：

#### β1. Tauri AppManifest 真 command 白名单（兑付原 ADR §I-8 hard-gate 承诺）

原 ADR §I-8.3 声明 "write 命令必须 capability=ui.write 静态检查"，α1 时因工具链准备暂用软白名单（`generate_handler!` 宏展开）。β1 通过 `tauri_build::Attributes::app_manifest(AppManifest::commands(INVOKE_COMMANDS))` 引入构建期 hard gate：

- **SSOT** `apps/desktop/src/commands.rs::INVOKE_COMMANDS`（19 条）
- **三处同步**：SSOT + `generate_handler!` + `capabilities/default.json`
- **守门**：4 单测（count / unique / well_formed + capability JSON 精确集合双向 diff）；`generate_handler!` 宏展开无 Rust 反射，仍靠人工 + code review
- Codex R1 REJECT → R2 ACCEPT

#### β3. EffectKind TS enum 强类型化（兑付原 α2 R2 NICE）

原 ADR §4.3 / §5 `EffectVector.effects` 作为字符串数组传 UI。β3：

- TS `EffectKind` 字面量 union（11 variants 严格对 Rust `#[serde(rename_all = "PascalCase")] #[non_exhaustive]`）
- `EffectVector.effects: string[]` → `EffectKind[]`
- Helper `effectKindTagMeta` 集中色彩/label 映射（读=info/写或执行=warning/凭据或对外=error）
- ApprovalDetailDrawer 从"JSON 堆"升级为 typed tags + destructive/reversible 徽章 + 分段列表（paths/hosts/secret_refs/recipients 仅非空）+ 原 JSON pretty-print 折叠作透明性附注
- Codex R1 REJECT → R2 ACCEPT（修正 "TS never 跨语言守门" 错误承诺，明确仅 TS-内部守门）

#### β5. Ledger 磁盘持久化（兑付 ADR 0002 §I-2.1 跨会话审计不变量）

α1 GUI 启动 `Ledger::open_in_memory()` 违反 ADR 0002 §I-2.1（审计不变量要求跨会话保存）。β5：

- 生产路径：`dirs::data_local_dir()/Vigil/ledger.sqlite3`（Windows `%LOCALAPPDATA%`，macOS `~/Library/Application Support`，Linux `$XDG_DATA_HOME`）
- 环境变量覆盖：`VIGIL_LEDGER_PATH`（开发/CI）
- **Fail-closed**：任一步失败 `exit(1)`，**不**回退 `open_in_memory`
- **DI pattern**：核心逻辑抽到 `apps/desktop/src/ledger_path.rs`（lib 模块，默认 feature 编译 + 8 单测覆盖）；binary 仅查询 `dirs::data_local_dir()` 注入。避免"生产路径藏在 feature-gated binary，默认 CI 不守门"
- Codex R1 REJECT（缺测试守门）→ R2 ACCEPT

### R3. 延后项状态更新（对原 §7 补充）

| 原 §7 延后项 | R1/R2 后状态 |
|---|---|
| Tauri 2 shell + capabilities 双分组 | **Done**（β1） |
| 4 页前端 UI | **Done**（α2-α5） |
| Hash chain 可视化 | **Done**（α3 EventDetail + α5 SessionReplay chain badge） |
| SandboxProfile 图形编辑 | **Deferred**（protocol + dispatcher 支持 `ListSandboxProfiles` / `UpsertSandboxProfile` / `BindServerSandboxProfile`,但桌面 UI 仅在 `ServerOnboardingCard.vue` 只读展示 `sandbox_profile_id` 字段；未提供 list / bind / edit 交互） |
| Node + tauri-cli toolchain | **Done（文件就绪版）**（α1 脚手架层；用户环境 `npm install + cargo tauri dev` 触发） |

### R4. 新增不变量（β 阶段固化）

- **SSOT 漂移守门必须精确集合双向 diff**（β1 教训）：count 断言是最弱降级防线
- **文档措辞不能超承诺实际守门范围**（β3 教训）：TS `never` 只守 TS-内部，不冒充跨语言同步检测
- **生产逻辑必须进默认测试矩阵**（β5 教训）：抽 lib + DI pattern 让 feature-gated binary 的关键入口被 `cargo test --workspace` 覆盖

### R5. 新增延后项（β 后，等环境 / 资源）

| 延后项 | 阻塞原因 | 目标 |
|---|---|---|
| β2 specta TS 类型自动生成 | Cargo.lock 无 specta，环境"禁 heavy install" | 环境允许时落地，根治手写 TS 镜像漂移 |
| β4 Playwright + tauri-driver E2E | 需 npm install Playwright + GUI runtime | 发行前在 CI 环境落地 |
| 正式图标资源 | 需设计物料 | 发行前 |
| 三平台打包 CI | 需 CI 环境（Win/Mac/Linux runner） | 发行前 |
| ESLint CSP 违反测试（`ui/tests/csp.spec.ts`） | 需 Vitest runtime | 发行前 |

### R6. 量化

| 项 | I08a 完成时 | I08b α5 完成 | β1 完成 | β5 完成 |
|---|---|---|---|---|
| workspace 测试数 | 213 | 396(α5 未新增测试,保持 β1 前基线) | **400**(+4 β1 守门单测) | **408**(+8 β5 ledger_path 单测) |
| Codex 审查轨迹累计 | R3 ACCEPT | 五 α 全 ACCEPT | +β1 R2 ACCEPT | +β3 R2 + β5 R2 ACCEPT |
| GUI 文件级交付累计 | — | 4 pages + 3 components + 2 pinia stores + 协议修正 | + commands.rs SSOT | + ledger_path.rs lib 模块 |
