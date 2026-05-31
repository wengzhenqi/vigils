# ADR 0014 — Tauri GUI 同进程 embed Hub(根治 cross-proc approval gap)

- 状态:**Stub / v0.5 Planned**(2026-04-28 起占位,ISS-019 Phase 1+2 已用短轮询 fallback 兜底,完整 embed 推到 v0.5)
- 日期:2026-04-28(草拟,落地待 v0.5)
- 依赖:ADR 0008(Desktop UI)/ ADR 0002(redaction)/ ADR 0006(SecretLease)
- 相关迭代:I08a / I08b / v0.3 Stage 3 / v0.4 ISS-019(Phase 1+2 短轮询 fallback)

---

## 1. Context(why this ADR exists)

v0.3 Stage 3 把 ApprovalBroker 从 in-process condvar 路径推向跨进程场景时
暴露了一个根因技术债:**ApprovalBroker 跨进程没有 condvar 唤醒通道**。

历史路径:
- **v0.3.1**:`--dev-permissive-firewall` 把 `approval_wait` 从 300s 砍到 3s 是 timing 权宜
- **v0.4 ISS-019 Phase 1**(commit `1601caf`):`wait_for_resolution` 内置 500ms
  短轮询 DB fallback;cross-proc 唤醒 ~ 1.3s vs 300s 默认 timeout;in-proc
  Condvar 路径不退化(< 450ms)
- **v0.4 ISS-019 Phase 2**(commit `33de821`):移除 dev_permissive_firewall 上的
  timing override,生产 300s 默认恢复,加 guard test 防退化

**Phase 1+2 已覆盖 99% 用户感知场景**(approve 后 ≤ 500ms 唤醒)。但 fallback 不是
根治 —— 跨进程仍走轮询而非事件驱动,语义上不优雅,且每个 wait 都附带 ≥ 0ms
≤ 500ms 的固定上限延迟。

本 ADR 定义 **完整根治路径:Tauri GUI 进程 embed Hub**,把 approval 路径压回
in-process 直通,让 Condvar 通知重新生效,fallback 退回为兜底而非主路径。

## 2. Decision Drivers

1. **正确性**:approve 后 Hub 内同 tick 放行(< 100ms),vs 现 fallback ≤ 500ms
2. **架构清晰度**:消除"为什么生产 wait 300s 但 dev 测试看到 < 1s"的理解负担
3. **兼容性**:必须保留现有 `vigil-hub serve --stdio` CLI 路径(Claude Code/Codex/Cursor/Zed
   通过此入口接 Vigil)。Tauri embed 仅在 GUI bin 分支生效,CLI 走 fallback
4. **不破坏 v0.3 接口**:zero-trust default-deny / ApprovalBroker / PolicyEngine /
   Ledger 接口稳定贯穿
5. **测试可守门**:必须能在 CI 不带 GUI 的情况下跑 embed 路径单测(用 mock Tauri command 通道)

## 3. Decision

**Tauri GUI bin (`vigil-desktop-gui`) 持有 `Arc<Hub>`**;approval 走 Tauri command
通道在 GUI 进程内 publish 到 ApprovalBroker;CLI bin (`vigil-desktop`) 继续跨进程
DB fallback 路径(由 ISS-019 Phase 1 支撑)。

### 3.1 关键架构变更(草拟,v0.5 落地时再定稿)

```text
旧(v0.4):
  Tauri GUI → IPC → vigil-hub serve(独立进程,持 Hub)→ DB ← (轮询)wait_for_resolution

新(v0.5,本 ADR):
  Tauri GUI = embed Hub(同进程持 Arc<Hub>)
    → Tauri command (#[command] resolve_approval)
    → Hub::approval_broker.publish() (直接 in-process)
    → Condvar wakeup (< 100ms)

  CLI bin 继续:
  vigil-desktop CLI → IPC → vigil-hub serve → DB ← (500ms 短轮询 fallback)
```

### 3.2 双 bin 分支

- `vigil-desktop`(CLI bin,现状)— 不改;继续 IPC + DB fallback 路径
- `vigil-desktop-gui`(新 bin / 或现有 GUI bin 加 embed feature flag)— 持
  `Arc<Hub>`;Tauri command 直接调用 Hub 方法(approval / firewall / ledger query)

### 3.3 Tauri command 白名单 SSOT 约束

延续 I08b-β1 的三联 SSOT(commands.rs `INVOKE_COMMANDS` + gui.rs
`generate_handler!` + capabilities/default.json `allow-*`)。新增 embed 路径的
approval/firewall command 必须三处同步,守门测延续 β1 模式。

### 3.4 fail-closed 不变量

embed 路径不得削弱 zero-trust:
- Hub 初始化失败 → GUI 拒绝启动(不 fail-open 跳过 firewall)
- approval broker 内部 panic → process abort(GUI 整体退出比放过未审批 tool 更安全)

## 4. Consequences

### 4.1 Positive

- Approval 唤醒 < 100ms(vs 短轮询 ≤ 500ms),用户感知"按钮点完即放行"
- 消除 dev_permissive_firewall 的存在理由(已在 ISS-019 Phase 2 移除,本 ADR 进一步去掉技术债思想包袱)
- 架构表达力提升:GUI 路径"approval = command"语义自然
- DB 不再是 approval 唤醒主通道(只是审计落盘),减少 SQLite 写竞争

### 4.2 Negative

- 双 bin 维护成本:GUI / CLI 两条路径需各自集成测
- Tauri command 数量上升(预估 +3:`resolve_approval` / `query_pending_approvals` /
  `subscribe_approval_events`),每个走完 SSOT 三联

### 4.3 Mitigation

- v0.5 落地时拆 Phase 1(GUI bin embed Hub 骨架,无 UI 接入)/ Phase 2(approval 路径接通)/
  Phase 3(firewall + ledger query 接通)三阶段 PR,每个 Phase 独立可审
- CI 矩阵:embed bin 路径默认入 `cargo test --workspace` 用 mock Tauri context;
  真 GUI E2E 走 `e2e-embed-approval.mjs`(类比现 `e2e-stage3.mjs`)
- ISS-019 Phase 1 短轮询 fallback **保留**,作为 embed 路径回退保险(若 Tauri
  channel 因任何原因卡住,DB 兜底依然能让 wait 在 ≤ 500ms 拿到结果)

## 5. Alternatives Considered

### 5.1 Tauri sidecar 进程(rejected)

让 Tauri 通过 `tauri-plugin-shell` 拉起 vigil-hub serve 子进程,通过 IPC 通信。
- 优点:进程隔离,GUI 崩溃不影响 Hub
- 缺点:**仍然跨进程**,approval condvar 无法通知,Phase 1 短轮询 fallback 依然必要;
  没有解决根因,只是把 IPC 路径从用户手动管理变成 sidecar 自动管理

### 5.2 共享内存 + futex / Windows event(rejected)

跨进程 Condvar 等价物。
- 优点:技术上最贴近 in-process Condvar 语义
- 缺点:三平台(Windows / macOS / Linux)实现差异大,引入新依赖;复杂度高于
  embed Hub 方案;且 Vigil 已经有 SQLite ledger 作为跨进程持久通道,再引入
  futex/event 是双轨

### 5.3 维持 ISS-019 Phase 1 短轮询(deferred)

不做 embed,长期靠 ≤ 500ms fallback。
- 优点:0 进一步工作
- 缺点:留下"为什么 wait 路径要 sleep"的思想包袱;每次 approval 多 250ms 平均
  延迟感;架构不优雅
- **结论**:作为 v0.5 之前的兜底是 OK 的(ISS-019 Phase 1+2 已落地);v0.5 推完整
  embed 是为了关掉这个长期债

## 6. v0.5 落地任务拆分(占位,正式 v0.5 roadmap 时细化)

| 子任务 | 估时 | 依赖 |
|---|---|---|
| ISS-019b-α1 GUI bin 持 `Arc<Hub>` 骨架(无 UI 接入)| 0.5-1 天 | - |
| ISS-019b-α2 Tauri `#[command] resolve_approval` + SSOT 三联 | 0.5 天 | α1 |
| ISS-019b-α3 ApprovalBroker.publish() 接 Tauri channel | 0.5 天 | α2 |
| ISS-019b-α4 e2e-embed-approval.mjs(< 100ms 唤醒断言)| 0.5 天 | α3 |
| ISS-019b-β1 firewall query / ledger query embed(选做)| 0.5-1 天 | α4 |
| ISS-019b-β2 ADR 0014 Revised + 文档同步 | 0.5 天 | β1 or α4 |

**总估时**:~ 2.5-4 天(纯架构重构,不涉及新算法)

## 7. References

- ADR 0008 — Desktop UI 协议层
- ISS-019 Phase 1 commit `1601caf` — 短轮询 fallback
- ISS-019 Phase 2 commit `33de821` — 拆 dev_permissive_firewall timing override
- I08b-β1 — Tauri AppManifest 真 command 白名单 SSOT 三联
- v0.3 Stage 3 done — `--dev-permissive-firewall` 历史背景

---

**注**:本 ADR 是 v0.5 计划占位,**当前(v0.4)状态下不应据此提交代码改动**。
ISS-019 Phase 1+2 短轮询 fallback 已经覆盖 99% 用户感知场景,完整 embed 是优化
而非 blocker。v0.5 启动时本 ADR 进入正式 Draft 评审。

---

## Revised — α1 implemented (2026-04-29)

v0.5 P1 ADR 0014 α1(GUI bin embed Hub 骨架)已落地。**严格骨架范围**:GUI bin
持 `Arc<Hub>`,通过 `app.manage()` 注册到 Tauri State;**不**新增 `#[tauri::command]`
handler,**不**改 ApprovalBroker 路径。下面 5 点固化 α1 的实装事实,供 α2/α3 接续。

1. **实装位置:`apps/desktop/src/embed.rs`(`vigil_desktop::embed`,gui-feature-gated lib 模块)**

   显式 **NOT** 走 path-dep `vigil-hub-cli` 复用 `build_hub`。理由:
   `apps/vigil-hub-cli/src/serve.rs:170 build_hub` 内部第 1 步 `Ledger::open(p)?`
   会与 `apps/desktop/src/bin/gui.rs:602 Ledger::open(&ledger_path)` 的 single-open
   冲突(SQLite WAL 模式下两次 open 同一文件路径在 Tauri lifecycle 内会触发
   WAL frame 竞争或 lock 路径重入)。GUI bin 的契约是"main 已 open ledger,把
   `Arc::clone(&ledger)` 喂给 embed 模块",`gui_build_hub` 7 步组装中
   **绝无** `Ledger::open(` 字面量(grep 守门 + embed.rs 模块级禁止清单)。

2. **INVOKE_COMMANDS=21 不变(`apps/desktop/src/commands.rs`)**

   α1 不加 `#[tauri::command]` handler,SSOT 三联(commands.rs `INVOKE_COMMANDS`
   + gui.rs `generate_handler!` + `capabilities/default.json`)21 条不变。守门:
   `apps/desktop/tests/embed_hub_skeleton.rs::invoke_commands_count_unchanged_in_alpha1`
   断言 21,任何 α1 内的 commit 加 handler 必触发本测试失败。α2 加
   `resolve_approval` embed 路径时再 +1,同步 SSOT 三联。

3. **ISS-019 Phase 1 短轮询 fallback 完整保留作为 α1 的 primary approval-wait**

   `crates/vigil-audit/src/approvals.rs:550 wait_for_resolution`(`WAIT_POLL_INTERVAL`
   = 500ms 轮询)依然是 GUI 与 CLI 双 bin 的 approval 唤醒主路径;α1 只准备好
   `Arc<Hub>` State 注入,**没**接通 `Hub.approval_broker.publish()` 到 Tauri
   command。α2 在 `resolve_approval` handler 内部既 publish() 又写 Ledger 后,
   short-poll fallback 退回为兜底(若 Tauri channel 因任何原因卡住,500ms DB
   兜底依然能拿到结果)。手工守门:`git diff crates/vigil-audit/src/approvals.rs`
   在 α1 commit 范围内必须为空。

4. **α2 `resolve_approval` 命名冲突 deferred**

   > **Superseded by Round 1 finding 2026-04-29 — see Revised α2 section below**.
   > 落地选 C3(Hub.resolve_approval thin-wrapper):既不 rename 也不新加 handler,
   > handler 名 `resolve_approval` 不变,SSOT 三件套 21 条不变。详情见末尾 Revised α2 段。

   `apps/desktop/src/commands.rs:33` 的 `"resolve_approval"` 已在 SSOT,对应
   `apps/desktop/src/bin/gui.rs:227` 的 `#[tauri::command] async fn resolve_approval`
   handler(语义:Ledger-write `UiCommand::ResolveApproval` 走 dispatch,
   `Capability::Write`)。α2 接 embed 路径需要决定:

   - **Option A — rename 现有**:把现有 handler 改名为 `record_approval_decision`
     之类,让 `resolve_approval` 留给 embed 路径(同时调
     `Hub.approval_broker.publish()` + Ledger write)。代价:前端 invoke 三处同步。
   - **Option B — semantic-merge**:α2 内部既调 `Hub.approval_broker.publish()`
     又走原 dispatch 写 Ledger,handler 名不变。代价:两路 atomic 语义需精心处理
     (publish 后 ledger 写失败该如何 rollback?)。

   α2 启动时 ADR 0014 Revised 再追一段记录最终选择 + 测试守门。

5. **dual `app.manage()` 模式确认**

   Tauri State 按 type 索引:`AppState`(含 `Arc<Ledger>` + `read_capability`)
   与 `Arc<Hub>` 各自 `.manage()`(`apps/desktop/src/bin/gui.rs:634` 与 `:642`),
   不冲突。α2 写 `resolve_approval` embed 路径时可同时 inject:

   ```rust
   #[tauri::command]
   async fn resolve_approval(
       req: ResolveApprovalReq,
       state: State<'_, AppState>,
       hub: State<'_, Arc<Hub>>,
   ) -> Result<ApprovalResolutionDto, String> { ... }
   ```

   守门:`apps/desktop/tests/embed_hub_skeleton.rs::arc_hub_is_send_sync_static`
   编译期断言 `Arc<Hub>: Send + Sync + 'static`(`Manager::manage` 隐式约束)。

### Revised 索引

- 实装文件:`apps/desktop/src/embed.rs`(新)/ `apps/desktop/src/lib.rs`(模块声明)
  / `apps/desktop/src/bin/gui.rs:615-630`(Hub 组装 + dual `app.manage()`)
  / `apps/desktop/Cargo.toml`(3 optional path deps gui-gated)
- 守门测试:`apps/desktop/tests/embed_hub_skeleton.rs`(4 tests)
- α1 严格范围(避免 scope creep):未触碰 `crates/vigil-audit/src/approvals.rs`、
  `apps/desktop/src/commands.rs`、`apps/desktop/capabilities/default.json`

---

## Revised — α2 implemented (2026-04-29)

v0.5 P1 ADR 0014 α2(GUI bin Tauri command embed-path approval handler 接通)已落地。
**最终选 C3(thin-wrapper)** 而非 α1 Revised §4 sketch 的 Option A(rename)/ Option B
(new `embed_resolve_approval` handler);理由见 §α2-2 Decision。下面 4 段固化 α2 实装事实。

### α2-1. Finding — α2 functional goal 已在 α1 通过 Arc<Ledger> 共享隐式达成

**Fact 1**:`Ledger::approve / deny / cancel` 已在 `crates/vigil-audit/src/approvals.rs`
**第 700-704 行** atomic publish-after-write —— audit `record_approval_resolved`
(approvals.rs:701)后立即 `self.approval_broker.publish(approval_id, resolution.clone())`
(approvals.rs:702-703)。这是 Ledger 持有的 ApprovalBroker(`pub(crate) struct ApprovalBroker`,
approvals.rs:75)的入口;Hub **没有自己的** approval_broker 字段
(`rg 'approval_broker' crates/vigil-mcp/src/hub.rs` 0 命中)。

**Fact 2**:α1(commit `9cc55c7`)`apps/desktop/src/embed.rs::gui_build_hub`
(embed.rs:81)7 步组装内 Hub 与 caller 共享同一份 `Arc<Ledger>`(单测
`gui_build_hub_shares_ledger_arc` 强制 `Arc::strong_count` post > pre)。
`apps/desktop/src/bin/gui.rs` `tauri::Builder` 链 `.manage(AppState { ledger:
Arc::clone(&ledger), ... })`(gui.rs:630)+ `.manage(hub)` 双 manage 让
`State<'_, AppState>` 与 `State<'_, Arc<Hub>>` 共享同一 Ledger;Hub 通过
`gui_build_hub(Arc::clone(&ledger))`(gui.rs:617)消费同一份 `Arc<Ledger>`。

**Synthesis**:既有 `#[tauri::command] resolve_approval` handler(gui.rs:234)走
`dispatch(UiCommand::ResolveApproval)` → `Ledger.approve/deny/cancel` →
`approval_broker.publish`(approvals.rs:702-703)→ 同进程 `wait_for_resolution`
(approvals.rs:541 起)的 Condvar `notify_all` 立即唤醒。**α1 commit 后,in-process
Condvar 唤醒已隐式生效**;α2 functional goal(approve 后 < 100ms 唤醒)在 α1 commit
时已先达。TASK-004 集成测试(`apps/desktop/tests/embed_hub_resolve_approval.rs:164
hub_resolve_approval_wakes_waiter_under_100ms`)实测 5 次样本 0.3-0.8ms,远低于
100ms 阈值(130-300× 余量),坐实此结论。

### α2-2. Decision — 选 C3(Hub.resolve_approval thin-wrapper)

**最终决策**:在 `crates/vigil-mcp/src/hub.rs:228 pub fn resolve_approval(&self,
req: ResolveApprovalReq) -> Result<ApprovalResolutionDto, HubError>`(同步 thin-wrapper,
内部按 `req.action` match 分流到 `self.ledger.approve/deny/cancel`);把
`apps/desktop/src/bin/gui.rs:234 #[tauri::command] async fn resolve_approval` handler
内部从 `dispatch(UiCommand::ResolveApproval, ...)` 改为 `hub.resolve_approval(req)
.map_err(...)`,移除 `state: State<'_, AppState>` 参数(写权限语义由 Hub 方法 doc
承诺承载;Hub 不暴露给 renderer,Tauri capability ACL `allow-resolve-approval`
仍是 hard-gate)。新签名携带 `hub: State<'_, Arc<Hub>>`(gui.rs:236),
`use vigil_mcp::Hub`(gui.rs:51)已就位。

**SSOT 三件套零修改**:
- `apps/desktop/src/commands.rs:33 INVOKE_COMMANDS["resolve_approval"]` —— 仍 21 条,
  `commands.rs:68` 守门 `invoke_commands_count_in_sync` 断言 21 不变
- `apps/desktop/src/bin/gui.rs tauri::generate_handler!` 列表 —— 仍 21 条,只是
  `resolve_approval` handler 内部委托对象变了
- `apps/desktop/capabilities/default.json allow-*` 集合 —— 仍 21 条,`commands.rs:123`
  守门 `capability_json_allow_set_matches_invoke_commands` 精确双向 diff 通过

**vs Option A(rename)与 Option B(新 handler)**:
- Option A 触发 capability slugified key 变更(`allow-record-approval-decision` 新 +
  `allow-resolve-approval` 释义换),前端 invoke 调用面也要改;高 churn 高 risk
- Option B 双 handler 等价语义共存到 α3,违反 YAGNI(α1 已隐式达成功能,新 handler
  不新增 runtime 能力);SSOT 21→22 需四处同步
- C3 唯一同时满足 KISS + SSOT-zero-churn + frontend-invoke-zero-churn + ISS-019-fallback-zero-touch
  + α3-single-point-of-change 五维度

**实装文件**:
- `crates/vigil-mcp/src/hub.rs:228 pub fn resolve_approval`(同步,函数体 ≤ 25 行,
  无 `.await` / 无 `redact_free_text` / 无新 capability gate);新 `HubError::Invalid(String)`
  variant(thiserror `#[error("invalid request: {0}")]`,1 处使用 — approve 缺 scope,
  hub.rs:235 `HubError::Invalid(...)`,doc 见 hub.rs:227)
- `apps/desktop/src/bin/gui.rs:234 #[tauri::command] async fn resolve_approval`
  签名改为 `(req: ResolveApprovalReq, hub: State<'_, Arc<Hub>>) -> Result<ApprovalResolutionDto,
  String>`(gui.rs:236),函数体单行 `hub.resolve_approval(req).map_err(|e| e.to_string())`
- `crates/vigil-mcp/tests/resolve_approval.rs`(新)—— 4 单测(approve/deny/cancel/
  approve_without_scope_returns_invalid)
- `apps/desktop/tests/embed_hub_resolve_approval.rs`(新)—— 4 集成测试,含
  `hub_resolve_approval_wakes_waiter_under_100ms`(embed_hub_resolve_approval.rs:164)
  真 Condvar 唤醒守门

**未触碰文件**(grep 守门已验):
- `crates/vigil-audit/src/approvals.rs` —— ISS-019 wait_for_resolution 0 修改,
  `WAIT_POLL_INTERVAL = 500ms`(approvals.rs:71)仍是 cross-proc fallback
- `apps/desktop/src/commands.rs` —— SSOT 不变
- `apps/desktop/capabilities/default.json` —— SSOT 不变
- `apps/desktop/src/dispatcher.rs` —— UiCommand::ResolveApproval 分流仍存在(本进程
  内 GUI handler 不再走它,但其它 caller / 旧 binary path 仍可走)

### α2-3. α3 接通点 — Hub.resolve_approval 是 single point of change

**α3 优化目标**(原 ADR §6 子任务 ISS-019b-α3 / α4):若未来发现 Condvar 唤醒延迟在
某些场景下退化(如多 waiter 排队 / Tauri runtime 调度抖动),**单一改动点是
`Hub::resolve_approval`(hub.rs:228)的方法体内部** —— 加缓存 / 加更细粒度 wakeup
channel / optional async 化都从这里下手。**不需要**改 SSOT 三件套,**不需要**改
Tauri command 签名,**不需要**改前端 invoke 调用面。

**α4 e2e**:留 `e2e-embed-approval.mjs`(类比现 `e2e-stage3.mjs`)— 跨进程 GUI 启动 +
真 firewall 拦截 + UI approve 真按钮事件 + 端到端 < 100ms 唤醒断言。**不在 α2 范围**
(本 ADR 的 §6 子任务 ISS-019b-α4)。

**β1**:firewall query / ledger query embed(只读 approval 详情、tool call 详情等),
留 `## Revised — β1 implemented` 段记录。**不在 α2 范围**。

### α2-4. 禁止清单(grep 守门可验)

后续 PR 触碰以下任一即触发 review 红线:

1. **Hub.resolve_approval 不可成第二审批状态机** — 函数体只能是 match `req.action` →
   delegate `self.ledger.approve/deny/cancel` → 投影 DTO。**禁止**:写自己的状态判定 /
   写自己的 redaction / 写自己的 expires_at 检查 / 引入新 capability 字段。
   Guard:`rg -A 30 'pub fn resolve_approval' crates/vigil-mcp/src/hub.rs` 函数体行数 ≤ 25。
2. **不可 capability 双重 gate** — Hub 方法**不**做 `Capability::Write` 校验(Tauri
   capability ACL `allow-resolve-approval` 已是 hard-gate;dispatcher 内部那条
   `Capability::Write` 是 dispatch 路径的;Hub 路径不需要重复)。**禁止**:`if cap !=
   Capability::Write { return Err(...) }` 之类。
3. **不可触碰 wait_for_resolution / WAIT_POLL_INTERVAL** — ISS-019 Phase 1+2 的 500ms
   短轮询 fallback 是 cross-proc 兜底,**保留**;`crates/vigil-audit/src/approvals.rs:71
   WAIT_POLL_INTERVAL = Duration::from_millis(500)` 在 α2 commit 范围内 `git diff`
   必须为空。Guard:`rg 'wait_for_resolution|WAIT_POLL_INTERVAL'
   crates/vigil-audit/src/approvals.rs` 行数与 α1 commit 一致。
4. **不可改 ledger.approve / deny / cancel 内部 publish 行为** — atomic publish-after-write
   (approvals.rs:700-704)是 in-process 唤醒的根因;改了等于把 α1+α2 共同建立的
   in-proc 路径打断。`crates/vigil-audit/src/approvals.rs` 在 α2 commit 范围内
   `git diff` 必须为空。
5. **SSOT 三件套不可漂移** — `INVOKE_COMMANDS` 仍 21 条;`generate_handler!` 列表仍 21 条;
   `capabilities/default.json allow-*` 集合仍 21 条。守门:
   `commands.rs:68 invoke_commands_count_in_sync`(=21)+
   `commands.rs:123 capability_json_allow_set_matches_invoke_commands`(精确双向 diff)+
   `embed_hub_skeleton.rs:72 invoke_commands_count_unchanged_in_alpha2`(α2 改名版,=21)。

### Revised α2 索引

- 实装:
  - `crates/vigil-mcp/src/hub.rs:228`(`pub fn resolve_approval` + `HubError::Invalid`)
  - `apps/desktop/src/bin/gui.rs:51 use vigil_mcp::Hub` + `:234 async fn resolve_approval`
    + `:236 hub: State<'_, Arc<Hub>>`(handler signature swap + 单行 hub.resolve_approval 委托)
- 守门测试:
  - `crates/vigil-mcp/tests/resolve_approval.rs`(新,4 单测)
  - `apps/desktop/tests/embed_hub_resolve_approval.rs:164`(新,4 集成,含 < 100ms wakeup 守门
    `hub_resolve_approval_wakes_waiter_under_100ms`)
  - `apps/desktop/tests/embed_hub_skeleton.rs:72`(rename `..._alpha1` →
    `invoke_commands_count_unchanged_in_alpha2`,assertion 21 不变)
- 实测唤醒延迟样本(2026-04-29 单 session 5 次连续 cargo test --features gui --test
  embed_hub_resolve_approval -- --test-threads=1):**0.3-0.8 ms**,远低于 100ms 阈值
- 未触碰(grep 验证):`crates/vigil-audit/src/approvals.rs` / `apps/desktop/src/commands.rs`
  / `apps/desktop/capabilities/default.json` / `apps/desktop/src/dispatcher.rs`
- α2 严格范围(避免 scope creep):**未**实装 e2e-embed-approval.mjs(留 α4)/ firewall
  query embed(留 β1)/ Condvar 替代 wakeup 优化(留 α3,Hub.resolve_approval 函数体内部)

## Revised — α4 implemented (2026-04-29)

v0.5 P1 ADR 0014 α4(e2e-embed-approval 进程级守门)已落地。**严格范围**:不开真 Tauri WebView,
只在 α2 已落地的 `Hub.resolve_approval` thin-wrapper + `apps/desktop/tests/embed_hub_resolve_approval.rs:164
hub_resolve_approval_wakes_waiter_under_100ms` 之上,新增进程级 cargo runner + 多样本统计 + 跨平台 CI matrix。

### α4-1. e2e 定义收敛

α4 e2e 严格定义为:**进程级可重跑 cargo runner + 多样本统计 + 三平台 CI matrix**。
**不**包括真 WebView 按钮点击 / 真 UI approve 渲染层 e2e。理由:Tauri 2.0 WebView 自动化(tauri-driver +
msedgedriver / webkit2gtk-webdriver)三平台 1h 内不可达,且与 α4 核心收益(< 100ms wakeup 守门)正交。
真 UI 自动化 deferred v0.6,本 ADR 段为 α4 边界文档化的单一 source of truth。

### α4-2. Deferred v0.6

下列工作 **不在 α4 范围**,留 v0.6 issue 创建时再补占位:

- `tauri-driver` 三平台联调(Windows `msedgedriver` 配置 / Linux `webkit2gtk-webdriver` 装包 / macOS WebKit 暂不稳定)
- 真 WebView 按钮点击 e2e(`WebView2` Win / `WebKitGTK` Linux / `WebKit` macOS)
- 真 UI approve 端到端剧本(渲染层 invoke → `Hub.resolve_approval` → 状态刷新)
- Playwright / Selenium / tauri-driver 选型评估
- CI runner self-hosted vs hosted 选型(macOS GHA 10x 额度评估,见 `.github/workflows/ci.yml` line 14 注释)

### α4-3. 双锚点引用

α4 e2e 真实落地的两个文件:

1. `scripts/test-local/e2e-embed-approval/run.mjs` — Node 进程级 runner;
   spawn `cargo test --features gui --test embed_hub_resolve_approval -- --nocapture --test-threads=1 --exact
   hub_resolve_approval_wakes_waiter_under_100ms`,正则 `\bWAKEUP_LATENCY_NS=(\d+)(?=\D|$)` 抽样 N=10 次
   (libtest 会把 `println!` 与 `test ... ok` 同行 flush,因此用单词边界而非行首锚定),
   自实现 percentile,`max < 100_000_000ns` 硬门禁(`process.exit(1)` 反之);0 新 npm 依赖。
2. `apps/desktop/tests/embed_hub_resolve_approval.rs:164 hub_resolve_approval_wakes_waiter_under_100ms` —
   α2 已落地的 Rust 集成测试;α4 仅在 line 201 之后追加一行 `println!("WAKEUP_LATENCY_NS={}",
   wakeup_latency.as_nanos())` 提供机器可读 stdout 样本(既有 `eprintln!` 人类可读双轨保留)。

### α4-4. 实测样本

α4 在本地运行 `node scripts/test-local/e2e-embed-approval/run.mjs` 采样数据(填写 commit 时实测;
若三平台均通过 < 100ms,即视为 ADR 0014 α 系列收尾):

- 平台:(Windows / Linux / macOS 单独 commit 时填实测)
- N:10 / iteration
- max:< 100_000_000ns(目标),实测见 commit 描述
- p50 / p95 / avg:见 stdout summary

### α4-5. CI matrix

`.github/workflows/ci.yml` 追加 job `embed-hub-e2e`,**沿用既有 matrix 风格**`[ubuntu-latest, windows-latest]`(line 14 注释明确不在 GHA 跑 macOS,与 v0.6 self-hosted 评估配套);env:`VIGIL_E2E_EMBED_APPROVAL_N=10`;
失败硬门禁 `process.exit(1)` 阻塞 PR。

### Revised α4 索引

- 实装:`scripts/test-local/e2e-embed-approval/run.mjs`(新) /
  `scripts/test-local/e2e-embed-approval/README.md`(新) /
  `apps/desktop/tests/embed_hub_resolve_approval.rs:201`(+1 line `println!`) /
  `.github/workflows/ci.yml`(+1 job `embed-hub-e2e`)
- 守门:`grep -E '\bWAKEUP_LATENCY_NS=[0-9]+\b'` stdout 命中 ≥ N;`max < 100_000_000ns` 硬门禁;
  既有 213+ tests 0 回归;`cargo clippy --workspace -- -D warnings` 0 warn
- 严格范围(避免 scope creep):未触碰 α2 `Hub::resolve_approval` 函数体 / `crates/vigil-audit/src/approvals.rs`
  `WAIT_POLL_INTERVAL=500ms` / `apps/desktop/src/commands.rs` SSOT / `apps/desktop/capabilities/default.json`
- 真 WebView UI 自动化:**deferred v0.6**(本 ADR α4-2 段已声明)
