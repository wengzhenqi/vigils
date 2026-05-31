# ADR 0018 — vigil-runner-types Crate Split(unblock SDK publish chain)

**Status**: Draft(2026-05-15)
**Context**: v0.12.1 完成后,v0.13+ 战略 Top 2 G(SDK publish to crates.io)被 vigil-mcp / vigil-ui-protocol → vigil-runner runtime 依赖阻塞(vigil-runner 拉 wasmtime + vigil-sandbox-linux 复杂依赖)。

## 1. Problem

### 1.1 当前 publish 阻塞链

```
vigil-sdk
  └─ vigil-mcp           ← depends on vigil-runner (runtime)
        └─ vigil-runner  ← wasmtime (15 RUSTSEC, optional feature)
              ├─ vigil-sandbox-linux (Linux-only, target-gated)
              ├─ vigil-redaction
              ├─ vigil-lease
              └─ vigil-audit
  └─ vigil-firewall      ← no vigil-runner dep ✓
  └─ vigil-redaction     ← no vigil-runner dep ✓

vigil-ui-protocol        ← depends on vigil-runner (types only)
  └─ vigil-runner        ← 同上
```

publish vigil-sdk 须 publish vigil-mcp + vigil-runner + vigil-sandbox-linux + 全套。runner 拉 wasmtime,publish 大且 audit 不干净(wasmtime patch line 频繁,1.92/1.95 toolchain 跟进)。

### 1.2 用法 evidence(实测 grep)

**vigil-mcp 用 vigil-runner**:
- `stdio.rs:102`:`vigil_runner::apply_native_env_policy(&mut cmd, env.iter()...)` — **纯函数**,env policy filter

**vigil-ui-protocol 用 vigil-runner**:
- `command.rs:324`:`pub profile: vigil_runner::SandboxProfile` — **types**
- `lib.rs:85`:`use vigil_runner::{RunnerKind, RunnerSpecific, SandboxProfile};` — **types**
- `response.rs:12`:`use vigil_runner::SandboxProfile;` — **types**

**结论**:两个 consumer 只用 vigil-runner 的 **types + 纯函数**,**完全不用 wasmtime / sandbox-linux concrete impl**。

## 2. Decision

### 2.1 拆分方案 — 新建 `vigil-runner-types` crate

**新 crate 含**(从 vigil-runner 抽出,**0 vigil deps**):

| 来源 | 内容 | 理由 |
|---|---|---|
| `plan.rs` 全部 | `ExecutionPlan` / `RunnerKind` / `RunnerSpecific` / `ExecutionResult` / `SandboxProfile` | 纯 types(注释中提及 wasmtime,无实际依赖) |
| `error.rs` | `RunnerError` / `RejectField` | 纯 types |
| `audit.rs` | `NullAuditSink` / `RunnerAuditSink` / `RunnerEvent` | 纯 trait + types |
| `native.rs` 部分 | `apply_native_env_policy` / `RESERVED_SYSTEM_ENV_KEYS` / `is_reserved_env_key` / `ScrubCallback`(type alias 不含 default impl)| 纯函数(env policy filter)+ const + 类型别名 |

**保留 vigil-runner 含**(Codex R1 fix:`default_scrub` + `leak_scan` 依赖 `vigil-redaction`,不能进 types crate):

- `wasm.rs`:`WasmRunner`(wasmtime + WASI preview1)
- `native.rs` 中:`spawn_native`(std::process + Landlock via vigil-sandbox-linux)+ `prescreen_native`
- `native.rs::default_scrub`(`vigil_redaction::scrub_text` dep,保留)
- `leak_scan.rs`(`vigil_redaction::scan_hard_findings` dep,保留)
- public re-export 一切给 backward compat

**理由**(Codex R1):vigil-mcp / vigil-ui-protocol **不**使用 `default_scrub` 或 `leak_scan`(grep verified),保留在 vigil-runner 不影响 unblock 目标,且避免 vigil-runner-types 引入 vigil-redaction dep 污染拓扑层级。

**新依赖图**:
```
vigil-sdk
  └─ vigil-mcp           ← vigil-runner-types ✓ (no wasmtime)
  └─ vigil-firewall      ✓
  └─ vigil-redaction     ✓

vigil-ui-protocol        ← vigil-runner-types ✓

vigil-runner             ← vigil-runner-types(internal),still has wasmtime/sandbox-linux
   (only for desktop binary, not in publish set)
```

### 2.2 Crate 结构

```
crates/
├── vigil-runner-types/   ← 新增,publishable(0 vigil deps)
│   ├── Cargo.toml        (license/repo/description/keywords/categories)
│   ├── README.md
│   └── src/
│       ├── lib.rs        (re-export plan/error/audit/env_policy + ScrubCallback type alias)
│       ├── plan.rs       (移自 vigil-runner/src/plan.rs)
│       ├── error.rs      (移自)
│       ├── audit.rs      (移自)
│       └── env_policy.rs (apply_native_env_policy + RESERVED_SYSTEM_ENV_KEYS + is_reserved_env_key + ScrubCallback type alias)
└── vigil-runner/         ← 保留,not publishable yet (wasmtime gated + vigil-redaction dep)
    ├── Cargo.toml        (add vigil-runner-types path dep)
    └── src/
        ├── lib.rs        (re-export vigil-runner-types pub items + add WasmRunner/spawn_native/default_scrub)
        ├── wasm.rs       (concrete impl, wasm feature gated)
        ├── native.rs     (concrete spawn_native impl + default_scrub vigil_redaction::scrub_text wrapper)
        └── leak_scan.rs  (vigil_redaction::scan_hard_findings wrapper,保留)
```

**Codex R1+R2 fix**:`scrub.rs` 不独立成文件(只剩 ScrubCallback type alias 进 env_policy.rs 或 plan.rs);`default_scrub` 和 `leak_scan.rs` 留 vigil-runner(因 vigil-redaction dep)。

### 2.3 Backward compat

vigil-runner 继续 re-export:
```rust
// vigil-runner/src/lib.rs
pub use vigil_runner_types::*;  // ExecutionPlan / RunnerKind / ... 不变路径
pub use wasm::WasmRunner;       // (wasm feature)
pub use native::spawn_native;
```

vigil-mcp / vigil-ui-protocol 改 Cargo.toml dep:
```toml
# old:
vigil-runner = { path = "../vigil-runner" }
# new:
vigil-runner-types = { path = "../vigil-runner-types" }
```

import 改:
```rust
// old:
use vigil_runner::SandboxProfile;
// new:
use vigil_runner_types::SandboxProfile;
```

或继续用 `vigil_runner::SandboxProfile`(vigil-runner re-export 还在,但 vigil-mcp/ui-protocol Cargo.toml 改了 dep — 编译错!)。**必须改 import 路径**。

## 3. Implementation Plan(v0.13 sprint scope)

### 3.1 任务拆分

| Task | Effort | 依赖 |
|---|---|---|
| T1 — 新建 `vigil-runner-types` crate(Cargo.toml + 元数据 + README + LICENSE alignment)| 0.5h | — |
| T2 — 移动 4 个 module(plan/error/audit/env_policy)+ ScrubCallback type alias(Codex R2 fix:default_scrub / leak_scan 留 vigil-runner)| 1-2h | T1 |
| T3 — vigil-runner 改 path dep + re-export | 0.5h | T2 |
| T4 — vigil-mcp Cargo.toml 改 dep + import path 改 | 0.5h | T3 |
| T5 — vigil-ui-protocol 同上 | 0.5h | T3 |
| T6 — workspace 测试 + clippy + fmt verify | 1h | T4+T5 |
| T7 — Codex review | 0.5h | T6 |
| T8 — vigil-runner-types dry-run publish + 加入 publish runbook | 0.5h | T7 |

**总计**:4-6h(半天工作量)

### 3.2 publish 顺序更新(v0.13+)

```
拓扑顺序(crates.io publish,Codex R1 fix:vigil-ui-protocol 先于 vigil-mcp):
1. vigil-types        (0 vigil deps)
2. vigil-redaction    (0 vigil deps)
3. vigil-runner-types ← NEW(0 vigil deps after split,no wasmtime/sandbox)
4. vigil-policy       (vigil-types)
5. vigil-audit        (vigil-types, vigil-redaction)
6. vigil-lease        (vigil-types, vigil-audit)
7. vigil-firewall     (vigil-types, vigil-policy, vigil-audit, vigil-redaction)
8. vigil-ui-protocol  (vigil-types, vigil-audit, vigil-runner-types) ← NEW dep
9. vigil-mcp          (vigil-types, vigil-audit, vigil-firewall, vigil-redaction, vigil-runner-types, vigil-ui-protocol) ← NEW dep
10. vigil-sdk         (vigil-types, vigil-firewall, vigil-redaction, vigil-mcp)
```

**Codex R1 fix**:vigil-mcp Cargo.toml line 28 真依赖 vigil-ui-protocol,publish 顺序要 ui-protocol 先。

**关键**:vigil-runner concrete 仍**不在 publish set**(wasmtime 漏洞跟进 + sandbox-linux Linux-only 复杂)。但 vigil-sdk 现可 publish。

## 4. Invariants

### 4.1 ADR 0007 sandbox 不变量(全保留,Codex R1 fix:9 不变量含 I07.5 加项)

`vigil-runner-types` 不含 sandbox impl,只含 types/policies。vigil-runner concrete 保留 **9 不变量**(I-7.1 ~ I-7.9):
- §I-7.1:`apply_native_env_policy` 迁入 vigil-runner-types(纯函数,易引用)
- §I-7.2 ~ §I-7.6:仍由 vigil-runner concrete 实施(WasmRunner + spawn_native)
- §I-7.7 ~ §I-7.9(I07.5 Linux Landlock 增项):仍由 vigil-runner concrete + vigil-sandbox-linux 实施(`restrict_self` + async-signal-safe `pre_exec` + `EPROTO` errno 通道),拆分不影响

### 4.2 ADR 0015 SDK boundary(不变)

SDK Phase 1 公开 surface 不变:
- vigil-types::* / vigil-firewall::{Firewall, FirewallConfig, ...} / vigil-redaction::{scan_text, ...}
- 仍**不**含 runner concrete(WasmRunner / spawn_native)

### 4.3 测试覆盖

`vigil-runner-types` 不引入新逻辑(纯 move),原 vigil-runner 测试矩阵:
- 默认 (no feature):tests for types/error/policy
- `--features wasm`:6 wasm_acceptance tests(在 vigil-runner)
- Linux Landlock tests(vigil-sandbox-linux + vigil-runner)

split 后:
- vigil-runner-types tests:types / env_policy 纯函数 tests
- vigil-runner tests:concrete impl(wasm + native + sandbox)

## 5. Alternatives Considered

| 选项 | 优点 | 缺点 | 选择 |
|---|---|---|---|
| **A. 新建 vigil-runner-types(本 ADR 推荐)** | 最小改动,types 公开,impl 保留;直接 unblock SDK publish | 新 crate 多一个维度;需 backward compat 处理 | ✅ |
| B. 把 types 移到 vigil-types | crates 数量不增 | vigil-types 当前是核心 SDK types,加入 runner-specific types 混杂边界;ADR 0008 SDK boundary 受污染 | ❌ |
| C. vigil-mcp/ui-protocol 内联复制 types | 0 dep | DRY 违反,types drift 风险 | ❌ |
| D. trait 抽象 + dyn impl | 解耦更彻底 | 大改动,types 仍要共用,trait 不是真问题(问题是 wasmtime 依赖)| ❌ over-engineering |
| E. 不拆,等 wasmtime 干净后整体 publish | 0 工作 | wasmtime patch line 永远滚动,never clean;long-term blocker | ❌ |

## 6. Risks

| 风险 | Mitigation |
|---|---|
| vigil-mcp/ui-protocol 改 import path 漏改 | grep `use vigil_runner::` 全 workspace + 测试矩阵 |
| Cargo.toml workspace path dep 风格不一致 | follow 现有 path = "../vigil-runner-types" pattern |
| 测试 fixture path 引用断裂 | tests/* 不移动,只移动 src/* |
| Backward compat 破:third-party 用 vigil-runner re-export 失效 | vigil-runner 内 `pub use vigil_runner_types::*` 保留,API 兼容 |

## 7. Verification(after T6)

- ✅ `cargo check --workspace --all-targets`
- ✅ `cargo test --workspace --features ort --all-targets`(预期 727+ tests)
- ✅ `cargo test -p vigil-runner --features wasm`(6/35 sandbox tests)
- ✅ `cargo clippy --workspace --features ort --all-targets -- -D warnings`
- ✅ `cargo audit`(预期 1 vuln 不变,rsa dev-only)
- ✅ `cargo publish --dry-run -p vigil-runner-types`
- ✅ vigil-mcp / vigil-ui-protocol dry-run publish(等 vigil-runner-types 真 publish 后)

## 8. Out of scope(v0.14+)

- vigil-runner concrete crate publish(等 wasmtime 干净 + Linux sandbox 拆 cross-platform abstraction)
- vigil-sandbox-linux publish(Linux-only,target-gated 复杂)
- WasmRunner trait abstraction(若需要 cross-runtime,留 future)

## 9. Next Steps(post-ADR)

1. Codex collaborative review of this draft(per `feedback_iteration_scope`)
2. 若 ACCEPT → 实施 T1-T8(半天)
3. 实施完成 → tag v0.13.0-rc.1 + 触发 SDK publish 准备(更新 `v0.11.2-crates-io-publish-runbook.md` 含 vigil-runner-types + 完整链)
