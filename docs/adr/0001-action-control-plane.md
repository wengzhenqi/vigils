# ADR 0001 — Vigil 是"行动控制平面"而非 Prompt 过滤器

- 状态:Accepted
- 日期:2026-04-20
- 适用迭代:I00 及以后全部

## 背景

行业里对"AI 安全"的主流叙事有两条:

1. **Prompt filter / 内容审核**——在语言层做黑白名单、PII 检测、越狱检测。
2. **云侧企业安全平台**——把 agent 调用接入 SIEM/DLP,由云端策略引擎统一裁决。

路线 1 的盲点在于 agent 的危险不在"说错话",而在"做错事":一句"清理临时文件"
可以被翻译成 `rm -rf ~/Downloads/*` 或 `DELETE FROM users;`。路线 2 的盲点在于
**凭据、文件系统、本地 MCP server 都是本地资源**,每次真实危险动作之前把决策托付
给云端会丢失上下文并引入新的信任边界。

## 决策

Vigil 是**本地 Action Control Plane**:

```text
Agent → Normalize → Tool-call Firewall → Decision → Approval / Auto Policy
   → Credential Lease Broker → MCP Gateway / Sandbox Runner → Audit Ledger → Replay
```

核心断言:

- **控副作用,不控文本**。决策针对 `ToolInvocation → EffectVector`,不针对 prompt。
- **本地优先**。SQLite 账本、OS Keychain、Wasmtime/OS sandbox 都在用户机器上,
  不依赖云端连通性。
- **Tool 描述不可信**。`ToolDescriptor.description/annotations` 仅作参考,
  效应由 `EffectExtractor` 在 args 上独立推断。
- **凭据租约化**。任何 secret 使用走 `SecretLease`,绑定 session/server/tool,
  不进入 prompt / log / UI / trace / SQLite payload。
- **审批是一等公民**。`Approve` 是与 `Allow`/`Deny` 并列的决策,不是例外路径。

## 取舍

| 被放弃的路径 | 原因 |
| ------------ | ---- |
| 上来做语义 guard model | 延迟高、可解释性差、被 prompt 注入即破防;先做确定性解析 + 规则引擎 |
| 默认使用 OPA/Rego | 增加部署/调试负担;先做 Rust 内置 policy DSL,团队版再加 Rego export/import |
| 云端统一策略下发 | 引入新信任边界并要求联网;留给企业版 |
| MCP `roots` 作为访问控制 | `roots` 只是 informational guidance(MCP 官方),Vigil 自实现 ACL/sandbox/file policy |

## 影响

- 所有 crate 的依赖顶点是 `vigil-types`,即 10 个核心对象共享语言。
- 任何运行时路径必须在执行前产生 `DecisionRecord`(AGENTS.md §1)。
- 新模块必须声明"落在哪一层"(Firewall / Gateway / Lease / Runner / Audit / UI / Extension)。

## 对 I07 Sandbox 设计的预留

`ServerProfile.sandbox_profile_id: Option<String>` 是 I00 对 I07 的**最小预留**。
I07 `ExecutionPlan` 必须至少承载以下五维约束,且默认取最小权限:

- `read_dirs` / `write_dirs`:只读 / 可写目录(缺省空集)
- `allowed_hosts`:出站白名单(缺省空集,等价无网)
- `env` inheritance:缺省 `env_clear`,仅注入被审批的 `SecretLease`
- 资源上限:`wall_ms` / `memory_mb` / `cpu_ms`(必须有上限)
- 运行器:`RunnerKind::{Wasm, Native}`,平台特化沙箱(Linux Landlock/seccomp,
  macOS App Sandbox,Windows AppContainer)

I00 不提前引入这些字段以免固化 API,但 I07 推进时须回来更新本 ADR 与 iteration doc。

## 引用

- 主方案 `Vigil项目方案.md` §0,§2,§12
- 补充研究 `Vigil项目安全方案_大全版本_.md`
- MCP 规范 2025-11-25:tool descriptor 默认不可信、roots 非 ACL、HTTP transport-level authorization
- Wasmtime 安全文档:WASI 默认无权限、import-based capability 模型
- Chrome Extensions Native Messaging:host 独立进程 + stdin/stdout 通信
