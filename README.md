<div align="center">

# Vigils

**A local control plane for AI agents — see what they do, approve what matters, keep secrets out.**

**面向 AI Agent 的本地控制平面 —— 看见行为、审批高危、隔离凭据。**

[vigils.ai](https://vigils.ai) · Apache-2.0 · Rust + Tauri 2 + Chrome MV3

</div>

---

## English

Vigils sits between your AI agents (Claude Code, Cursor, Zed, MCP clients, browser
assistants) and the tools/data they touch. It is **local-first** — your prompts, secrets,
and audit trail never leave your machine.

### Why

Modern AI agents call tools, read files, hit APIs, and paste into web UIs. That power is
useful and risky. Vigils gives you four guarantees:

- **See what the agent did** — every tool call is recorded in a tamper-evident SHA-256
  hash-chained ledger with full-text search.
- **Approve risky actions first** — destructive or sensitive calls pause for human review
  in an Approval Queue, with per-agent policy.
- **Keep credentials out of prompts / logs / UI** — a redaction engine strips secrets and
  PII (hard-fingerprint rules + an optional ML ensemble) before text reaches a model,
  a log, or the screen.
- **Roll back bad actions** — the ledger is traceable end-to-end and the sandbox runner is
  fail-closed by default.

### Architecture

| Layer | What it does |
|---|---|
| **Audit ledger** | SQLite, SHA-256 hash chain, FTS5 search, per-event integrity |
| **Firewall / Policy** | default-deny tool gating, per-agent rules, OAuth scope allow-lists |
| **Approval broker** | human-in-the-loop for high-risk effects, scoped grants |
| **Redaction engine** | secret/PII detection — hard fingerprints + ML ensemble, fail-closed merge |
| **Secret lease broker** | short-lived credential leases, never persisted in clear |
| **Sandbox runner** | Wasm (Wasmtime) + native, Linux Landlock LSM file isolation |
| **MCP gateway** | stdio + HTTP transports, descriptor pinning + drift detection |
| **Desktop app** | Tauri 2 + Vue 3 — Approval Queue, Activity Feed, Server Registry, Session Replay, Privacy Findings |
| **Browser extension** | Chrome MV3 — redacts before paste/submit on AI sites |

### Build from source

Requirements: a recent stable Rust toolchain (see `rust-toolchain.toml`) and Node.js for
the desktop UI.

```bash
# Workspace tests (no GPU / model deps by default)
cargo test --workspace

# Lints
cargo clippy --workspace --all-targets -- -D warnings
cargo fmt --all -- --check

# Desktop UI
cd apps/desktop/ui && npm install && npm run build

# Desktop app (GUI feature embeds the built UI)
cargo build --release -p vigil-desktop --features gui --bin gui
```

> Crate names use the `vigil-*` prefix for historical reasons; the product and project are
> **Vigils**.

### Project layout

```
crates/        # 15 library crates (audit, firewall, policy, redaction, mcp, runner, sdk, …)
apps/          # desktop (Tauri), native-host (browser bridge), vigil-hub-cli
extensions/    # Chrome MV3 extension
docs/          # ADRs, user guide (mdBook), threat model, SDK API
```

### Documentation

- User guide (mdBook): `docs/book/`
- Architecture decisions: `docs/adr/`
- Threat model: `docs/threat-model/`
- SDK API surface: `docs/sdk-shallow-api.md`

### License

[Apache-2.0](./LICENSE).

---

## 中文

Vigils 位于你的 AI Agent(Claude Code、Cursor、Zed、MCP 客户端、浏览器助手)与它们所触及的
工具/数据之间。**本地优先** —— 你的 prompt、凭据与审计记录永不离开本机。

### 为什么

现代 AI Agent 会调用工具、读写文件、访问 API、向网页 UI 粘贴内容 —— 强大而有风险。
Vigils 提供四项保证:

- **看见 Agent 做了什么** —— 每次工具调用都写入防篡改的 SHA-256 哈希链账本,支持全文检索。
- **高危动作先审批** —— 破坏性/敏感调用在 Approval Queue 暂停,交由人工审核,支持按 Agent 策略。
- **凭据不进入 prompt / 日志 / UI** —— 脱敏引擎在文本抵达模型、日志或屏幕之前剥离密钥与 PII
  (硬指纹规则 + 可选 ML 集成模型)。
- **错误动作可回滚** —— 账本端到端可追溯,沙箱 runner 默认 fail-closed。

### 架构

| 层 | 职责 |
|---|---|
| **审计账本** | SQLite,SHA-256 哈希链,FTS5 检索,逐事件完整性 |
| **防火墙 / 策略** | 默认拒绝的工具门禁、按 Agent 规则、OAuth scope 白名单 |
| **审批中枢** | 高风险副作用的人在回路、范围化授权 |
| **脱敏引擎** | 密钥/PII 检测 —— 硬指纹 + ML 集成,fail-closed 合并 |
| **凭据租约** | 短时凭据租约,明文永不落盘 |
| **沙箱 runner** | Wasm(Wasmtime)+ native,Linux Landlock LSM 文件隔离 |
| **MCP 网关** | stdio + HTTP 传输,descriptor pinning + 漂移检测 |
| **桌面应用** | Tauri 2 + Vue 3 —— 审批队列、活动流、服务器注册、会话回放、隐私发现 |
| **浏览器扩展** | Chrome MV3 —— 在 AI 站点粘贴/提交前脱敏 |

### 从源码构建

环境:近期 stable Rust 工具链(见 `rust-toolchain.toml`)+ Node.js(桌面 UI)。

```bash
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings
cd apps/desktop/ui && npm install && npm run build
cargo build --release -p vigil-desktop --features gui --bin gui
```

> crate 名沿用历史 `vigil-*` 前缀;产品与项目名为 **Vigils**。

### 许可证

[Apache-2.0](./LICENSE)。
