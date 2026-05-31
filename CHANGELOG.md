# Changelog

All notable changes to Vigils are documented here. Versions follow
[Semantic Versioning](https://semver.org/) (0.x allows interface evolution).

本项目变更记录。版本遵循 [SemVer](https://semver.org/)(0.x 阶段允许接口演进)。

---

## [Unreleased]

First public release of Vigils — a local control plane for AI agents.
Vigils 首个公开版本 —— 面向 AI Agent 的本地控制平面。

### Core capabilities / 核心能力

- **Audit ledger** — SQLite, SHA-256 hash chain, FTS5 full-text search, per-event integrity.
  审计账本 —— 哈希链 + 全文检索 + 逐事件完整性。
- **Firewall & approval** — default-deny tool gating, per-agent policy, human-in-the-loop
  Approval Queue with scoped grants. 默认拒绝门禁 + 按 Agent 策略 + 人在回路审批。
- **Redaction engine** — secret/PII detection via hard-fingerprint rules and an optional ML
  ensemble, with a fail-closed merge layer. 脱敏引擎 —— 硬指纹 + ML 集成,fail-closed 合并。
- **Secret lease broker** — short-lived credential leases; plaintext never persisted.
  凭据租约 —— 短时租约,明文不落盘。
- **Sandbox runner** — Wasm (Wasmtime) and native execution, Linux Landlock LSM file
  isolation, fail-closed by default. 沙箱 runner —— Wasm + native + Landlock 隔离。
- **MCP gateway** — stdio and HTTP transports, descriptor pinning with drift detection,
  OAuth scope allow-lists. MCP 网关 —— 双传输 + descriptor pinning + scope 白名单。
- **Desktop app** (Tauri 2 + Vue 3) — Approval Queue, Activity Feed, Server Registry,
  Session Replay, Privacy Findings; keyboard shortcuts, theme toggle, real-time updates,
  bilingual (zh / en) UI. 桌面应用 —— 5 大面板 + 快捷键 + 主题 + 实时更新 + 中英双语。
- **Browser extension** (Chrome MV3) — redacts secrets/PII before paste or submit on AI
  sites. 浏览器扩展 —— AI 站点粘贴/提交前脱敏。

### License / 许可证

Apache-2.0.
