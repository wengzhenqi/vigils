# Vigil 用户指南

本地运行的 **AI Agent 控制平面**。一句话描述:帮你守住 LLM Agent(ChatGPT / Claude / Gemini / Cursor / Claude Code 等)**不把 secret 粘出去、不越权调工具、审计留痕、沙箱隔离**。

## 文档导航

1. **[Installation](installation.md)** — 装三平台 binary + Chrome 扩展
2. **[Getting Started](getting-started.md)** — 5 分钟跑通 3 个核心场景
3. **[Agent Integration](agent-integration.md)** — ★ Claude Code / Codex / OpenCode / Cursor / Zed 接入 vigil-hub
4. **[Troubleshooting](troubleshooting.md)** — 常见问题

## 产品能力速览

| 能力 | 场景 |
|---|---|
| **Secret 拦截** | 在 ChatGPT 粘贴 `ghp_...` → 扩展显示 "blocked" + 内容不进对话框 |
| **审批闭环** | Agent 调未批工具 → Desktop Approval Queue 待批 → 点 approve 后放行 |
| **审计链** | 每次 tool call / 用户粘贴都写 SQLite ledger(SHA256 hash chain,防篡改) |
| **Sandbox** | Agent 工具进程受限于只读/读写白名单目录(Linux Landlock / Windows job 限权) |
| **HTTP MCP Auth** | 连 SaaS MCP server(GitHub / Anthropic 等)自动 OAuth + token 刷新 + scope 校验 |
| **本地优先** | 所有 secret / token / ledger 都在本机,零云端上报 |

## 本发行版(v0.2)交付

**三平台 Tauri GUI + CLI**(全部 portable binary,见 `dist/v0.2/`):

| 平台 | Desktop GUI | CLI |
|---|---|---|
| Windows x86_64 | `vigil-desktop-gui.exe` 12.1 MiB(**GUI**)| `vigil-desktop.exe`(CLI)+ `vigil-hub.exe` + `vigil-native-host.exe` |
| Linux x86_64(Ubuntu 22.04+)| `vigil-desktop-gui` ELF(**GUI**)| `vigil-desktop`(CLI)+ `vigil-hub` + `vigil-native-host` |
| macOS arm64(Apple Silicon)| `vigil-desktop-gui` Mach-O(**GUI**)| `vigil-desktop`(CLI)+ `vigil-hub` + `vigil-native-host` |

**Chrome MV3 扩展**:`vigil-chrome-mv3-v0.1.zip`(平台无关)

**本版未包含**(v0.3 或之后):
- MSI / DMG / AppImage / deb 打包(portable 二进制可直接用,但发行需 `.ico`/`.icns` 图标)
- 代码签名(Authenticode / notarization)
- macOS x86_64(Intel)二进制(arm64 可通过 Rosetta,原生需自行编译)

## 对谁有用

- **个人 AI 开发者**:用 Claude Code / Cursor 等 agent 工具时希望"粘贴时敏感内容不外泄 + 工具调用有审计"
- **企业合规 / 安全团队**:需要本地 MCP hub + 审计链,满足"AI agent 行为可追溯"合规要求
- **Red-team / 内审**:用 `docs/test-cases/scenarios/` 的场景验证 agent 不绕过策略

## 不做什么

- 不做云端同步 / 团队审计聚合(**by design,本地优先**)
- 不替代 EDR / DLP(Vigil 是 agent 控制平面,不是终端防护)
- 不劫持 HTTPS(不装根证书,不动浏览器安全模型 — 扩展只在用户主动粘贴/提交时介入)

---

继续读 **[installation.md](installation.md)** 开始装。
