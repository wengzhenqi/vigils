# Introduction

**Vigil** is a local-first AI Agent control plane:

- **Action firewall** (`Firewall::evaluate`) — fail-closed effect gating
- **Audit ledger** (SHA256 hash chain) — tamper-evident decision history
- **Privacy filter** (13 hard fingerprint rules + ONNX-backed PII detection)
- **MCP hub** (Model Context Protocol server registry + descriptor pinning)
- **Approval queue** (human-in-the-loop for risky effects)
- **Sandbox runner** (Wasm + Native, Linux Landlock LSM)

Vigil sits between AI agents and effectful tools/APIs, gating each action through policy + privacy + audit + approval.

## Project Status(2026-05)

| Dimension | State |
|---|---|
| Iterations | I00 → I10b done(11 iterations,Codex collaborative review ACCEPT) |
| Public Releases | v0.11(installer)/ v0.12(sandbox security)/ v0.13(SDK publish chain) |
| Workspace tests | 735+ passing / 0 failing |
| `cargo audit` | 1 vuln(rsa 0.9.10 dev-only,no fixed upgrade) |
| ADRs | 0001-0018(`vigil-runner-types` split,2026-05-15) |
| Codex reviews | All sandbox / SDK / publish changes go through collaborative ACCEPT |

## Distribution

- **3 desktop installers**:Linux deb/rpm/AppImage + macOS dmg + Windows nsis/msi(`v0.11.1` Ed25519-signed,auto-update ready)
- **Rust SDK**:`vigil-sdk` (v0.13 publish-ready,`cargo add vigil-sdk`)
- **Browser extension**:Chrome MV3 (`v0.4`)
- **CLI agent**:`vigil-hub-cli` (stdio MCP agent — Claude Code / Codex / Cursor / Zed integration)

## License

Apache-2.0 © Vigil Project Contributors

## Quick links

- [Quickstart — Embedding the SDK](./getting-started/sdk-quickstart.md)
- [Architecture Overview](./concepts/architecture.md)
- [Release Notes (v0.13.0-rc.1)](./releases/v0.13.0-rc.1.md)
