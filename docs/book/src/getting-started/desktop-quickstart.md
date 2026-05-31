# Desktop Quickstart

## First launch

启动后窗口默认进 **Activity Feed**(首次为空)。4 个 tabs:
- Activity Feed / Approval Queue / Server Registry / Session Replay

## Connect AI Agent

### Claude Code(MCP stdio)

```json
{ "mcpServers": { "vigil": { "command": "vigil-hub", "args": ["serve", "--stdio"] } } }
```

### Cursor / Zed / Codex
同样 `vigil-hub serve --stdio` MCP stdio entry。

### Browser Extension

Chrome MV3 ext → Native Host → desktop app(stdio MCP)。

## Tab 概览

| Tab | 功能 |
|---|---|
| Activity Feed | 最近 100 events,SQLite FTS5 搜索,hash chain verify |
| Approval Queue | risky effects 待批准,Approve/Reject/Delegate/Defer |
| Server Registry | 3 tabs:Active/Pending/Removed,descriptor drift |
| Session Replay | 选 session_id 看完整决策时间线 |

详见 [Architecture](../concepts/architecture.md)。
