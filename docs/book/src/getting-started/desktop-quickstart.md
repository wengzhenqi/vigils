# Desktop Quickstart

## First launch

The window opens on the **Activity Feed** (empty on first run). There are four tabs:
Activity Feed, Approval Queue, Server Registry, and Session Replay.

## Connect an AI agent

### Claude Code (MCP stdio)

```json
{ "mcpServers": { "vigil": { "command": "vigil-hub", "args": ["serve", "--stdio"] } } }
```

### Cursor / Zed / Codex

The same `vigil-hub serve --stdio` MCP stdio entry point.

### Browser extension

Chrome MV3 extension → native host → desktop app (stdio MCP).

## Tabs at a glance

| Tab | What it shows |
|---|---|
| Activity Feed | Recent events, SQLite FTS5 search, hash-chain verification |
| Approval Queue | Risky effects awaiting a decision — Approve / Reject / Delegate / Defer |
| Server Registry | Active / Pending / Removed servers, descriptor drift |
| Session Replay | The full decision timeline for a chosen `session_id` |

See [Architecture](../concepts/architecture.md).
