# MCP Hub

`vigil-mcp` — Model Context Protocol hub。

- **Server Registry**:stdio servers / HTTP servers(OAuth/JWT,ADR 0011)
- **Descriptor Pinning**(I05):SHA256 of tool list + schema → drift detection
- **Outbox**(I04):append-only outbox table
- **Approval Queue 集成**(ADR 0014 embed Hub):跨进程 SQLite persistence

详见 ADR 0004 / 0005 / 0011 / 0014。
