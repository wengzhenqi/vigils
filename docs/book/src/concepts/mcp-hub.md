# MCP Hub

`vigil-mcp` — a Model Context Protocol hub that sits in front of your tool servers.

- **Server registry** — stdio servers and HTTP servers (OAuth / JWT; see ADR 0011).
- **Descriptor pinning** — a SHA-256 of each server's tool list + schemas, used for drift
  detection. A changed descriptor is treated as first-seen (approval-required), never
  auto-trusted.
- **Outbox** — an append-only outbox table for reliable delivery.
- **Approval-queue integration** — the embedded Hub shares cross-process SQLite persistence
  with the Approval Queue (see ADR 0014).

See ADR 0004, 0005, 0011, and 0014.
