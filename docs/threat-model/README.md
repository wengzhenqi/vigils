# Threat Model(骨架)

I00 占位。完整威胁建模在 I02 起随 firewall/policy 一起演化。

## 首要威胁(按优先级)

1. **Tool poisoning**:工具描述称"safe read",实际参数指向 `~/.ssh/id_rsa`。
2. **Descriptor drift**:已审批 schema 从只读变成可写。
3. **Token exfiltration**:工具输出诱导模型回显环境变量。
4. **Confused deputy**:agent 拿 GitHub token 去调用无关 server。
5. **Browser paste leak**:用户把 `.env` 粘进 ChatGPT。
6. **Local MCP command injection**:恶意 server 启动命令被拼接进 shell。
7. **Audit tamper**:事后修改 SQLite 覆盖痕迹。

## 对应缓解

| 威胁 | 缓解 | 实装迭代 |
| ---- | ---- | -------- |
| Tool poisoning | EffectExtractor 独立从 args 推断 | I02 |
| Descriptor drift | descriptor_hash pinning + drift 触发再审批 | I05 |
| Token exfiltration | 真实 secret 不进入模型可见上下文;走 lease + 注入 | I06 |
| Confused deputy | lease 绑定 (session, server, tool) | I06 |
| Browser paste leak | 扩展 paste/submit hook → native host → redaction | I09 |
| MCP command injection | 启动前展示 exact argv;env_clear;sandbox profile | I04 / I07 |
| Audit tamper | hash chain + 只读字段 | I01 |
