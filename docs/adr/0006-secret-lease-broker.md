# ADR 0006 — Secret Lease Broker(I06)

- 状态:**Proposed**
- 日期:2026-04-20
- 依赖:ADR 0001 / 0002 / 0003 / 0004 / 0005

## 1. 背景与范围

主方案 §5 要求 Agent **永远拿不到真实 secret**,只能通过 `secret://` alias 请求使用;真实 secret 存 OS Keychain / Credential Manager / Secret Service,SQLite 只存 metadata。

I06 交付:
- `SecretStore` trait(真实值读写边界)+ `InMemorySecretStore` 实现
- feature-gated `KeyringSecretStore`(默认关)
- `secret_refs` SQLite 表(alias + fingerprint + metadata,**无值**)
- `tool_secret_bindings` SQLite 表(server + tool + secret_ref + injection_method + env_var_name)
- `LeaseBroker`:`mint_lease` / `resolve_value` / `revoke_lease` / `sweep_expired`
- Runtime secret cache:`Mutex<HashMap<lease_id, CachedSecret>>` + lazy 淘汰 + `zeroize`
- bound_* 三元组校验(session + server + tool,不匹配返 `LeaseContextMismatch` + 审计)
- ChildEnv 注入(与 I04 `StdioUpstream.env_clear()` 对接)
- `get_onboarding_data().requested_env_keys` 从 `tool_secret_bindings` 聚合(I05 遗留项)
- 红线 redaction tests

不在本迭代:
- HttpHeader / Pipe / TempFile 注入(保留枚举 + `UnsupportedInjectionMethod` 拒绝路径)
- 真实 Keychain 跨平台 CI
- lease 跨进程共享(I08)

## 2. 关键决策(Codex 协作)

### D1 — Keychain adapter 边界
窄 trait `SecretStore` + `InMemorySecretStore`(默认)+ feature `os-keychain` 启用 `keyring` 适配(默认关)。trait 只管 put/get/delete/backend_kind,不含 lease 语义。

### D2 — Runtime cache + 零化
`Mutex<HashMap<LeaseId, CachedSecret>>` + lazy eviction + `SecretValue(Zeroizing<String>)`。drop/shutdown 强制 drain。`expose()` 是唯一真值暴露点。

### D3 — bound 三元组校验职责
Broker 内校验(mint + resolve 双点);resolve 传 `ResolveContext { session_id, server_id, tool_name }`;不匹配写 `secret.lease_misuse_attempt` 审计。错误:`ContextMismatch / Expired / Revoked / NotFound / StoreError`。

### D4 — I06 注入范围
仅 ChildEnv 端到端;其他方式保留枚举 + fail-closed `UnsupportedInjectionMethod`。

### D5 — `secret_refs.fingerprint` 语义
`SHA-256("vigil.secret_ref.fp.v1" || normalized_secret_ref)` — **不**对真实 value 做 hash。

### D6 — `requested_env_keys` 填充
新表 `tool_secret_bindings`;`get_onboarding_data` 聚合 DISTINCT env_var_name(ChildEnv 绑定,去重排序)。三态:无绑定=Some([]),未分析=None,已分析=Some(envs)。

### D7 — Firewall/Hub/Broker 集成
Firewall 决策 → Hub spawn 前 **just-in-time** mint → 调用结束立即 revoke;mint 失败=执行错误不改决策。

## 3. 数据模型

### 3.1 `secret_refs`(新增)

```sql
CREATE TABLE secret_refs (
    secret_ref    TEXT PRIMARY KEY,
    display_name  TEXT NOT NULL,
    provider      TEXT NOT NULL,
    fingerprint   TEXT NOT NULL,
    created_at    INTEGER NOT NULL,
    last_used_at  INTEGER
);
```

### 3.2 `tool_secret_bindings`(新增)

```sql
CREATE TABLE tool_secret_bindings (
    server_id         TEXT NOT NULL,
    tool_name         TEXT NOT NULL,
    secret_ref        TEXT NOT NULL REFERENCES secret_refs(secret_ref),
    injection_method  TEXT NOT NULL,
    env_var_name      TEXT,
    created_at        INTEGER NOT NULL,
    PRIMARY KEY (server_id, tool_name, secret_ref, injection_method)
);
CREATE INDEX idx_bindings_server ON tool_secret_bindings(server_id);
```

### 3.3 `SecretValue` 新类型

```rust
pub struct SecretValue(Zeroizing<String>);
impl SecretValue {
    pub fn new(s: impl Into<String>) -> Self { Self(Zeroizing::new(s.into())) }
    pub fn expose(&self) -> &str { &self.0 }
}
```

不派生 Debug / Display,避免 println! 泄漏。

## 4. 运行时流程

Hub handle_tool_call(Firewall Approved 后):
1. `resolve_injection_plan(server, tool, effects.secret_refs)` → bindings
2. 对每个 ChildEnv binding:`broker.mint_lease(MintRequest{..})` → lease
3. `broker.resolve_value(lease_id, &ctx)` → env value
4. `StdioUpstream.env_clear().envs(env).spawn()`
5. `upstream.call_tool(..)`
6. **finally** `broker.revoke_lease(lease_id)`

## 5. 安全不变量

- **I-6.1**:`secret_refs` / `audit_events` 不含真实 value(运行期测试守门)
- **I-6.2**:`SecretValue::expose` 是唯一真实值暴露点
- **I-6.3**:过期 lease 在 `resolve_value` 返 `Expired`(lazy)
- **I-6.4**:bound 三元组不匹配 → `ContextMismatch` + 审计
- **I-6.5**:ChildEnv 注入时 Hub 必须 `env_clear()` + 只注 lease 绑定 env
- **I-6.6**:`LeaseBroker::Drop` / `shutdown()` 后 cache 为空

## 6. 测试与验收

### 红线 7 条

| # | 验收 | 测试 |
|---|------|------|
| 1 | DB 无真实 secret | `raw_secret_never_in_sqlite` |
| 2 | 日志无真实 secret | `raw_secret_never_in_audit_payload` |
| 3 | UI DTO 无真实 secret | `onboarding_data_contains_only_env_keys_not_values` |
| 4 | tool args 无真实 secret | `tool_call_args_scrubbed` |
| 5 | 过期失败 | `resolve_after_expiry_returns_expired_error` |
| 6 | bound 不匹配失败 | `resolve_with_wrong_{session/server/tool}_returns_context_mismatch` |
| 7 | child env 只含批准 | `child_env_contains_only_approved_keys` |

### 失败路径

- `keychain_not_found_returns_store_error`
- `unsupported_injection_method_fails_closed`
- `revoked_lease_resolve_fails`
- `sweep_expired_removes_old_and_zeroizes`

### I05 遗留

- `requested_env_keys_populated_from_bindings`(`Some([])` / `Some(["GITHUB_TOKEN"])` 两态)

## 7. 跨版本契约

- `SecretStore` trait 稳定边界
- `LeaseBroker::mint_lease(MintRequest) -> SecretLease` 签名稳定
- `SecretValue::expose()` 是 I06-I10 唯一真实值访问点
- 新审计事件前缀:`secret.lease_minted` / `secret.lease_revoked` / `secret.lease_misuse_attempt` / `secret.lease_mint_failed`

## 8. 延后项

| 延后项 | 目标迭代 | 原因 |
|--------|---------|------|
| HttpHeader 注入 | I08 | 无远程 HTTP transport |
| Pipe / TempFile 注入 | I07+ | 需要 sandbox 清理保证 |
| 跨进程 lease 共享 | I08 | Tauri UI + Hub CLI 同机时评估 |
| 真实 OS keychain CI | 后续 | 跨平台 CI 基础设施 |
| Lease 跨 session 迁移 | 未定 | 当前设计故意禁止 |
