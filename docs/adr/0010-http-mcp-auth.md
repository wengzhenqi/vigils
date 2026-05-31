# ADR 0010 — HTTP MCP Auth(I10a:认证核心 + mock transport)

- 状态:**Proposed**
- 日期:2026-04-21
- 依赖:ADR 0001 / 0002 / 0003 / 0004 / 0006 / 0008

## 1. 背景

主方案 §4.8:远程 HTTP MCP 走 MCP Authorization spec —— PRM 发现 + OAuth 2.1 + PKCE +
audience/resource/scope 校验 + token 存 keychain + **禁止 token passthrough**。

**现状**:
- I04 Hub 只实装 stdio upstream(`Arc<StdioUpstream>`);`TransportKind::Http` 仅占位
- I06 Secret Lease 已有 `SecretStore` trait + `KeyringSecretStore` + `SecretValue(Zeroizing)`
- 无 HTTP client / 无 OAuth 代码

## 2. 分段交付

I10 拆三段,本轮只承诺 **I10a**:

| 段 | 交付 | 本轮验收? |
|----|------|---------|
| **I10a** | 新 crate `vigil-http-auth`:PRM types + validate / OAuth client(`oauth2` crate) / JWT gate / token persistence / passthrough-deny planner / **mock** HttpClient / 9 条单测 + §12.3 I10 三条映射 | **是** |
| I10b | 真 HTTP transport(`reqwest + rustls`)接入 Hub + loopback redirect + JSON-RPC over HTTP POST | 后续 |
| I10c | UI 添加远程 MCP 流 + refresh token 自动刷新 + opaque token introspection + policy `allowed_scopes` | 后续 |

## 3. 关键决策(Codex 协作)

### D1 — I10 三段式
§12.3 I10 三条验收在 **mock transport** 下可达成;不绑网络库不接 Hub,避免把 I10 做成跨 3 层的大坑。

### D2 — OAuth 实装
用 [`oauth2`](https://crates.io/crates/oauth2) crate 处理 PKCE + code exchange + token types;Vigil 自己包安全边界(PRM 校验 / aud 验证 / passthrough deny / token 安全存储)。**不**手写完整 flow(redirect / discovery 踩坑点多)。

### D3 — PRM(RFC 9728 Protected Resource Metadata)
完整 `ProtectedResourceMetadata` 类型 + 校验:
- `resource` 非空 + 可 parse 为 URL
- `authorization_servers` 非空 + 每项可 parse
- `bearer_methods_supported` 必须含 `"header"`(fail-closed)
- `scopes_supported` 覆盖 requested scopes(交集校验)

fetch 走 `HttpClient` trait;I10a 只接 mock。

### D4 — Token Store
- **真值** → `vigil_lease::SecretStore`(复用 I06 边界)
  - key 形态:`token://oauth/access/<sha256(resource)>/<sha256(client_id)>`
  - refresh token 同形态,`access` 换 `refresh`
- **metadata** → SQLite 新表 `oauth_token_metadata`(**不**含 value)
  - `token_ref TEXT PK`(= SecretStore 的 key)
  - `resource TEXT`
  - `authorization_server TEXT`
  - `scope_set TEXT`(JCS 规范化的 Vec<String>)
  - `token_kind TEXT`(`access` / `refresh`)
  - `expires_at INTEGER`(NULL = 不过期)
  - `created_at INTEGER`

### D5 — Token 格式
**I10a 只支持 JWT access token**:
- 本地 decode + 验 `aud` 包含 PRM.resource(或 `resource` claim 相等)
- 验 `scope` claim(空格分隔字符串)覆盖请求 scope
- **不验签**(AS 公钥发现 JWKS 延 I10b/c;I10a 接受 `unsecure` decode + claims 校验)
- opaque token → `UnsupportedTokenFormat`,fail-closed

本选择记录的**安全权衡**:I10a 本地 `aud` 校验只防 "客户端把别处 token 贴过来假冒" 的简单误用;真防伪造要 I10b 的 JWKS 签名校验 + AS introspection。ADR 明记此边界。

### D6 — Passthrough Deny 不变量
Request planner 对 **incoming** client request 的 header 做严格过滤:
- `Authorization` / `Proxy-Authorization` / `X-Forwarded-Authorization` / 任何 bearer-like header → **丢弃 + 审计**
- Gateway 构造 upstream 请求时,`Authorization: Bearer <gateway_token>` **只**来自 `ResolvedAccessToken`
- 无 token → 拒调 `MissingToken`,**不**用 client token 代替
- 审计 `http_auth.passthrough_blocked`(**不**记 header value;只记 header 名集合)

### D7 — Scope 不扩 PolicyEngine
scope 在 I10a 仅作 "auth 请求参数 + JWT claim 校验对象",**不**进 firewall DSL;I10c 再与 policy 联动。

### D8 — HTTP 客户端抽象
`trait HttpClient { fn get(&self, url) -> Response; fn post_form(&self, url, form) -> Response }`(最小面);I10a `MockHttpClient`(`HashMap<Url, Response>` 预录);I10b 接 `reqwest`。

### D9 — 测试
全 mock。三条主方案验收映射:
1. `wrong_resource_rejected_when_jwt_aud_mismatches_prm_resource`
2. `incoming_authorization_header_is_never_forwarded_to_upstream`
3. `scoped_token_authorizes_mock_tools_call_successfully`

## 4. 数据模型

```rust
/// RFC 9728 Protected Resource Metadata
pub struct ProtectedResourceMetadata {
    pub resource: Url,
    pub authorization_servers: Vec<Url>,
    pub bearer_methods_supported: Vec<String>,  // 必须含 "header"
    pub scopes_supported: Vec<String>,
    pub resource_documentation: Option<Url>,
}

/// 持久化的 token metadata(**不**含 value;value 在 SecretStore)
pub struct OAuthTokenMetadata {
    pub token_ref: String,        // SecretStore key
    pub resource: String,
    pub authorization_server: String,
    pub scope_set: Vec<String>,
    pub token_kind: TokenKind,    // Access / Refresh
    pub expires_at: Option<i64>,
    pub created_at: i64,
}

/// 运行时解析的 access token
pub struct ResolvedAccessToken {
    pub raw: SecretValue,         // 真值,零化
    pub resource: String,
    pub scope_set: Vec<String>,
    pub expires_at: Option<i64>,
}

/// request planner 输出 —— 保证无 passthrough
pub struct AuthorizedHttpRequest {
    pub url: Url,
    pub method: HttpMethod,       // POST / GET
    pub headers: Vec<(String, String)>,  // 已含 Authorization: Bearer ...
    pub body: Option<Vec<u8>>,
}

pub enum HttpAuthError {
    InvalidPrm(&'static str),
    MissingAuthorizationServer,
    BearerHeaderNotSupported,
    ScopeNotSupported(String),
    UnsupportedTokenFormat,         // opaque token
    JwtDecodeFailed,
    AudienceMismatch { expected: String, actual: String },
    ScopeMissing(String),
    TokenExpired,
    MissingToken,                    // 无 token 时拒调
    TokenStoreError(&'static str),   // 稳定 reason_code
    Internal(&'static str),
}
```

## 5. 安全不变量

- **I-10.1**:access/refresh token **value** 只能在 `SecretStore` 内,**不**进 SQLite / log / audit payload
- **I-10.2**:SQLite `oauth_token_metadata` 表只存 metadata,字段白名单固定
- **I-10.3**:incoming `Authorization` / `Proxy-Authorization` / `X-Forwarded-Authorization` 等 bearer-like header 必须被丢弃;审计只记 header **名** 不记 value
- **I-10.4**:无已批准 token 时调用远程 MCP → `MissingToken` fail-closed,**不**用 client 的 token
- **I-10.5**:I10a 仅支持 JWT access token;opaque 或非 JWT → `UnsupportedTokenFormat`
- **I-10.6**:JWT `aud` 必须等于 PRM `resource`(或 `resource` claim 等于);不等 → `AudienceMismatch`
- **I-10.7**:PRM `bearer_methods_supported` 必须含 `"header"`,否则 fail-closed

## 6. 测试与验收(§12.3 I10 映射)

| # | 验收 | I10a 测试 |
|---|------|---------|
| 1 | token issued for wrong resource rejected | `wrong_resource_rejected_when_jwt_aud_mismatches_prm_resource` |
| 2 | token passthrough fails closed | `incoming_authorization_header_is_never_forwarded_to_upstream` |
| 3 | scoped token works | `scoped_token_authorizes_mock_tools_call_successfully` |

### 补充:
- `prm_parse_valid_metadata`
- `prm_rejects_missing_bearer_header_method`
- `prm_rejects_missing_authorization_server`
- `opaque_token_returns_unsupported_format`
- `jwt_expired_returns_token_expired`
- `missing_scope_returns_scope_missing`
- `token_value_never_in_sqlite_or_audit`

## 7. 跨版本契约

- `vigil-http-auth` 的类型 / trait / error 作为 I10-future 稳定 API
- SQLite 表 `oauth_token_metadata` 字段集合固定;新增字段走 I08 `COLUMN_MIGRATIONS` 机制
- 审计事件前缀:`http_auth.*`(非 `RESERVED_EVENT_PREFIXES`)
  - `http_auth.prm_discovered`
  - `http_auth.token_stored`
  - `http_auth.token_rejected_wrong_resource`
  - `http_auth.passthrough_blocked`
  - `http_auth.request_authorized`

## 8. 延后项

| 延后项 | 目标迭代 |
|--------|---------|
| 真 HTTP transport(`reqwest`)接入 Hub | I10b |
| loopback localhost redirect server | I10b |
| JWKS 发现 + 签名验证 | I10b |
| AS introspection(opaque token) | I10b/c |
| refresh token 自动刷新 | I10c |
| UI 添加远程 MCP URL 流 | I10c |
| PolicyEngine `allowed_scopes` 字段 | I10c |

## 9. 与既有 ADR 的关系

- ADR 0002:复用 Ledger + `append_event`;`oauth_token_metadata` 表通过 `COLUMN_MIGRATIONS` 或 schema.sql 声明
- ADR 0006:复用 `SecretStore` + `SecretValue`(零化);token key 形态遵循 `secret://` 约定但 prefix 为 `token://`
- ADR 0004:I10b 的 HTTP transport 将扩展 Hub 的 upstream 抽象;I10a 不动 Hub
- ADR 0008:未来 `UiCommand` 可加 `AddRemoteMcpServer` / `AuthorizeRemoteMcp`,I10a 不做
