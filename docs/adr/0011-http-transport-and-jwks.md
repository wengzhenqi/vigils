# ADR 0011 — HTTP Transport + JWKS 验签(I10b-α1 / α2 / β)

- 状态:**Accepted(设计审查通过,α1 开工就绪;R1 REJECT → R2 CONDITIONAL-ACCEPT → R3 REJECT → R4 ACCEPT,2026-04-21)**
- 日期:2026-04-21
- 依赖:ADR 0004 / 0006 / 0008 / **0010**
- 相关迭代:
  - **I10b-α1**:纯 Rust **契约层**(issuer 绑定 + sealed API 重写 + planner 类型级强制)
  - **I10b-α2**:`reqwest + rustls` 实装 + JWKS 发现 + 真 TLS 集成测试
  - **I10b-β**:loopback redirect UX + 最小 token onboarding
  - I10c:refresh / opaque introspection / Remote MCP UI / policy `allowed_scopes`

## 0. R1 审查与本次修订

**Codex R1 REJECT**(2026-04-21 session `019dafec-e79e-7fb2-8ba5-8f27312e1965`):
5 BLOCKER + 7 MUST-FIX + 3 NICE-TO-HAVE。核心问题:

- **issuer 绑定缺失** —— 原 §I-11.4 "不跨 issuer 共享 key" 没有落实到数据结构
- **planner 只是规约** —— `HttpClient` 面接受通用 `HttpRequest`,调用者能自拼 Authorization
- **I10a sealed API 不够** —— `resolve_access_token` 入参塞不进 JWKS verifier,补丁式改造回潮
- **范围 vs "产品能力" 不一致** —— 无 loopback 就只能跑预录 JWT,不是产品能力
- **TLS 测试靠 wiremock 证明不了 rustls 协商**
- **Hub trait 化不是 0.5d** —— 错误模型 / 测试夹具 / attach 语义一起动

**R1 后的修订策略**(用户选 Path C,2026-04-21):
把 I10b-α 拆成 **α1(契约)+ α2(实装)**,α1 先把"契约回潮"风险清零(纯 Rust,
零网络),α2 再接真 HTTP + JWKS。β(loopback)独立于 α2,可在 α2 或 I08c 里完成。

## 1. 背景

I10a 把 HTTP MCP 认证核心做成了纯协议层 + mock transport(297 tests,R2 ACCEPT)。
`vigil-http-auth` 已有稳定 API:`HttpClient` trait / `TokenStore::resolve_access_token` /
`plan_authorized_request` / 5 类 `http_auth.*` 审计事件。

**已识别缺口**(需 α1 或 α2 补齐):
1. **issuer 绑定缺位**(α1):`DecodedAccessToken` 没 `iss`,`OAuthTokenMetadata` 存的是
   `authorization_server`(不是 JWT `issuer`);没有机制阻止"签名合法但来自错 issuer" 的 token
2. **planner 只是软约束**(α1):`HttpClient::get/post_form` 能接受任意 `Authorization` header
3. **sealed API 不够装 JWKS verifier**(α1):`resolve_access_token` 的签名需扩展
4. **真 HTTP transport 未接入**(α2):`TransportKind::Http` 在 Hub 仍是占位
5. **JWKS 验签缺失**(α2)
6. **Hub 仍绑死 `Arc<StdioUpstream>`**(α2):必须走 `Arc<dyn McpUpstream>`
7. **loopback / refresh / opaque / Remote MCP UI**(β / I10c)

## 2. 分段总览

| 段 | 范围 | 估期 | 网络依赖 | 前置 |
|----|----|----|----|----|
| **α1** | issuer 绑定 + sealed 契约重写 + planner 类型级强制 + `McpUpstream` trait + `UpstreamError` + singleflight JWKS verifier trait | **2-3d** | **零网络**,纯 Rust + mock | — |
| **α2** | `reqwest 0.12 + rustls-tls` / JWKS 发现 / 真 TLS 集成测试 / `HttpUpstream` impl / Hub 路由 | **2d** | 有(本地 mock AS / MCP) | α1 ACCEPT |
| **β** | loopback localhost redirect server + 最小 token onboarding UX | **2d** | 有 | α2 ACCEPT 或并入 I08c |

## 3. I10b-α1 关键决策(**契约层**,零网络)

### α1-D1 —— `issuer` 成为一级公民(BLOCKER 1)

**原状**:`OAuthTokenMetadata` 只有 `authorization_server`(URL);`DecodedAccessToken` 无
`iss`;`resolve_access_token` 不校验 issuer。

**修订**:
- `OAuthTokenMetadata` 新增字段 `issuer: String`(来自 AS `/.well-known/oauth-authorization-server`
  的 `issuer`,**不是** `authorization_server` URL 本身 —— 两者可能差一个尾斜杠或 subpath)
- `DecodedAccessToken` 新增 `iss: Option<String>`(**Option 仅作为 decode 容器**,
  外部 JWT 可能缺失 `iss`;消费侧 `resolve_access_token` 必须把 `None` 映射到
  `TokenRejectedWrongIssuer { expected, actual: "(missing)" }` —— 参见 α1-D3 处理流程)
- 新 sealed API 入参 `expected_issuer: &str`
- JWT 校验三项缺一不可:`iss == expected_issuer`(精确等,**缺失即非法**)+
  `aud/resource == expected_resource`(I10a 已有)+ 签名验证(α2 接入)
- 不变量 §I-11.4 重写:**JWKS 信任锚是 `(issuer, jwks_uri, kid, alg)` 四元组**,
  同一个 `jwks_uri` 被两个 issuer 引用 → 视作不同缓存条目,绝不共享

**SQLite 迁移**(R2 追加澄清,**落点两处必须同步改**):
- **声明**:`vigil-audit/src/ledger.rs::COLUMN_MIGRATIONS` 追加
  `("oauth_token_metadata", "issuer", "TEXT")` —— I08 以来的 ADD COLUMN 机制只支持
  **nullable** 追加列,这是刻意设计(`ALTER TABLE ADD COLUMN ... NOT NULL` 对非空表会
  失败,不能向后兼容)
- **读写**:`vigil-audit/src/registry.rs` 的 `register_oauth_token_metadata` 签名加
  `issuer: &str`;`list_oauth_token_metadata` / `get_oauth_token_metadata` 读 `issuer` 列
- **读侧 fail-closed**:legacy I10a 行 `issuer = NULL` → `TokenStoreError("issuer_missing_legacy_row")`
  (`vigil-http-auth::TokenStore` 的 metadata → typed 转换处统一拦截)
- **未来护栏**:ADR 明记 "该列走 nullable + 读侧 fail-closed 是刻意选择,未来**不**得
  修改为 `NOT NULL`" —— 防止后续迭代误强化

### α1-D2 —— Planner 类型级强制(BLOCKER 2)

**原状**:`HttpClient` trait 接受通用 `HttpRequest`,有能力构造任意 header。

**修订**(**不动** I10a `HttpClient` trait 面,以保持 I10a 9 条测试零 regression):
- 新增 `trait AuthorizedSender`(在 `vigil-http-auth`):`fn send_authorized(&self, req: AuthorizedHttpRequest) -> Result<HttpResponse, HttpAuthError>`
- `HttpUpstream`(α2)**只**持有 `Arc<dyn AuthorizedSender>`,不持有原 `HttpClient`
- `ReqwestHttpClient`(α2)同时实现 `HttpClient`(给 PRM/AS/JWKS 发现路径用)和
  `AuthorizedSender`(给 upstream 请求用);构造器 `ReqwestHttpClient::new()` 返回
  一个同时暴露两条面的封装类型,但 `HttpUpstream` 只接 `Arc<dyn AuthorizedSender>`
- **规约测试 + 类型测试**:用 `trybuild` 或等价 compile-fail 测试确保 `HttpUpstream` 不
  能构造 `HttpRequest`(类型面不给)

**理由**:I10a `HttpClient` 在发现路径(PRM / AS metadata / JWKS)**必须**能 GET
任意 URL 并设 Accept header —— 这部分不能被 "只准 AuthorizedRequest" 收死。所以设计是
**双 trait**:发现路径 `HttpClient`、upstream 路径 `AuthorizedSender`,两条面独立 DI。

### α1-D3 —— sealed API 重写(BLOCKER 3,R2 修订)

**原状**:
```rust
pub fn resolve_access_token(
    &self, token_ref: &str, expected_resource: &str,
    scopes: &[String], now: i64
) -> Result<ResolvedAccessToken, HttpAuthError>
```

**修订**(R2 对 `key_verifier: Option<_>` 修正为**必填**):
```rust
pub fn resolve_access_token(
    &self,
    token_ref: &str,
    expected: &ExpectedBinding,      // 新 DTO,封装所有校验约束
    now: i64,
) -> Result<ResolvedAccessToken, HttpAuthError>

pub struct ExpectedBinding {
    pub resource: String,
    pub issuer: String,                                  // α1 新增
    pub scopes: Vec<String>,
    pub key_verifier: Arc<dyn JwtKeyVerifier>,           // **R2 修订:必填**,不再 Option
}

pub trait JwtKeyVerifier: Send + Sync {
    /// 对已 decode 的 JWT(raw token + JOSE header)做签名验证。
    /// α2 唯一生产实装:`JwksSignatureVerifier`。
    /// 测试夹具:`tests/common::AlwaysAcceptVerifier`(**不**进 crate pub API,
    /// **不**走 feature 开关;仅在 integration test crate 本地定义并跨 test file 共享)。
    fn verify(&self, raw_jwt: &str, header: &JoseHeader, expected_issuer: &str)
        -> Result<(), HttpAuthError>;
}

pub struct JoseHeader {
    pub alg: String,
    pub kid: Option<String>,
    pub typ: Option<String>,
}
```

**R2 修订要点**:
1. **`key_verifier` 必填**(不 Option):Option 在生产 DTO 上留下"合法不验签路径",
   直接回潮 BLOCKER 3。生产路径永远必须注入 verifier,α1 路径由**测试夹具**
   `AlwaysAcceptVerifier` 提供(见下),α2 起改注入 `JwksSignatureVerifier`。
2. **删除 `resolve_access_token_i10a_compat` shim + 删除 `feature = "i10a-compat"`**
   (R2 的 compat feature 与 α2-D6 "alg=none 不给 feature 开关" 冲突):
   - α1 直接迁移 I10a 9 条 integration test 到新 API(重写 `ExpectedBinding` 构造 + 注入
     `AlwaysAcceptVerifier`)—— 不保留旧签名
   - 测试夹具 `AlwaysAcceptVerifier` 放 `crates/vigil-http-auth/tests/common/mod.rs`
     (integration test crate **本地** 模块,通过 `mod common;` 跨 test file 共享),
     **不**是 crate pub API,也不是 feature gate,prod build 根本看不到这个类型
   - 此举把 MUST-FIX 1(`alg=none` feature 风险)和 compat shim 风险**一起** 打穿
3. **`None` `iss` claim 处理**:`DecodedAccessToken.iss` 是 `Option<String>` 作为 decode
   容器(外部 JWT 不可控);`resolve_access_token` 内部把 `None` 显式映射到稳定
   `HttpAuthError::TokenRejectedWrongIssuer { expected, actual: "(missing)" }`,
   审计事件 `http_auth.token_rejected_wrong_issuer` 的 `actual_issuer` 字段置
   `"__iss_claim_missing__"`

**内部顺序**(`resolve_access_token` 实现,R2 明示):
1. 查 metadata(`get_metadata(token_ref)`);无 → `MissingToken`
2. `metadata.issuer == expected.issuer`?不等 → `TokenRejectedWrongIssuer`
3. SecretStore 查 value;无 → `TokenRehydrateRequired { reason_code: "secret_missing_for_known_metadata" }`
4. `decode_jwt_access_token(raw)` → `(header: JoseHeader, claims: Claims)`
5. **必填** `expected.key_verifier.verify(raw, &header, &expected.issuer)`;失败 →
   `JwtSignatureInvalid` / `JwtAlgRejected` / `JwksKidNotFound`
6. `claims.iss` → `None` 映射到 `TokenRejectedWrongIssuer { actual: "(missing)" }`;
   存在但 `!= expected.issuer` → 同错
7. I10a 已有校验:`aud / resource / scope / exp`
8. 返 `ResolvedAccessToken { raw, resource, scope_set, expires_at }`

### α1-D4 —— `McpUpstream` trait + `UpstreamError`(MUST-FIX 3)

```rust
pub trait McpUpstream: Send + Sync + std::fmt::Debug {
    fn server_id(&self) -> &str;
    fn transport(&self) -> TransportKind;
    /// **仅支持 unary request/response**;server-initiated notifications / SSE 不在 α1/α2 范围。
    fn call(&self, method: &str, params: serde_json::Value, timeout_ms: u64)
        -> Result<serde_json::Value, UpstreamError>;
    fn shutdown(&self);
}

pub enum UpstreamError {
    TransportIo(&'static str),       // 不泄漏底层细节
    Unauthorized { reason_code: &'static str },  // MUST-FIX 5 新增独立 code
    Forbidden,                        // 401/403 分开
    TimedOut,
    JsonRpc { code: i64, message_sha256: String },  // NICE-TO-HAVE 1:保留诊断
    TokenRehydrateRequired,           // MUST-FIX 5:metadata 活着 / secret 丢了
    AuthError(HttpAuthError),
    // stdio 特有的错误投影到 TransportIo / Internal,不透传具体类型
    Internal(&'static str),
}
```

**Hub 回归**:`Hub.upstreams` 从 `HashMap<String, Arc<StdioUpstream>>` 改为
`HashMap<String, Arc<dyn McpUpstream>>`;`HubError::Stdio` 改名 `HubError::Upstream`
(承接 `UpstreamError`);`StdioUpstream` 实现 `McpUpstream`,具体类型错误映射到
`UpstreamError`。

**Codex R1 警告**:此处回归成本被低估,α1 用**完整一天**完成 trait 化 + 既有 171+ 测试
零 regression,不再声称 0.5d。

### α1-D5 —— JWKS verifier trait + singleflight 语义(MUST-FIX 2)

α1 定义语义(无实装):
```rust
pub trait JwksSource: Send + Sync {
    /// 按 `(issuer, jwks_uri)` 获取当前 JwkSet。
    /// **并发约束**:同一 `(issuer, jwks_uri)` 在 "kid miss → 强制刷新" 场景下,
    /// 必须 singleflight —— 同一时刻最多一个 in-flight fetch;其余调用者阻塞等待
    /// 同一个 Future。这**不是**优化项,是并发安全不变量(§I-11.6)。
    fn get(&self, issuer: &str, jwks_uri: &str, force_refresh_for_kid: Option<&str>)
        -> Result<Arc<JwkSet>, HttpAuthError>;
}
```

α1 交付 `MockJwksSource`(`HashMap<(issuer, jwks_uri), JwkSet>` 预录),无 singleflight
因无并发;α2 交付 `HttpJwksSource` 用 `Mutex<HashMap<_, WaitGroup<_>>>` 或 `tokio::sync::OnceCell` 实现 singleflight。

### α1-D6 —— 跨重启 "metadata alive / secret gone" 独立错误(MUST-FIX 5)

`resolve_access_token` 区分:
- `HttpAuthError::MissingToken` —— 没 metadata 也没 secret(从未授权)
- `HttpAuthError::TokenRehydrateRequired { reason: "secret_missing_for_known_metadata" }` ——
  有 metadata 但 SecretStore 查 `token_ref` 返回 None(跨重启 / keychain 被清)

后续 I10c refresh / re-auth 入口按 `TokenRehydrateRequired` 触发 UX,不用猜。

### α1-D7 —— 审计事件语义固定(MUST-FIX 4)

I10a 的 5 类 `http_auth.*` 事件**语义不改**。签名 / JWKS 相关走**新**事件:

| 事件 | 语义 | 载荷(已脱敏) |
|---|---|---|
| `http_auth.token_rejected_wrong_resource`(**旧**) | JWT aud/resource 不对 —— **只**这一种触发 | expected_resource / actual_resource |
| `http_auth.token_rejected_wrong_issuer`(**α1 新**) | iss 不对 | expected_issuer / actual_issuer |
| `http_auth.jwt_signature_rejected`(**α2 新**) | 签名验证失败 | reason_code(alg_rejected / kid_not_found / signature_invalid / typ_rejected) |
| `http_auth.jwt_signature_verified`(**α2 新**) | 签名验证通过 | alg / kid / issuer |
| `http_auth.jwks_fetched`(**α2 新**) | JWKS 拉取(命中缓存也记,flag 标注) | jwks_uri / key_count / cache_hit / singleflight_coalesced |
| `http_auth.as_metadata_fetched`(**α2 新**) | AS metadata 拉取 | issuer / cache_hit |

审计事件命名一律收 `http_auth.*`;upstream 请求层事件走 `http_upstream.*`(α2):
- `http_upstream.request_sent`(server_id / method / status / duration_ms)
- `http_upstream.request_failed`(server_id / reason_code,无 body)

### α1-D8 —— "产品能力" 描述降格(BLOCKER 4)

α1/α2 合起来交付的是 **"transport + verifier 内核能力 + Hub 路由"**,不是"对外可
演示的 Remote MCP 产品能力"。真正产品能力要等 β(loopback token onboarding)+ I10c
(UI)。ADR 和 iteration 文档统一改此表述。

## 4. I10b-α2 关键决策(实装层,有网络)

### α2-D1 —— reqwest + rustls 严格依赖(MUST-FIX 6)

workspace `Cargo.toml` 追加:
```toml
reqwest = { version = "0.12", default-features = false, features = ["rustls-tls", "http2", "json"] }
webpki-roots = "0.26"
```

**严禁**:`default-tls` / `native-tls` / `cookies` / `gzip` / `brotli` / `deflate`。
CI 加 `cargo deny` 规则:`reqwest` 的 `default-features` 必须 `false`,任何 TLS feature
切换必须走 ADR 修订。

**企业私有 CA**:**α2 明确不支持**(不给用户装根证书入口);I10c 视需求再加
`rustls::RootCertStore::add_pem` 扩展 + UI 批准弹窗。

**webpki-roots 更新**:ADR 追加 release checklist "每季度更新 webpki-roots 版本
并记录差异";不再只靠 iteration double-check 口头提醒。

### α2-D2 —— 真 TLS 集成测试(BLOCKER 5)

**替换** wiremock 方案。α2 新增测试夹具(`tests/fixtures/mock_tls_server.rs`):
- 本地 `rustls::ServerConfig` + `hyper` 启动自签证书 MCP mock
- `ReqwestHttpClient` 用 `rustls::RootCertStore::add(self_signed_cert)` 仅在 test cfg 下
  信任(prod 绝不开放)
- 用这个真 TLS 端验证:`tls_minimum_version_is_1_2` / `http_1_0_downgrade_rejected` /
  `sni_correct` / `hostname_mismatch_rejected` 四项
- **wiremock 保留** 给 JWKS / AS metadata 的 HTTP 层测试(不涉及 TLS 协商正确性)

### α2-D3 —— JWKS 发现 + 签名验证实装

- 发现链:`AS URL (from PRM.authorization_servers[0]) → /.well-known/oauth-authorization-server → JwkSet`
- AS metadata 缓存:`HashMap<Url, (AuthorizationServerMetadata, Instant)>`,TTL 1h
- JWKS 缓存:`HashMap<(issuer, jwks_uri), (JwkSet, Instant)>`,TTL 10min,**按 issuer 隔离**
- singleflight:`tokio::sync::OnceCell` per `(issuer, jwks_uri)` 或 `Mutex<BTreeMap<_, Arc<Notify>>>` 手写
- `verify_jwt`(实现 `JwtKeyVerifier`):
  - `alg` 白名单:`RS256` / `ES256`,其他(含 `none`/`HS*`)→ `JwtAlgRejected`
  - `typ` 存在时必须 `"JWT"`(**不**强制存在 —— NICE-TO-HAVE 2 补注释说明理由)
  - `kid` 必须存在且在 `JwkSet` 内;miss 触发 singleflight 刷新一次,再 miss → `JwksKidNotFound`
  - 使用 `jsonwebtoken::decode::<Claims>(token, &DecodingKey::from_jwk(&jwk), &Validation::new(alg))`
  - 签名通过后再做 claim 校验(iss / aud / resource / scope / exp,α1 已落)

### α2-D4 —— `HttpUpstream` 实装

- `impl McpUpstream for HttpUpstream`
- `call()` 固定顺序:`resolve_access_token(ExpectedBinding{...})` → `plan_authorized_request()` → `AuthorizedSender::send_authorized()`
- `HttpUpstream` 只持 `Arc<dyn AuthorizedSender>`,拿不到原 `HttpClient`(类型级约束,§D2)

### α2-D5 —— I10a 9 条测试迁移(已在 α1 完成,此处仅做 α2 验收 checklist)

R2 修订后,I10a 9 条 integration 测试**已在 α1 阶段** 直接迁移到
`ExpectedBinding + AlwaysAcceptVerifier`(fixture 位于 `tests/common/mod.rs`);
**不存在** `resolve_access_token_i10a_compat` shim,也不存在 `feature = "i10a-compat"`。

α2 的 checklist:
- workspace `git grep -i "i10a_compat\|i10a-compat"` 零结果(α1 已保证,α2 复核)
- I10a 9 条测试继续跑 `AlwaysAcceptVerifier`;α2 新增的真 HTTP 端到端测试改用
  `JwksSignatureVerifier` + mock AS signed JWT,与 I10a 路径并存

### α2-D6 —— `alg=none` **仅 cfg(test)**(MUST-FIX 1)

`AlwaysAcceptVerifier` 与 `alg=none` 解析路径 **只**在 `#[cfg(test)]` 下可用;
**不给 feature 开关**。prod build 无论如何都走 `JwksSignatureVerifier`。

## 5. I10b-β 关键决策(loopback UX)

α2 ACCEPT 后独立启动 β;β 可并入 I08c(Desktop Server Registry UI)。β 范围:

- loopback HTTP server(`127.0.0.1:<ephemeral_port>`)接收 OAuth redirect code
- 跳转用户默认浏览器(`open` / `xdg-open` / `start`)
- 收到 code 后走 I10a 已有的 `exchange_code_for_token` 完成 token 落库
- 最小 CLI 命令 `vigil-hub-cli add-remote-mcp --url ...` 串联 PRM discover + loopback
  OAuth + token persist(Desktop UI 仍延到 I10c)

## 6. 安全不变量(重写 ADR 0010 §I-11.*)

- **§I-11.1**(α1):`HttpUpstream::call` 类型级只能通过 `AuthorizedSender` 发送;
  `HttpUpstream` 不持有 `HttpClient`(不再是软约束)
- **§I-11.2**(α2):JWT 签名验证失败 / `kid` 不存在 / `alg` 不在白名单 → **立即** fail-closed,
  审计 `http_auth.jwt_signature_rejected`(**不复用** `token_rejected_wrong_resource`)
- **§I-11.3**(α2):TLS 最低 1.2,由**真 TLS 集成测试**回归(非 wiremock)
- **§I-11.4**(α1 重写):JWKS 缓存按 **`(issuer, jwks_uri)`** 索引;同一 `jwks_uri` 对应
  不同 issuer 视作独立条目,绝不共享 key
- **§I-11.5**(α2):4xx/5xx 响应 body **不进 audit payload**;只记 status + reason_code +
  `body_sha256`(NICE-TO-HAVE 1,保留诊断能力但不泄漏内容)
- **§I-11.6**(α1 新增):同一 `(issuer, jwks_uri)` 的 JWKS 刷新必须 singleflight,
  并发等待同一 in-flight fetch(**不变量**,不是优化项)
- **§I-11.7**(α1 新增):JWT `iss` 校验必须精确等于 `expected_issuer`(来自 AS metadata
  `issuer` 字段,不是 AS URL),缺失 `iss` claim → fail-closed

## 7. 跨版本契约(α1 ACCEPT 后)

- `McpUpstream` trait / `UpstreamError` 作为 I10b 起稳定 API
- `ExpectedBinding` / `JwtKeyVerifier` trait / `JoseHeader` / `JwksSource` trait 同上
- `AuthorizedSender` trait 作为 upstream 发送面稳定 API
- `oauth_token_metadata` 表新增 `issuer` 列;未来新增字段继续走 `COLUMN_MIGRATIONS`
- 新审计事件 6 类(3 签名 + 2 发现 + 1 issuer rejected)进入固定集合
- `HttpClient` trait(I10a 定义)**不动**

## 8. 与既有 ADR 的关系

- ADR 0004:`McpUpstream` trait 替代具体 `Arc<StdioUpstream>`(α1 完整迁移 + 回归)
- ADR 0006:复用 `SecretStore`,token key 形态不变;α1 加 `TokenRehydrateRequired` 语义
- ADR 0008:UI 不动;β / I10c 再扩 `UiCommand::AddRemoteMcpServer`
- ADR 0010:I10a §I-10.1~§I-10.7 全部保留;`oauth_token_metadata.issuer` 列走迁移补齐;
  I10a 9 条测试在 **α1**(非 α2)直接迁移到 `ExpectedBinding + AlwaysAcceptVerifier` fixture

## 9. 交付估算(R1 修订后)

| 段 | 估期 | 主要里程碑 |
|----|----|----|
| α1 | **2-3d** | sealed 契约重写 + issuer 绑定 + `McpUpstream` trait 全 workspace 迁移 + 既有 297 测试零 regression + 新增 ~15 条单元测试(契约边界) |
| α2 | **2d** | reqwest+rustls 实装 + JWKS 签名验证 + 真 TLS 集成测试 + mock AS/MCP 端到端 |
| β | **2d** | loopback server + 最小 CLI onboarding |
| **合计** | **6-7d** | 原 3-4d 估期被低估;Codex R1 观察 "Hub trait 化不是 0.5d" 正确 |

## 10. α1 启动前 double-check

1. **I10a 9 条测试直接迁移(α1 内完成)**:在 `crates/vigil-http-auth/tests/common/mod.rs`
   定义 `AlwaysAcceptVerifier`(integration test crate 本地,非 pub API,**非** feature);
   重写 `tests/integration.rs` 9 条测试为 `ExpectedBinding { issuer, key_verifier:
   Arc::new(AlwaysAcceptVerifier), ... }` 调用;**不**保留任何 compat shim 或 "i10a-compat"
   feature 路径;α1 合并前 `git grep -i "i10a_compat\|i10a-compat"` 必须零结果
2. **`oauth_token_metadata.issuer` 列迁移**:NULL → fail-closed,只在 α1 引入;跨重启
   回归测试(`oauth_token_metadata_survives_reopen`)需补一条 "legacy NULL issuer"
3. **`trybuild` compile-fail 测试**:`HttpUpstream { sender: Arc<dyn HttpClient> }` 应编译失败
   (不实现 `AuthorizedSender`)—— 证明类型级约束
4. **Hub trait 化影响面**:I04 / I05 / I07 / I09a 共 171+ 测试先跑基线快照,
   `cargo test --workspace -p vigil-mcp` 改造前记录一次,改造后对比零 regression
5. **`UpstreamError` 语义稳定性**:α1 一旦合并,后续变体只能**新增**(`#[non_exhaustive]`)
   不能改现有语义 —— 这会影响 Desktop UI 的错误映射(I08a 协议层)

## 11. α2 启动前 double-check(α1 ACCEPT 后再审)

1. 真 TLS 测试夹具是否真实拉起 rustls server(不得降级成 HTTP mock)
2. webpki-roots 版本锁定 + 每季度更新 checklist 写进 release runbook
3. `cargo deny` 禁 `default-tls` / `native-tls` feature 生效
4. JWKS singleflight 在 tokio 多线程 runtime 下并发 race 压测(>=100 并发 kid miss)

## 12. β 启动前 double-check

1. loopback 端口选择:`127.0.0.1:0` 让 OS 分配;记录在审计事件 `oauth.loopback_started`
2. CSRF state + PKCE code_verifier 一次一对,绑 session
3. 浏览器默认 app fallback(WSL / headless server)
