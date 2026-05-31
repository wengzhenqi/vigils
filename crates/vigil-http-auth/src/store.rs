//! Token 持久化(ADR 0010 §D4):
//!
//! - 真值 → `vigil_lease::SecretStore`(复用 I06 边界);key = `token://oauth/{kind}/<res_hash>/<client_hash>`
//! - metadata → SQLite 新表 `oauth_token_metadata`(**不含** value)
//!
//! 通过 I08 `COLUMN_MIGRATIONS` 机制保证老库升级兼容(但 table 本身走 schema.sql 的
//! `CREATE TABLE IF NOT EXISTS`)。

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Instant;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use vigil_audit::Ledger;
use vigil_lease::{SecretStore, SecretValue};

use crate::error::HttpAuthError;

/// Token 种类。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum TokenKind {
    /// access token(JWT bearer)
    Access,
    /// refresh token(opaque,I10a 只存不用)
    Refresh,
}

impl TokenKind {
    /// 序列化到 key 路径。
    pub fn as_path_segment(self) -> &'static str {
        match self {
            TokenKind::Access => "access",
            TokenKind::Refresh => "refresh",
        }
    }

    /// 稳定字符串(SQLite 列值 / 审计 payload)。
    pub fn as_str(self) -> &'static str {
        match self {
            TokenKind::Access => "access",
            TokenKind::Refresh => "refresh",
        }
    }
}

/// SQLite `oauth_token_metadata` 一行(**不含** value)。
///
/// I10b-α1(ADR 0011 §α1-D1)新增 `issuer`:来自 AS `/.well-known/oauth-authorization-server`
/// 的 `issuer` 字段,**不等同** `authorization_server` URL(可能差尾斜杠 / subpath)。
/// JWT `iss` claim 校验必须精确等此字段。
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct OAuthTokenMetadata {
    /// SecretStore 的 key(形如 `token://oauth/access/<res_hash>/<client_hash>`)
    pub token_ref: String,
    /// 远程 MCP resource URL
    pub resource: String,
    /// AS URL(发现端点)
    pub authorization_server: String,
    /// AS metadata 的 `issuer` 字符串 —— JWT `iss` 精确等此值
    pub issuer: String,
    /// token 覆盖的 scope(字母排序)
    pub scope_set: Vec<String>,
    /// access / refresh
    pub token_kind: TokenKind,
    /// Unix 秒;None 表示 JWT 无 exp(I10a 允许但 UI 应提示)
    pub expires_at: Option<i64>,
    /// 创建时间 Unix 秒
    pub created_at: i64,
}

/// 构造 access token 的 SecretStore key。
pub fn token_ref_for_access(resource: &str, client_id: &str) -> String {
    format!(
        "token://oauth/access/{}/{}",
        sha256_hex(resource),
        sha256_hex(client_id)
    )
}

/// 构造 refresh token 的 SecretStore key。
pub fn token_ref_for_refresh(resource: &str, client_id: &str) -> String {
    format!(
        "token://oauth/refresh/{}/{}",
        sha256_hex(resource),
        sha256_hex(client_id)
    )
}

fn sha256_hex(s: &str) -> String {
    let mut h = Sha256::new();
    h.update(s.as_bytes());
    hex::encode(h.finalize())
}

/// I10c-α3:introspection 缓存 key。`sha256(token || '\0' || endpoint)` hex。
///
/// 用 `\0` 分隔防止 token+endpoint 拼接歧义(e.g. `"ab" + "cd"` vs `"abc" + "d"`)。
/// 不持 raw token,只存 hash。
fn make_introspection_cache_key(token_raw: &str, endpoint: &str) -> String {
    let mut h = Sha256::new();
    h.update(token_raw.as_bytes());
    h.update(b"\0");
    h.update(endpoint.as_bytes());
    hex::encode(h.finalize())
}

/// I10c-α3:缓存 TTL 计算。
///
/// 实际规则(按此顺序):
/// - `response.exp` 存在且 `> now` → `min(response.exp - now, cache_max_ttl_secs, HARD_CAP)`
/// - `response.exp` 存在且 `<= now` → 返 `0`(token 已过期,不缓存)
/// - `response.exp == None` → `min(cache_max_ttl_secs, HARD_CAP)`(AS 未提供到期时间,
///   仍允许**有界**缓存 —— 由 `HARD_CAP=300s` 兜底,避免永久缓存;若需完全不缓存,用
///   `IntrospectionConfig::with_cache_max_ttl_secs(0)`)
///
/// 三层上限保证缓存不可能比 token 实际 lifetime 更长。
fn compute_cache_ttl(
    response: &crate::oauth::IntrospectionResponse,
    now_unix_secs: i64,
    cache_max_ttl_secs: u64,
) -> i64 {
    let hard_cap = crate::jwt::INTROSPECTION_CACHE_HARD_CAP_SECS.min(cache_max_ttl_secs) as i64;
    if hard_cap <= 0 {
        return 0;
    }
    match response.exp {
        Some(exp) => {
            let remaining = exp - now_unix_secs;
            if remaining <= 0 {
                0
            } else {
                remaining.min(hard_cap)
            }
        }
        None => hard_cap,
    }
}

/// Token 持久化门面:把"真值进 SecretStore + metadata 进 SQLite"封成单一 API,
/// 避免 caller 分开调两边导致不一致。
///
/// I10c-α1 新增 per-token_ref singleflight 锁 —— 同一 access token 的并发 refresh
/// 合并为一次 IO,避免 N 个并发 Hub call 同时撞 AS `/token` 端点。
///
/// I10c-α3 新增 introspection 响应缓存 + per-key singleflight —— 避免同一 opaque
/// token 的高频 Hub call 把 AS introspection endpoint 压垮。
pub struct TokenStore {
    store: Arc<dyn SecretStore>,
    ledger: Arc<Ledger>,
    /// per access-token_ref refresh 锁(I10c-α1 §I-11.6 style singleflight)。
    /// 同一 token_ref 并发 refresh → 第一个 caller 持锁做 IO,其他 caller 等锁释放后
    /// 从 `get_metadata` + `resolve_access_value` 读更新后的 token(短路不再 IO)。
    ///
    /// **v0.5.1 修(flaky 治理)**:lock 内值由 `()` 改为 `Option<Instant>` —— 记录该 key
    /// 上一次成功完成 refresh 的 monotonic 时刻;`try_refresh_access_token` 在函数入口处
    /// 捕获 `my_arrival = Instant::now()`,锁内若发现 `last_completion >= my_arrival`,即
    /// "我决定刷新之后,他人已替我刷过" → 短路 `Ok(false)`。这条不变量与 pre/post snapshot
    /// 不同 —— 它对 late-arriver 也成立(barrier-released N 线程在 CPU 抖动下,任意被延迟
    /// 至前 caller 完成之后才入函数的线程,其 `my_arrival` 仍早于 `last_completion`)。
    refresh_locks: Mutex<HashMap<String, Arc<Mutex<Option<Instant>>>>>,
    /// I10c-α3:introspection 响应缓存。key = `sha256(raw_token || endpoint)` hex,
    /// **只缓存 `active: true`** 的成功响应(失败 / active:false 立即失效,不污染缓存)。
    /// Entry 过期由读路径 lazy 清理;无总大小上限(生产侧 key 空间 = 活跃 opaque token 数,
    /// 通常 O(10) 量级,可接受)。
    introspection_cache: Mutex<HashMap<String, CachedIntrospection>>,
    /// I10c-α3:per-cache-key introspection singleflight 锁。模式复用 `refresh_locks` —
    /// 同一 cache key 并发 miss → 第一个 caller 做 IO 并写缓存,其他 caller 等锁释放后
    /// 重读缓存(hit 短路)。
    introspection_locks: Mutex<HashMap<String, Arc<Mutex<()>>>>,
}

/// I10c-α3:一条 introspection 缓存条目。
#[derive(Clone)]
struct CachedIntrospection {
    /// 缓存的响应(caller 复用,跳过 IO)。
    response: crate::oauth::IntrospectionResponse,
    /// Unix 秒;`cached_at <= now < expires_at` 时 hit。
    expires_at: i64,
}

impl std::fmt::Debug for TokenStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TokenStore")
            .field("store_backend", &self.store.backend_kind())
            .finish_non_exhaustive()
    }
}

impl TokenStore {
    /// 新建门面。
    pub fn new(store: Arc<dyn SecretStore>, ledger: Arc<Ledger>) -> Self {
        Self {
            store,
            ledger,
            refresh_locks: Mutex::new(HashMap::new()),
            introspection_cache: Mutex::new(HashMap::new()),
            introspection_locks: Mutex::new(HashMap::new()),
        }
    }

    /// 存 access token:value → SecretStore;metadata → SQLite。
    ///
    /// 对同一 `token_ref` 调用会覆盖。
    pub fn put_access_token(
        &self,
        metadata: &OAuthTokenMetadata,
        value: SecretValue,
    ) -> Result<(), HttpAuthError> {
        self.put_with_kind(metadata, value, TokenKind::Access)
    }

    /// 存 refresh token。
    pub fn put_refresh_token(
        &self,
        metadata: &OAuthTokenMetadata,
        value: SecretValue,
    ) -> Result<(), HttpAuthError> {
        self.put_with_kind(metadata, value, TokenKind::Refresh)
    }

    fn put_with_kind(
        &self,
        metadata: &OAuthTokenMetadata,
        value: SecretValue,
        expected_kind: TokenKind,
    ) -> Result<(), HttpAuthError> {
        if metadata.token_kind != expected_kind {
            return Err(HttpAuthError::TokenStoreError("token_kind_mismatch"));
        }
        // 1. 真值 → SecretStore
        self.store
            .put(&metadata.token_ref, value)
            .map_err(|_| HttpAuthError::TokenStoreError("secret_store_put_failed"))?;
        // 2. metadata → SQLite(via Ledger)。I10b-α1 起 issuer 必填。
        self.ledger
            .register_oauth_token_metadata(
                &metadata.token_ref,
                &metadata.resource,
                &metadata.authorization_server,
                &metadata.scope_set,
                metadata.token_kind.as_str(),
                metadata.expires_at,
                &metadata.issuer,
            )
            .map_err(|_| HttpAuthError::TokenStoreError("metadata_insert_failed"))?;
        Ok(())
    }

    /// 从 SecretStore 读 access token 的真值。
    ///
    /// 返 None 表示 `token_ref` 未登记(caller 应走 auth flow)。
    pub fn resolve_access_value(
        &self,
        token_ref: &str,
    ) -> Result<Option<SecretValue>, HttpAuthError> {
        match self.store.get(token_ref) {
            Ok(v) => Ok(Some(v)),
            Err(vigil_lease::SecretStoreError::NotFound) => Ok(None),
            Err(_) => Err(HttpAuthError::TokenStoreError("secret_store_get_failed")),
        }
    }

    /// **sealed 生产入口**(ADR 0011 §α1-D3,R2 必填 verifier):按 `ExpectedBinding`
    /// 查 token → 校 issuer/metadata → 查 value(缺失 → `TokenRehydrateRequired`)→ decode
    /// → verifier → claims 校验 → 返 `ResolvedAccessToken`。
    ///
    /// 流程(按 ADR 0011 §α1-D3 第 1-8 步):
    /// 1. metadata 查不到 → `MissingToken`
    /// 2. `metadata.issuer != expected.issuer` → `TokenRejectedWrongIssuer`
    /// 3. SecretStore 查 value 缺失 → `TokenRehydrateRequired { reason_code: "secret_missing_for_known_metadata" }`
    /// 4. decode → `(JoseHeader, DecodedAccessToken)`
    /// 5. `expected.key_verifier.verify(raw, &header, &expected.issuer)` —— 必填
    /// 6. `claims.iss` = None → `TokenRejectedWrongIssuer { actual: "(missing)" }`;
    ///    存在但 != expected → 同错,actual = claims.iss
    /// 7. aud / resource / scope / exp(I10a 已有)
    /// 8. 返 `ResolvedAccessToken`
    pub fn resolve_access_token(
        &self,
        token_ref: &str,
        expected: &crate::jwt::ExpectedBinding,
        now_unix_secs: i64,
    ) -> Result<crate::types::ResolvedAccessToken, HttpAuthError> {
        // 1. metadata
        let metadata = self
            .get_metadata(token_ref)?
            .ok_or(HttpAuthError::MissingToken)?;
        // 2. metadata.issuer vs expected.issuer —— 数据库端预验,避免 value 被取用后再拒
        if metadata.issuer != expected.issuer {
            return Err(HttpAuthError::TokenRejectedWrongIssuer {
                expected: expected.issuer.clone(),
                actual: metadata.issuer,
            });
        }
        // 3. value
        let raw =
            self.resolve_access_value(token_ref)?
                .ok_or(HttpAuthError::TokenRehydrateRequired {
                    reason_code: "secret_missing_for_known_metadata",
                })?;
        // 4. decode JWT —— I10c-α2 分流:UnsupportedTokenFormat + 有 IntrospectionConfig
        //    → 走 RFC 7662 opaque 路径;否则维持 I10a 行为
        let decode_result = crate::jwt::decode_jwt_access_token(raw.expose());
        match decode_result {
            Ok((header, claims)) => {
                // JWT 路径(I10a/b 原路径)
                // 5. 签名验证(必填)
                expected
                    .key_verifier
                    .verify(raw.expose(), &header, &expected.issuer)?;
                // 6. claims.iss 精确等(含 None → (missing))
                match claims.iss.as_deref() {
                    None => {
                        return Err(HttpAuthError::TokenRejectedWrongIssuer {
                            expected: expected.issuer.clone(),
                            actual: "(missing)".to_string(),
                        });
                    }
                    Some(iss) if iss != expected.issuer => {
                        return Err(HttpAuthError::TokenRejectedWrongIssuer {
                            expected: expected.issuer.clone(),
                            actual: iss.to_string(),
                        });
                    }
                    _ => {}
                }
                // 7. aud / resource / scope / exp
                crate::jwt::validate_and_resolve_access_token(
                    raw,
                    &expected.resource,
                    &expected.scopes,
                    now_unix_secs,
                )
            }
            Err(HttpAuthError::UnsupportedTokenFormat) => {
                // opaque 路径(I10c-α2):只有当 caller 明示 IntrospectionConfig 时启用
                match &expected.introspection {
                    Some(cfg) => {
                        self.resolve_opaque_via_introspection(raw, expected, cfg, now_unix_secs)
                    }
                    None => Err(HttpAuthError::UnsupportedTokenFormat),
                }
            }
            Err(other) => Err(other),
        }
    }

    /// I10c-α2(ADR 0011 §8):opaque token 走 RFC 7662 introspection。
    ///
    /// 流程:
    /// 0. **I10c-α3 缓存**:`sha256(raw_token || endpoint)` 查缓存,hit 且未过期 → 复用响应,
    ///    miss/过期 → 取 per-key 锁,锁后重查(可能前 caller 刚填)→ 否则真 IO + 写缓存
    /// 1. 从 SecretStore 取 client_secret(`expected.introspection.client_secret_ref`)
    /// 2. POST introspect 到 AS introspection endpoint
    /// 3. 校 `active == true`;否则 `TokenExpired`(caller 走 refresh)。**失败不缓存**
    /// 4. 校 `iss == expected.issuer`;不等 → `TokenRejectedWrongIssuer`
    /// 5. 校 `aud` 含 `expected.resource`;不含 → `AudienceMismatch`
    /// 6. 校 `exp > now`;否则 `TokenExpired`
    /// 7. 校 scope 覆盖 `expected.scopes`;缺失 → `ScopeMissing`
    /// 8. 返 `ResolvedAccessToken { raw, resource: expected.resource, scope_set, expires_at }`
    fn resolve_opaque_via_introspection(
        &self,
        raw: SecretValue,
        expected: &crate::jwt::ExpectedBinding,
        cfg: &crate::jwt::IntrospectionConfig,
        now_unix_secs: i64,
    ) -> Result<crate::types::ResolvedAccessToken, HttpAuthError> {
        // 0. I10c-α3:缓存查找 + singleflight 合并。
        // cache key 对 (token, endpoint) 取 sha256 —— 只存 hash,不持 raw。
        let cache_key = make_introspection_cache_key(raw.expose(), cfg.endpoint().as_str());
        let cache_ttl = cfg.cache_max_ttl_secs();

        let ir = if cache_ttl == 0 {
            // 显式关闭缓存(如测试 / 高敏场景):直接走 IO
            self.introspect_uncached(raw.expose(), cfg)?
        } else {
            match self.cache_lookup(&cache_key, now_unix_secs)? {
                Some(hit) => hit,
                None => {
                    // miss:取 per-key 锁,锁后再查一次(前 caller 可能刚填),还 miss 才真 IO
                    let lock = {
                        let mut locks = self
                            .introspection_locks
                            .lock()
                            .map_err(|_| HttpAuthError::Internal("introspection_locks_poisoned"))?;
                        locks
                            .entry(cache_key.clone())
                            .or_insert_with(|| Arc::new(Mutex::new(())))
                            .clone()
                    };
                    let fresh_result = {
                        let _guard = lock.lock().map_err(|_| {
                            HttpAuthError::Internal("introspection_singleflight_poisoned")
                        })?;
                        if let Some(hit) = self.cache_lookup(&cache_key, now_unix_secs)? {
                            Ok(hit)
                        } else {
                            let fresh = self.introspect_uncached(raw.expose(), cfg)?;
                            // 只缓存 active:true 的响应 —— 失败结果不污染缓存,避免"token 刚
                            // rotate 却被缓存的 false 持续拒绝"。caller 看到 active:false
                            // 会触发 refresh,refresh 成功后新 token 有新 cache key。
                            if fresh.active {
                                let ttl = compute_cache_ttl(&fresh, now_unix_secs, cache_ttl);
                                if ttl > 0 {
                                    self.cache_store(
                                        cache_key.clone(),
                                        fresh.clone(),
                                        now_unix_secs + ttl,
                                    )?;
                                }
                            }
                            Ok(fresh)
                        }
                    }; // _guard 释放
                       // I10c-α3+ lock cleanup(R2 修订 —— cleanup 必须在 Ok/Err 两条路径都跑,
                       // 否则失败 token 的 lock entry 依然积累):
                       //   1. drop 本地 lock Arc(fresh_result 仍持 Result,不触发提前返回)
                       //   2. 尝试 cleanup,返回值 `let _ = ...` 显式吞掉 —— cleanup 失败
                       //      (poisoned / strong_count>1)一律保留 map entry,下次再清理
                       //   3. 最后 `fresh_result?` 上抛原始 IO 结果 / 错误,优先级不受 cleanup 污染
                       // 竞争安全:cleanup 内部 check + remove 仍在 outer mutex 内原子完成。
                    drop(lock);
                    let _ = self.try_cleanup_introspection_lock(&cache_key);
                    fresh_result?
                }
            }
        };

        // 3. active
        if !ir.active {
            return Err(HttpAuthError::TokenExpired);
        }

        // 4. iss
        match ir.iss.as_deref() {
            None => {
                return Err(HttpAuthError::TokenRejectedWrongIssuer {
                    expected: expected.issuer.clone(),
                    actual: "(missing)".to_string(),
                });
            }
            Some(iss) if iss != expected.issuer => {
                return Err(HttpAuthError::TokenRejectedWrongIssuer {
                    expected: expected.issuer.clone(),
                    actual: iss.to_string(),
                });
            }
            _ => {}
        }

        // 5. aud 必须含 expected.resource
        let auds = ir.audience();
        if !auds.iter().any(|a| a == &expected.resource) {
            return Err(HttpAuthError::AudienceMismatch {
                expected: expected.resource.clone(),
                actual: auds.join(","),
            });
        }

        // 6. exp
        if let Some(exp) = ir.exp {
            if exp <= now_unix_secs {
                return Err(HttpAuthError::TokenExpired);
            }
        }

        // 7. scope 覆盖
        let token_scopes: Vec<String> = ir
            .scope
            .as_deref()
            .map(|s| {
                s.split(' ')
                    .filter(|x| !x.is_empty())
                    .map(String::from)
                    .collect()
            })
            .unwrap_or_default();
        for req in &expected.scopes {
            if !token_scopes.iter().any(|t| t == req) {
                return Err(HttpAuthError::ScopeMissing(req.clone()));
            }
        }

        // 8. 构造 ResolvedAccessToken
        Ok(crate::types::ResolvedAccessToken {
            raw,
            resource: expected.resource.clone(),
            scope_set: token_scopes,
            expires_at: ir.exp,
        })
    }

    /// I10c-α3:真 IO introspect(不走缓存)。由 `resolve_opaque_via_introspection`
    /// 的缓存 miss 分支或 `cache_ttl == 0` 路径调用。
    fn introspect_uncached(
        &self,
        token_raw: &str,
        cfg: &crate::jwt::IntrospectionConfig,
    ) -> Result<crate::oauth::IntrospectionResponse, HttpAuthError> {
        let client_secret_sv = self
            .store
            .get(cfg.client_secret_ref())
            .map_err(|_| HttpAuthError::TokenStoreError("client_secret_missing"))?;
        crate::oauth::introspect_token(
            cfg.http(),
            cfg.endpoint(),
            cfg.client_id(),
            client_secret_sv.expose(),
            token_raw,
        )
    }

    /// I10c-α3:读缓存,hit 且未过期返 Some(response)。过期 entry 顺手 lazy 清理。
    fn cache_lookup(
        &self,
        key: &str,
        now_unix_secs: i64,
    ) -> Result<Option<crate::oauth::IntrospectionResponse>, HttpAuthError> {
        let mut cache = self
            .introspection_cache
            .lock()
            .map_err(|_| HttpAuthError::Internal("introspection_cache_poisoned"))?;
        if let Some(entry) = cache.get(key) {
            if entry.expires_at > now_unix_secs {
                return Ok(Some(entry.response.clone()));
            }
            // 过期,lazy 清理
            cache.remove(key);
        }
        Ok(None)
    }

    /// I10c-α3+(**仅测试** —— 命名遵循仓库 `*_for_test` 纪律,I04 先例如
    /// `inject_route_for_test` / `set_session_id_for_test`):
    /// introspection 锁 map 当前大小,用于回归 lock cleanup。
    ///
    /// 本 API 不在任何 AGENTS.md 不变量的 public 范围,生产组件不应调用。
    #[doc(hidden)]
    pub fn introspection_locks_len_for_test(&self) -> Result<usize, HttpAuthError> {
        Ok(self
            .introspection_locks
            .lock()
            .map_err(|_| HttpAuthError::Internal("introspection_locks_poisoned"))?
            .len())
    }

    /// I10c-α3+:try-cleanup per-key introspection 锁。
    ///
    /// 在 `resolve_opaque_via_introspection` 的 IO 路径结束后调用 —— 本 caller 已释放
    /// 自己持有的 `Arc<Mutex<()>>`,若此刻 map 里的 Arc `strong_count == 1`,说明没有
    /// 其他并发 caller 正在等待或将要进入该 key 的 singleflight,可安全 remove。
    ///
    /// **竞争安全**:check 与 remove 都在 `introspection_locks` outer mutex 内原子
    /// 完成 —— 任何新 caller 要拿到该 key 的 Arc 必须先持本 mutex,不会看到半清理状态。
    ///
    /// 最坏情况下 cleanup 失败(strong_count > 1 或 poisoned):map 保留 entry,
    /// 下次再清理 —— fail-soft,不影响正确性。
    fn try_cleanup_introspection_lock(&self, key: &str) -> Result<(), HttpAuthError> {
        let mut locks = self
            .introspection_locks
            .lock()
            .map_err(|_| HttpAuthError::Internal("introspection_locks_poisoned"))?;
        if let Some(existing) = locks.get(key) {
            // strong_count == 1 表示 map 是唯一持有者(本 caller 刚 drop 自己那份),
            // 无人能在不持 outer mutex 的前提下 clone 出新引用,所以 remove 安全。
            if Arc::strong_count(existing) == 1 {
                locks.remove(key);
            }
        }
        Ok(())
    }

    /// I10c-α3:写缓存。
    fn cache_store(
        &self,
        key: String,
        response: crate::oauth::IntrospectionResponse,
        expires_at: i64,
    ) -> Result<(), HttpAuthError> {
        let mut cache = self
            .introspection_cache
            .lock()
            .map_err(|_| HttpAuthError::Internal("introspection_cache_poisoned"))?;
        cache.insert(
            key,
            CachedIntrospection {
                response,
                expires_at,
            },
        );
        Ok(())
    }

    /// 列出所有已登记 token metadata(ADR §D4 / I10.md T4)。
    pub fn list_metadata(&self) -> Result<Vec<OAuthTokenMetadata>, HttpAuthError> {
        let rows = self
            .ledger
            .list_oauth_token_metadata()
            .map_err(|_| HttpAuthError::TokenStoreError("metadata_query_failed"))?;
        let mut out = Vec::with_capacity(rows.len());
        for r in rows {
            out.push(row_to_typed(r)?);
        }
        Ok(out)
    }

    /// 查 metadata(不触碰 value);把 raw row 转为 typed `OAuthTokenMetadata`。
    pub fn get_metadata(
        &self,
        token_ref: &str,
    ) -> Result<Option<OAuthTokenMetadata>, HttpAuthError> {
        let row = self
            .ledger
            .get_oauth_token_metadata(token_ref)
            .map_err(|_| HttpAuthError::TokenStoreError("metadata_query_failed"))?;
        let Some(r) = row else { return Ok(None) };
        Ok(Some(row_to_typed(r)?))
    }

    /// I10c-α1(ADR 0011 §6 refresh):用已存的 refresh token 换新 access,原子更新
    /// SecretStore value + SQLite metadata(`expires_at`)。
    ///
    /// **真 singleflight**(v0.5.1 重写 —— 取代 I10c-α1 R1 / R3 pre/post snapshot 方案):
    /// 1. 入锁**前**捕获 `my_arrival = Instant::now()`(monotonic),代表"我决定可能要刷新"的时刻
    /// 2. 取 per-token_ref `Arc<Mutex<Option<Instant>>>`(outer map 守门 + arc clone)
    /// 3. lock 该 Mutex(阻塞等前一个 caller 完成 IO)
    /// 4. lock 内若 `last_completion = Some(t)` 且 `t >= my_arrival` —— 别人在我决定之后才
    ///    完成,刷新结果可复用 → **短路 `Ok(false)`**,**不打 AS**
    /// 5. 否则本 caller 真刷 → 完成后写 `*state = Some(Instant::now())` → 返 `Ok(true)`
    ///
    /// **为何弃用 pre/post snapshot**:旧实现 Step 0 在锁外读 pre,late-arriver(被 OS
    /// scheduler 延迟到前 caller 完成之后才进函数)的 pre 已是别人的 post → "无变化"误判
    /// → 触发额外 IO(workspace 全跑下 ~4% 失败率,e2e_real_tls.rs 两 concurrent_refresh
    /// 测试坐实)。新方案用 monotonic `Instant` arrival_time,不存在该窗口。
    ///
    /// 这样 N 个并发 caller 合并成 1 次 AS IO(§I-11.6 等效 jwks singleflight)。
    ///
    /// **fail-closed**:
    /// - refresh token 不在 SecretStore → `TokenStoreError("refresh_token_missing")`
    /// - metadata 不存在 → `MissingToken`
    /// - AS 返非 Bearer / 非 2xx → `HttpError`
    ///
    /// 返回 `bool`:`true` = 本 caller 触发了真刷;`false` = 入锁后发现已被前 caller 刷过。
    pub fn try_refresh_access_token(
        &self,
        access_token_ref: &str,
        client_id: &str,
        token_endpoint: &url::Url,
        http: &dyn crate::HttpClient,
    ) -> Result<bool, HttpAuthError> {
        // Step 0:函数入口立即记 monotonic 时刻 —— 这是 singleflight 短路判定的"我"参考点
        let my_arrival = Instant::now();

        // Step 1:拿 per-key singleflight 锁(锁内值是 `Option<Instant>` —— 上次成功完成时刻)
        let key_lock = {
            let mut locks = self
                .refresh_locks
                .lock()
                .map_err(|_| HttpAuthError::Internal("refresh_locks_poisoned"))?;
            Arc::clone(
                locks
                    .entry(access_token_ref.to_string())
                    .or_insert_with(|| Arc::new(Mutex::new(None))),
            )
        };
        let mut sf_state = key_lock
            .lock()
            .map_err(|_| HttpAuthError::Internal("refresh_singleflight_poisoned"))?;

        // Step 2:**真 singleflight 短路** —— 若上次完成发生在我决定之后,直接复用
        if let Some(last_completion) = *sf_state {
            if last_completion >= my_arrival {
                return Ok(false);
            }
        }

        // Step 3:metadata 必须存在(否则完全没登记)
        let access_meta = self
            .get_metadata(access_token_ref)?
            .ok_or(HttpAuthError::MissingToken)?;
        if access_meta.token_kind != TokenKind::Access {
            return Err(HttpAuthError::TokenStoreError("not_an_access_token_ref"));
        }

        // Step 4:派生对应 refresh token_ref(与 access 同一 resource / client_id 哈希)
        let refresh_token_ref = token_ref_for_refresh(&access_meta.resource, client_id);
        let refresh_value = self
            .store
            .get(&refresh_token_ref)
            .map_err(|_| HttpAuthError::TokenStoreError("refresh_token_missing"))?;

        // Step 5:发 refresh request
        let resource: url::Url = access_meta
            .resource
            .parse()
            .map_err(|_| HttpAuthError::TokenStoreError("refresh_resource_parse_failed"))?;
        let tr = crate::oauth::exchange_refresh_token_for_token(
            http,
            token_endpoint,
            client_id,
            refresh_value.expose(),
            &resource,
        )?;

        // Step 6:更新 access token —— value + metadata.expires_at(换新 token,旧 token_ref 保持不变)
        let new_expires_at = tr.expires_in.map(|secs| {
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs() as i64 + secs)
                .unwrap_or(0)
        });
        let new_access_meta = OAuthTokenMetadata {
            token_ref: access_meta.token_ref.clone(),
            resource: access_meta.resource.clone(),
            authorization_server: access_meta.authorization_server.clone(),
            issuer: access_meta.issuer.clone(),
            scope_set: tr
                .scope
                .as_deref()
                .map(|s| {
                    s.split(' ')
                        .filter(|x| !x.is_empty())
                        .map(str::to_string)
                        .collect::<Vec<_>>()
                })
                .unwrap_or_else(|| access_meta.scope_set.clone()),
            token_kind: TokenKind::Access,
            expires_at: new_expires_at,
            created_at: access_meta.created_at,
        };
        self.put_access_token(&new_access_meta, SecretValue::new(tr.access_token))?;

        // Step 7:如果 AS 返回了新 refresh token(rotation),更新 refresh 值
        // (metadata 的 refresh 条目需存在才能覆盖;若首次收到,本函数不主动创建 —— 由 caller 走 add-remote-mcp 流程首建)
        if let Some(new_refresh) = tr.refresh_token {
            if let Some(refresh_meta) = self.get_metadata(&refresh_token_ref)? {
                self.put_refresh_token(&refresh_meta, SecretValue::new(new_refresh))?;
            }
        }

        // Step 8:**记录完成时刻**(monotonic) —— 后续 caller 在 lock 内若发现
        // `last_completion >= my_arrival` 即短路,这是新 singleflight 不变量的写侧
        *sf_state = Some(Instant::now());

        Ok(true)
    }
}

/// raw SQLite 行 → typed `OAuthTokenMetadata` 的统一转换。
///
/// fail-closed 两处:
/// - 未知 `token_kind`(I10a R2 NICE-TO-HAVE 消化)
/// - `issuer IS NULL`(I10b-α1 ADR 0011 §α1-D1):legacy I10a 磁盘行升级后 issuer=NULL,
///   读侧拒绝返回,调用方必须重新走 auth flow 补齐 issuer。
fn row_to_typed(
    r: vigil_audit::vigil_http_auth_metadata::OAuthTokenMetadataRow,
) -> Result<OAuthTokenMetadata, HttpAuthError> {
    let kind = match r.token_kind.as_str() {
        "access" => TokenKind::Access,
        "refresh" => TokenKind::Refresh,
        _ => return Err(HttpAuthError::TokenStoreError("unknown_token_kind")),
    };
    let issuer = r
        .issuer
        .ok_or(HttpAuthError::TokenStoreError("issuer_missing_legacy_row"))?;
    Ok(OAuthTokenMetadata {
        token_ref: r.token_ref,
        resource: r.resource,
        authorization_server: r.authorization_server,
        issuer,
        scope_set: r.scope_set,
        token_kind: kind,
        expires_at: r.expires_at,
        created_at: r.created_at,
    })
}
