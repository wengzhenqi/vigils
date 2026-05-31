//! I10b-α2(ADR 0011 §α2-D3):真 HTTP JWKS 发现 + `(issuer, jwks_uri)` 双键缓存 +
//! **真 singleflight**(§I-11.6 不变量)。
//!
//! 发现链:
//! 1. `AS URL` → `GET {AS}/.well-known/oauth-authorization-server`(RFC 8414)→
//!    `AuthorizationServerMetadata { issuer, jwks_uri, ... }`
//! 2. `GET {jwks_uri}` → `JwkSet`
//!
//! 缓存 TTL:
//! - AS metadata:1h
//! - JWKS:10 min,`kid` miss 触发一次强制刷新
//!
//! **Singleflight 真实装**:对每个 `(issuer, jwks_uri)` 分配一个独立 `Arc<Mutex<()>>`
//! —— 同 key 并发 fetch 时,第一个 caller 持锁做网络 IO,其他 caller 阻塞在同一锁上;
//! 第一个完成后,其他读缓存即返(不再发网络请求)。分配 per-key Mutex 本身由外层
//! `state_mu` 串行化。

use std::collections::HashMap;
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};
use url::Url;

use vigil_http_auth::{HttpAuthError, HttpClient, HttpMethod, HttpRequest, JwkSet, JwksSource};

/// AS metadata(RFC 8414 子集)。Vigil 只消费与 α2 相关的字段。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthorizationServerMetadata {
    /// AS `issuer` —— JWT `iss` 精确等此值(§I-11.7)
    pub issuer: String,
    /// JWKS URI
    pub jwks_uri: String,
    /// `token_endpoint`(OAuth token exchange;α1 测试已用到)
    #[serde(default)]
    pub token_endpoint: Option<String>,
    /// `authorization_endpoint`
    #[serde(default)]
    pub authorization_endpoint: Option<String>,
    /// 支持的 response type
    #[serde(default)]
    pub response_types_supported: Vec<String>,
    /// 支持的 PKCE 方法(Vigil 要 `"S256"`)
    #[serde(default)]
    pub code_challenge_methods_supported: Vec<String>,
    /// RFC 7662 introspection(I10c 使用)
    #[serde(default)]
    pub introspection_endpoint: Option<String>,
}

type KeyPair = (String, String);

/// α2 真实装 `JwksSource`。
pub struct HttpJwksSource {
    http: Arc<dyn HttpClient>,
    state: Mutex<JwksCacheState>,
    as_metadata_ttl: Duration,
    jwks_ttl: Duration,
    // per-key singleflight 锁;state_mu 下分配,fetch IO 时持该锁(不持 state_mu)
    per_key_locks: Mutex<HashMap<KeyPair, Arc<Mutex<()>>>>,
    /// kid-miss 去抖窗口:若 `(issuer, jwks_uri)` 最近 < 此时长真刷过且 kid 仍 miss,
    /// 不再刷,直接 `JwksKidNotFound`。防止"kid 本就不存在"场景下无限循环刷。
    min_refresh_interval: Duration,
}

impl std::fmt::Debug for HttpJwksSource {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HttpJwksSource")
            .field("as_metadata_ttl", &self.as_metadata_ttl)
            .field("jwks_ttl", &self.jwks_ttl)
            .finish_non_exhaustive()
    }
}

#[derive(Default)]
struct JwksCacheState {
    as_metadata: HashMap<String, (AuthorizationServerMetadata, Instant)>,
    jwks: HashMap<KeyPair, JwksEntry>,
}

struct JwksEntry {
    set: Arc<JwkSet>,
    fetched_at: Instant,
    // 最后一次**真网络刷新**时间(与 fetched_at 同步,但语义化用于 kid-miss 去抖)
    last_network_fetch_at: Instant,
}

impl HttpJwksSource {
    /// 构造默认 TTL:AS metadata 1h,JWKS 10 min。
    pub fn new(http: Arc<dyn HttpClient>) -> Self {
        Self {
            http,
            state: Mutex::new(JwksCacheState::default()),
            as_metadata_ttl: Duration::from_secs(3600),
            jwks_ttl: Duration::from_secs(600),
            per_key_locks: Mutex::new(HashMap::new()),
            min_refresh_interval: Duration::from_secs(5),
        }
    }

    /// 发现 AS metadata(RFC 8414)。按 AS URL 缓存。
    ///
    /// `as_url` 例如 `"https://auth.example.com"` —— 内部拼 `/.well-known/oauth-authorization-server`。
    pub fn fetch_as_metadata(
        &self,
        as_url: &str,
    ) -> Result<Arc<AuthorizationServerMetadata>, HttpAuthError> {
        // 缓存命中?
        {
            let st = self.lock_state()?;
            if let Some((m, at)) = st.as_metadata.get(as_url) {
                if at.elapsed() < self.as_metadata_ttl {
                    return Ok(Arc::new(m.clone()));
                }
            }
        }
        let base: Url = as_url
            .parse()
            .map_err(|_| HttpAuthError::HttpError("invalid_as_url"))?;
        let discovery_url = base
            .join("/.well-known/oauth-authorization-server")
            .map_err(|_| HttpAuthError::HttpError("invalid_as_url"))?;
        let resp = self.http.send(&HttpRequest {
            url: discovery_url,
            method: HttpMethod::Get,
            headers: vec![("accept".into(), "application/json".into())],
            body: None,
        })?;
        if resp.status != 200 {
            return Err(HttpAuthError::HttpError("as_metadata_non_200"));
        }
        let meta: AuthorizationServerMetadata = serde_json::from_slice(&resp.body)
            .map_err(|_| HttpAuthError::HttpError("as_metadata_json_invalid"))?;
        if meta.issuer.is_empty() {
            return Err(HttpAuthError::HttpError("as_metadata_empty_issuer"));
        }
        if meta.jwks_uri.is_empty() {
            return Err(HttpAuthError::HttpError("as_metadata_empty_jwks_uri"));
        }
        let mut st = self.lock_state()?;
        st.as_metadata
            .insert(as_url.to_string(), (meta.clone(), Instant::now()));
        Ok(Arc::new(meta))
    }

    fn lock_state(&self) -> Result<MutexGuard<'_, JwksCacheState>, HttpAuthError> {
        self.state
            .lock()
            .map_err(|_| HttpAuthError::Internal("jwks_cache_lock_poisoned"))
    }

    /// 获取或创建 per-key singleflight 锁。**不**持有 state 锁做 IO。
    fn get_or_init_key_lock(&self, key: &KeyPair) -> Result<Arc<Mutex<()>>, HttpAuthError> {
        let mut map = self
            .per_key_locks
            .lock()
            .map_err(|_| HttpAuthError::Internal("jwks_key_locks_poisoned"))?;
        Ok(Arc::clone(
            map.entry(key.clone())
                .or_insert_with(|| Arc::new(Mutex::new(()))),
        ))
    }
}

impl JwksSource for HttpJwksSource {
    fn get(
        &self,
        issuer: &str,
        jwks_uri: &str,
        force_refresh_for_kid: Option<&str>,
    ) -> Result<Arc<JwkSet>, HttpAuthError> {
        let key: KeyPair = (issuer.to_string(), jwks_uri.to_string());

        // Step 1:无锁快速检查缓存(不触发 IO 且不需要 kid 强刷 → 立即返)。
        {
            let st = self.lock_state()?;
            if let Some(entry) = st.jwks.get(&key) {
                if entry.fetched_at.elapsed() < self.jwks_ttl {
                    match force_refresh_for_kid {
                        None => return Ok(Arc::clone(&entry.set)),
                        Some(kid) if entry.set.find_by_kid(kid).is_some() => {
                            return Ok(Arc::clone(&entry.set));
                        }
                        _ => {} // kid miss 或未找到 → 下面走 singleflight
                    }
                }
            }
        }

        // Step 2:获取 per-key singleflight 锁 —— 同 key 并发 caller 在此阻塞。
        //
        // I10b-α2 代码 R1 BLOCKER 1 修复:把网络 IO 严格串行化到 per-key Mutex。
        // 第一个 caller 持锁做 fetch;其他 caller 等到其释放后,在 Step 3 先读缓存
        // (此时已被 Step 2a 更新),命中即返,不再重复 IO。
        let key_lock = self.get_or_init_key_lock(&key)?;
        let _sf_guard = key_lock
            .lock()
            .map_err(|_| HttpAuthError::Internal("jwks_singleflight_poisoned"))?;

        // Step 3:拿到 singleflight 锁后,再次检查缓存
        // —— 可能已被前一个 caller 更新(合并并发 miss 的关键)。
        // 若 force_refresh_for_kid 仍 miss 但**刚真刷过** < min_refresh_interval,
        // 视作"kid 本就不存在",直接 JwksKidNotFound 避免所有并发 caller 都再刷。
        {
            let st = self.lock_state()?;
            if let Some(entry) = st.jwks.get(&key) {
                if entry.fetched_at.elapsed() < self.jwks_ttl {
                    match force_refresh_for_kid {
                        None => return Ok(Arc::clone(&entry.set)),
                        Some(kid) if entry.set.find_by_kid(kid).is_some() => {
                            return Ok(Arc::clone(&entry.set));
                        }
                        Some(_)
                            if entry.last_network_fetch_at.elapsed()
                                < self.min_refresh_interval =>
                        {
                            // 刚有人真刷过,仍无此 kid → 放弃(kid 本就不存在)
                            return Err(HttpAuthError::JwksKidNotFound);
                        }
                        _ => {}
                    }
                }
            }
        }

        // Step 4:真网络拉取(持 per-key 锁,**不**持 state 锁)
        let url: Url = jwks_uri
            .parse()
            .map_err(|_| HttpAuthError::HttpError("invalid_jwks_uri"))?;
        let resp = self.http.send(&HttpRequest {
            url,
            method: HttpMethod::Get,
            headers: vec![("accept".into(), "application/json".into())],
            body: None,
        })?;
        if resp.status != 200 {
            return Err(HttpAuthError::HttpError("jwks_non_200"));
        }
        let set: JwkSet = serde_json::from_slice(&resp.body)
            .map_err(|_| HttpAuthError::HttpError("jwks_json_invalid"))?;
        let arc_set = Arc::new(set);

        // Step 5:更新缓存(同时记录 last_network_fetch_at 以驱动 kid-miss 去抖)
        {
            let mut st = self.lock_state()?;
            let now = Instant::now();
            st.jwks.insert(
                key.clone(),
                JwksEntry {
                    set: Arc::clone(&arc_set),
                    fetched_at: now,
                    last_network_fetch_at: now,
                },
            );
        }

        // Step 6:若是 kid miss 强刷,刷后仍找不到 → fail-closed
        if let Some(kid) = force_refresh_for_kid {
            if arc_set.find_by_kid(kid).is_none() {
                return Err(HttpAuthError::JwksKidNotFound);
            }
        }
        Ok(arc_set)
    }
}
