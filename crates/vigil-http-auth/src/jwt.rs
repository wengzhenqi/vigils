//! JWT access token decode + claim 校验(ADR 0010 §D5 / ADR 0011 §α1-D3)。
//!
//! I10b-α1 起:
//! - `decode_jwt_access_token` 额外返 `JoseHeader`,便于签名验证 (`alg/kid/typ`)
//! - `DecodedAccessToken.iss` 作为 decode 容器(**可缺失**),消费侧在
//!   `TokenStore::resolve_access_token` 把 None 映射到稳定 reason code
//! - **签名验证**通过 `trait JwtKeyVerifier` 注入;I10b-α2 起唯一生产实装
//!   `JwksSignatureVerifier`,α1 测试走 `tests/common::AlwaysAcceptVerifier` 夹具
//!
//! ADR 0011 §I-11.2 不变量:签名验证失败 / `kid` 不存在 / `alg` 不在白名单 → fail-closed。

use std::sync::Arc;

use serde::Deserialize;
use vigil_lease::SecretValue;

use crate::error::HttpAuthError;
use crate::types::{ResolvedAccessToken, SCOPES_CLAIM_DELIMITER};

/// JOSE header(JWT `header` 段 base64url-decode + JSON parse)。
/// α1 定义 + 承诺稳定,α2 的 `JwksSignatureVerifier` 按它做 key lookup。
#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
pub struct JoseHeader {
    /// 签名算法名,例如 `"RS256"` / `"ES256"` / `"none"`
    #[serde(default)]
    pub alg: String,
    /// key ID;α2 的 JWKS 发现用此索引;α1 `AlwaysAcceptVerifier` 忽略
    #[serde(default)]
    pub kid: Option<String>,
    /// token 类型;RFC 8725 SHOULD `"JWT"`;缺失可接受(ADR 0011 NICE-TO-HAVE 2)
    #[serde(default)]
    pub typ: Option<String>,
}

/// JWT 签名验证抽象(ADR 0011 §α1-D3)。
///
/// **生产路径唯一实装**:`JwksSignatureVerifier`(α2 在 `vigil-http-transport` 落)。
/// **测试夹具**:`tests/common::AlwaysAcceptVerifier`(integration test crate 本地,
/// **非** crate pub API,**非** feature,prod build 根本看不到)。
pub trait JwtKeyVerifier: Send + Sync + std::fmt::Debug {
    /// 对 **已 decode 的 header + raw JWT string** 做签名验证;成功返 `Ok(())`。
    ///
    /// 失败应返回:
    /// - `HttpAuthError::JwtAlgRejected(reason)` — alg 不在白名单
    /// - `HttpAuthError::JwksKidNotFound` — kid 不在 JwkSet
    /// - `HttpAuthError::JwtSignatureInvalid` — 签名本身无效
    fn verify(
        &self,
        raw_jwt: &str,
        header: &JoseHeader,
        expected_issuer: &str,
    ) -> Result<(), HttpAuthError>;
}

/// 上层 sealed API(`TokenStore::resolve_access_token`)的入参封装。
///
/// I10b-α1(ADR 0011 §α1-D3):`key_verifier` **必填**(非 Option)——
/// 生产 DTO 上留可空 verifier 等于留"合法不验签路径",直接回潮 BLOCKER 3。
///
/// # `key_verifier` 必填 —— 编译期守门(代码 R1 MUST-FIX)
///
/// 传 `None` 或省略字段会编译失败,证明"必填"不只是文字约定:
///
/// ```compile_fail
/// use vigil_http_auth::ExpectedBinding;
/// // 缺 key_verifier 字段 → 编译失败(missing field `key_verifier`)
/// let _bad = ExpectedBinding {
///     resource: "https://mcp.example.com/".to_string(),
///     issuer: "https://auth.example.com".to_string(),
///     scopes: vec![],
///     introspection: None,
/// };
/// ```
///
/// ```compile_fail
/// use vigil_http_auth::ExpectedBinding;
/// // `None` 语法对非 Option 字段 → 编译失败(expected Arc<dyn JwtKeyVerifier>)
/// let _bad = ExpectedBinding {
///     resource: "https://mcp.example.com/".to_string(),
///     issuer: "https://auth.example.com".to_string(),
///     scopes: vec![],
///     key_verifier: None,
///     introspection: None,
/// };
/// ```
#[derive(Clone)]
pub struct ExpectedBinding {
    /// PRM `resource_base` —— JWT `aud` / `resource` 必等此
    pub resource: String,
    /// AS metadata `issuer` —— JWT `iss` 必精确等此
    pub issuer: String,
    /// caller 请求的 scope 集合(token 必须全覆盖)
    pub scopes: Vec<String>,
    /// 签名验证器(必填):α1 test 夹具 `AlwaysAcceptVerifier`;α2 `JwksSignatureVerifier`
    pub key_verifier: Arc<dyn JwtKeyVerifier>,
    /// I10c-α2(ADR 0011 §8):opaque token 回退路径。
    ///
    /// `None`(常态):token 必须是 JWT 格式,非 JWT 直接返 `UnsupportedTokenFormat`。
    /// `Some(cfg)`:若 token 非 JWT(`.` 数 != 2 或不可 base64url decode),
    /// caller 走 RFC 7662 introspection 验证 `active/aud/scope/exp/iss`。
    ///
    /// JWT 路径不受 `introspection` 影响(已由 `key_verifier` 把关)。
    pub introspection: Option<IntrospectionConfig>,
}

/// I10c-α2 opaque token introspection 配置(RFC 7662)。
///
/// **安全约束**(见 `IntrospectionConfig::new`):
/// - `introspection_endpoint` 必须 `https://` 或 loopback(token / client_secret 明文)
/// - `client_id` 必需;`client_secret_ref` 指向 SecretStore 里的 client secret
///   (key 由 caller 构造,例如 `client://oauth/<sha256(issuer)>/<client_id>`)
#[derive(Clone)]
pub struct IntrospectionConfig {
    pub(crate) endpoint: url::Url,
    pub(crate) client_id: String,
    pub(crate) client_secret_ref: String,
    pub(crate) http: Arc<dyn crate::client::HttpClient>,
    /// I10c-α3:introspection 响应缓存最大 TTL(秒)。
    /// 实际 TTL = `min(response.exp - now, cache_max_ttl_secs, HARD_CAP)`。
    /// 默认 60s;`0` 关闭缓存。
    pub(crate) cache_max_ttl_secs: u64,
}

/// I10c-α3:introspection 缓存 TTL 硬上限(秒)。
/// 即使 `cache_max_ttl_secs` 或 token `exp` 给了更大值,也不允许超过此上限,
/// 避免缓存脏到 token rotation / 政策变化后仍被使用。
pub(crate) const INTROSPECTION_CACHE_HARD_CAP_SECS: u64 = 300;
/// I10c-α3:`IntrospectionConfig::new` 不显式配置时的默认 TTL(秒)。
pub(crate) const INTROSPECTION_CACHE_DEFAULT_TTL_SECS: u64 = 60;

impl IntrospectionConfig {
    /// 构造 —— 强制 `endpoint` 为 https 或 loopback(与 `AutoRefreshConfig::new` 同语义)。
    /// 缓存 TTL 默认 60s(上限 300s 见 [`INTROSPECTION_CACHE_HARD_CAP_SECS`]);
    /// 如需自定义 / 关闭,用 [`IntrospectionConfig::with_cache_max_ttl_secs`]。
    pub fn new(
        endpoint: url::Url,
        client_id: impl Into<String>,
        client_secret_ref: impl Into<String>,
        http: Arc<dyn crate::client::HttpClient>,
    ) -> Result<Self, HttpAuthError> {
        if !is_safe_endpoint(&endpoint) {
            return Err(HttpAuthError::HttpError(
                "introspection_endpoint_must_be_https_or_loopback",
            ));
        }
        Ok(Self {
            endpoint,
            client_id: client_id.into(),
            client_secret_ref: client_secret_ref.into(),
            http,
            cache_max_ttl_secs: INTROSPECTION_CACHE_DEFAULT_TTL_SECS,
        })
    }

    /// I10c-α3:覆盖缓存 TTL。`0` 关闭缓存;值大于 [`INTROSPECTION_CACHE_HARD_CAP_SECS`]
    /// 时自动 clamp 到上限,避免缓存脏到 token rotation 后仍被使用。
    pub fn with_cache_max_ttl_secs(mut self, secs: u64) -> Self {
        self.cache_max_ttl_secs = secs.min(INTROSPECTION_CACHE_HARD_CAP_SECS);
        self
    }

    /// 供 `TokenStore::resolve_access_token` 内部只读访问。
    pub(crate) fn endpoint(&self) -> &url::Url {
        &self.endpoint
    }
    pub(crate) fn client_id(&self) -> &str {
        &self.client_id
    }
    pub(crate) fn client_secret_ref(&self) -> &str {
        &self.client_secret_ref
    }
    pub(crate) fn http(&self) -> &dyn crate::client::HttpClient {
        &*self.http
    }
    pub(crate) fn cache_max_ttl_secs(&self) -> u64 {
        self.cache_max_ttl_secs
    }
}

impl std::fmt::Debug for IntrospectionConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("IntrospectionConfig")
            .field("endpoint", &self.endpoint.as_str())
            .field("client_id", &self.client_id)
            // client_secret_ref 是 SecretStore key,不打印 value;key 本身非 secret
            .field("client_secret_ref_len", &self.client_secret_ref.len())
            .finish_non_exhaustive()
    }
}

/// 判定 endpoint 是否允许(https 或 loopback),与 `AutoRefreshConfig::new` 同语义。
fn is_safe_endpoint(url: &url::Url) -> bool {
    match url.scheme() {
        "https" => true,
        "http" => {
            let host = url.host_str().unwrap_or("");
            matches!(host, "127.0.0.1" | "::1") || host.eq_ignore_ascii_case("localhost")
        }
        _ => false,
    }
}

impl std::fmt::Debug for ExpectedBinding {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // key_verifier 作为 trait object 打印 backend 类型而非内容
        f.debug_struct("ExpectedBinding")
            .field("resource", &self.resource)
            .field("issuer", &self.issuer)
            .field("scopes", &self.scopes)
            .field("key_verifier", &self.key_verifier)
            .field("introspection", &self.introspection)
            .finish()
    }
}

/// JWT payload 的 Vigil 视图(最小字段集)。
#[derive(Debug, Clone, Deserialize)]
pub struct DecodedAccessToken {
    /// `iss` claim(I10b-α1 新增)。**可缺失** 仅作 decode 容器;消费侧
    /// `TokenStore::resolve_access_token` 把 `None` 映射到
    /// `HttpAuthError::TokenRejectedWrongIssuer { actual: "(missing)" }`。
    #[serde(default)]
    pub iss: Option<String>,
    /// `aud` claim(单值或数组;此字段收 single;数组时 caller 拆)
    #[serde(default)]
    pub aud: Option<serde_json::Value>,
    /// RFC 8707 `resource` claim(可选,有则优先)
    #[serde(default)]
    pub resource: Option<String>,
    /// OAuth `scope`(空格分隔 string)
    #[serde(default)]
    pub scope: Option<String>,
    /// `exp` Unix 秒
    #[serde(default)]
    pub exp: Option<i64>,
}

impl DecodedAccessToken {
    /// 解析 `aud` 返标准化 Vec<String>:
    /// - single string → vec![s]
    /// - array<string> → 原样
    /// - 其他 → 空 vec
    pub fn audience(&self) -> Vec<String> {
        match &self.aud {
            Some(serde_json::Value::String(s)) => vec![s.clone()],
            Some(serde_json::Value::Array(arr)) => arr
                .iter()
                .filter_map(|v| v.as_str().map(String::from))
                .collect(),
            _ => Vec::new(),
        }
    }

    /// 空格分隔的 scope → Vec。
    pub fn scope_set(&self) -> Vec<String> {
        self.scope
            .as_deref()
            .map(|s| {
                s.split(SCOPES_CLAIM_DELIMITER)
                    .filter(|t| !t.is_empty())
                    .map(String::from)
                    .collect()
            })
            .unwrap_or_default()
    }
}

/// Decode 一个 JWT access token string 的 **header + payload**(I10a 不验签;
/// I10b-α1 起 caller 应把 `JoseHeader` 传给 `JwtKeyVerifier` 做签名验证)。
///
/// 返 `UnsupportedTokenFormat` 若 token 不是 JWT(不含两个 `.` 或任一段非 base64url)。
/// 返 `JwtDecodeFailed` 若 header / payload 不是合法 JSON。
pub fn decode_jwt_access_token(
    token: &str,
) -> Result<(JoseHeader, DecodedAccessToken), HttpAuthError> {
    // JWT 格式:header.payload.signature,3 段用 `.` 分隔
    let parts: Vec<&str> = token.split('.').collect();
    if parts.len() != 3 {
        return Err(HttpAuthError::UnsupportedTokenFormat);
    }
    use base64::Engine;
    let engine = base64::engine::general_purpose::URL_SAFE_NO_PAD;
    let header_bytes = engine
        .decode(parts[0])
        .map_err(|_| HttpAuthError::UnsupportedTokenFormat)?;
    let header: JoseHeader =
        serde_json::from_slice(&header_bytes).map_err(|_| HttpAuthError::JwtDecodeFailed)?;
    let payload_bytes = engine
        .decode(parts[1])
        .map_err(|_| HttpAuthError::UnsupportedTokenFormat)?;
    let payload: DecodedAccessToken =
        serde_json::from_slice(&payload_bytes).map_err(|_| HttpAuthError::JwtDecodeFailed)?;
    Ok((header, payload))
}

/// 取 JWT raw string + PRM resource + requested scopes,返 `ResolvedAccessToken`。
///
/// 校验链(ADR §I-10.5 §I-10.6):
/// 1. decode(unsecure)
/// 2. 若 `resource` claim 存在 → 用它对比;否则用 `aud` 任一项对比
/// 3. aud/resource 必须等于 `expected_resource`(字符串完全匹配),否则 `AudienceMismatch`
/// 4. `exp` 若存在且 `< now`,返 `TokenExpired`
/// 5. 请求的每个 scope 必须在 JWT `scope` claim 中,否则 `ScopeMissing`
///
/// I10b-α1 代码 R1 BLOCKER 修复:改 `pub(crate)` —— 不再对下游 crate 暴露。
/// 下游**唯一**生产入口是 sealed `TokenStore::resolve_access_token(&ExpectedBinding, ...)`,
/// 这样 `issuer + verifier` 绑定不可绕过。本函数只给 `store.rs` 内部复用
/// aud/resource/scope/exp 校验逻辑。
pub(crate) fn validate_and_resolve_access_token(
    raw_token: SecretValue,
    expected_resource: &str,
    requested_scopes: &[String],
    now_unix_secs: i64,
) -> Result<ResolvedAccessToken, HttpAuthError> {
    let (_header, decoded) = decode_jwt_access_token(raw_token.expose())?;

    // resource / aud 校验
    let actual_resource = if let Some(r) = decoded.resource.as_deref() {
        r.to_string()
    } else {
        let auds = decoded.audience();
        if auds.is_empty() {
            return Err(HttpAuthError::AudienceMismatch {
                expected: expected_resource.to_string(),
                actual: String::new(),
            });
        }
        // 若 aud 数组含 expected_resource 视为匹配
        if auds.iter().any(|a| a == expected_resource) {
            expected_resource.to_string()
        } else {
            return Err(HttpAuthError::AudienceMismatch {
                expected: expected_resource.to_string(),
                actual: auds.join(","),
            });
        }
    };
    if actual_resource != expected_resource {
        return Err(HttpAuthError::AudienceMismatch {
            expected: expected_resource.to_string(),
            actual: actual_resource,
        });
    }

    // exp
    if let Some(exp) = decoded.exp {
        if exp <= now_unix_secs {
            return Err(HttpAuthError::TokenExpired);
        }
    }

    // scope
    let token_scopes = decoded.scope_set();
    for req_scope in requested_scopes {
        if !token_scopes.iter().any(|t| t == req_scope) {
            return Err(HttpAuthError::ScopeMissing(req_scope.clone()));
        }
    }

    Ok(ResolvedAccessToken {
        raw: raw_token,
        resource: actual_resource,
        scope_set: token_scopes,
        expires_at: decoded.exp,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::Engine;

    /// 构造一个简化的 JWT(header 占位,payload 为给定 JSON,signature 占位)。
    fn mk_jwt(payload: &serde_json::Value) -> String {
        let engine = base64::engine::general_purpose::URL_SAFE_NO_PAD;
        let header = engine.encode(br#"{"alg":"none","typ":"JWT"}"#);
        let payload_bytes = serde_json::to_vec(payload).unwrap();
        let payload = engine.encode(&payload_bytes);
        let sig = engine.encode(b"sig");
        format!("{header}.{payload}.{sig}")
    }

    #[test]
    fn decode_parses_header_aud_scope_exp_iss() {
        let token = mk_jwt(&serde_json::json!({
            "iss": "https://auth.example.com",
            "aud": "https://mcp.example.com/",
            "scope": "mcp:tools.read mcp:tools.write",
            "exp": 1_700_000_000
        }));
        let (header, d) = decode_jwt_access_token(&token).unwrap();
        assert_eq!(header.alg, "none");
        assert_eq!(header.typ.as_deref(), Some("JWT"));
        assert_eq!(d.iss.as_deref(), Some("https://auth.example.com"));
        assert_eq!(d.audience(), vec!["https://mcp.example.com/".to_string()]);
        assert_eq!(
            d.scope_set(),
            vec!["mcp:tools.read".to_string(), "mcp:tools.write".to_string()]
        );
        assert_eq!(d.exp, Some(1_700_000_000));
    }

    #[test]
    fn opaque_token_returns_unsupported_format() {
        let err = decode_jwt_access_token("just_an_opaque_string_no_dots").unwrap_err();
        assert_eq!(err, HttpAuthError::UnsupportedTokenFormat);
    }

    #[test]
    fn validate_resource_match_and_scope() {
        let token = mk_jwt(&serde_json::json!({
            "aud": "https://mcp.example.com/",
            "scope": "mcp:tools.read",
            "exp": 9_999_999_999i64
        }));
        let resolved = validate_and_resolve_access_token(
            SecretValue::new(token),
            "https://mcp.example.com/",
            &["mcp:tools.read".to_string()],
            1_700_000_000,
        )
        .unwrap();
        assert_eq!(resolved.resource, "https://mcp.example.com/");
    }

    #[test]
    fn wrong_resource_rejected_when_jwt_aud_mismatches_prm_resource() {
        let token = mk_jwt(&serde_json::json!({
            "aud": "https://other.example.com/",
            "scope": "mcp:tools.read",
            "exp": 9_999_999_999i64
        }));
        let err = validate_and_resolve_access_token(
            SecretValue::new(token),
            "https://mcp.example.com/",
            &["mcp:tools.read".to_string()],
            1_700_000_000,
        )
        .unwrap_err();
        assert!(matches!(err, HttpAuthError::AudienceMismatch { .. }));
    }

    #[test]
    fn resource_claim_takes_precedence_over_aud() {
        let token = mk_jwt(&serde_json::json!({
            "aud": "https://other.example.com/",
            "resource": "https://mcp.example.com/",
            "scope": "mcp:tools.read",
            "exp": 9_999_999_999i64
        }));
        let resolved = validate_and_resolve_access_token(
            SecretValue::new(token),
            "https://mcp.example.com/",
            &["mcp:tools.read".to_string()],
            1_700_000_000,
        )
        .unwrap();
        assert_eq!(resolved.resource, "https://mcp.example.com/");
    }

    #[test]
    fn jwt_expired_returns_token_expired() {
        let token = mk_jwt(&serde_json::json!({
            "aud": "https://mcp.example.com/",
            "scope": "mcp:tools.read",
            "exp": 1_700_000_000i64
        }));
        let err = validate_and_resolve_access_token(
            SecretValue::new(token),
            "https://mcp.example.com/",
            &["mcp:tools.read".to_string()],
            1_800_000_000,
        )
        .unwrap_err();
        assert_eq!(err, HttpAuthError::TokenExpired);
    }

    #[test]
    fn missing_scope_returns_scope_missing() {
        let token = mk_jwt(&serde_json::json!({
            "aud": "https://mcp.example.com/",
            "scope": "mcp:tools.read",
            "exp": 9_999_999_999i64
        }));
        let err = validate_and_resolve_access_token(
            SecretValue::new(token),
            "https://mcp.example.com/",
            &["mcp:tools.write".to_string()],
            1_700_000_000,
        )
        .unwrap_err();
        match err {
            HttpAuthError::ScopeMissing(s) => assert_eq!(s, "mcp:tools.write"),
            other => panic!("expected ScopeMissing, got {other:?}"),
        }
    }
}
