//! OAuth 2.1 + PKCE S256 核心(ADR 0010 §D2)。
//!
//! 用 `oauth2` crate 的 PKCE 类型做 verifier/challenge,手动构造 authorize URL
//! 和 token exchange HTTP POST —— 避免拉入 `oauth2` crate 的 reqwest 依赖
//! (I10a 只走 `HttpClient` trait)。
//!
//! **不在 I10a 范围**:loopback redirect server、PAR(RFC 9126)、refresh flow、
//! client authentication(client_secret / private_key_jwt)。

use oauth2::{CsrfToken, PkceCodeChallenge, PkceCodeVerifier};
use serde::Deserialize;
use url::Url;

use crate::client::{HttpClient, HttpMethod, HttpRequest};
use crate::error::HttpAuthError;

/// PKCE 挑战对:verifier 本地保留直到 token exchange,challenge 发给 AS。
pub struct PkcePair {
    /// RFC 7636 code verifier(长度 43-128,URL-safe)
    pub verifier: PkceCodeVerifier,
    /// S256 challenge + method `"S256"`
    pub challenge: PkceCodeChallenge,
}

impl std::fmt::Debug for PkcePair {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // verifier 不印(是 secret);challenge 是 hash 公开值
        f.debug_struct("PkcePair")
            .field("challenge_method", &"S256")
            .finish_non_exhaustive()
    }
}

/// 生成新的 PKCE 挑战对(S256)。
pub fn new_pkce_pair() -> PkcePair {
    let (challenge, verifier) = PkceCodeChallenge::new_random_sha256();
    PkcePair {
        verifier,
        challenge,
    }
}

/// 构造 authorization request URL(RFC 6749 + PKCE + RFC 8707 resource indicator)。
///
/// 参数顺序按 RFC 6749 4.1.1;`resource` 从 PRM 取,**必须**作为 `resource` 参数附上,
/// 否则 AS 可能签发不带 audience 绑定的 token,破坏 §I-10.6。
pub fn build_authorization_url(
    authorization_endpoint: &Url,
    client_id: &str,
    redirect_uri: &Url,
    scopes: &[String],
    state: &CsrfToken,
    challenge: &PkceCodeChallenge,
    resource: &Url,
) -> Result<Url, HttpAuthError> {
    let mut url = authorization_endpoint.clone();
    let scope_joined = scopes.join(" ");
    {
        let mut q = url.query_pairs_mut();
        q.append_pair("response_type", "code");
        q.append_pair("client_id", client_id);
        q.append_pair("redirect_uri", redirect_uri.as_str());
        q.append_pair("scope", &scope_joined);
        q.append_pair("state", state.secret());
        q.append_pair("code_challenge", challenge.as_str());
        q.append_pair("code_challenge_method", "S256");
        q.append_pair("resource", resource.as_str());
    }
    Ok(url)
}

/// AS 的 token endpoint 返回(OAuth 2.0 token response;取最小字段)。
#[derive(Debug, Clone, Deserialize)]
pub struct TokenResponse {
    /// access token(JWT 或 opaque,I10a 只支持 JWT)
    pub access_token: String,
    /// `Bearer`
    #[serde(default)]
    pub token_type: Option<String>,
    /// 秒;None 表示不指定过期(按 JWT `exp` 决定)
    #[serde(default)]
    pub expires_in: Option<i64>,
    /// 可选 refresh token
    #[serde(default)]
    pub refresh_token: Option<String>,
    /// 实际签发的 scope(空格分隔 string)
    #[serde(default)]
    pub scope: Option<String>,
}

/// 用 PKCE verifier 兑换 access token(RFC 6749 4.1.3 + RFC 8707 resource indicator)。
///
/// 构造 `application/x-www-form-urlencoded` POST body,经 `HttpClient` 发给
/// `token_endpoint`;响应按 2xx JSON 解析为 `TokenResponse`;非 2xx 视为 `HttpError`。
pub fn exchange_code_for_token(
    client: &dyn HttpClient,
    token_endpoint: &Url,
    client_id: &str,
    redirect_uri: &Url,
    code: &str,
    verifier: &PkceCodeVerifier,
    resource: &Url,
) -> Result<TokenResponse, HttpAuthError> {
    // 手动组装 form body —— 用 form_urlencoded crate 不值当,自己 encode 即可
    let body = form_urlencode(&[
        ("grant_type", "authorization_code"),
        ("code", code),
        ("redirect_uri", redirect_uri.as_str()),
        ("client_id", client_id),
        ("code_verifier", verifier.secret()),
        ("resource", resource.as_str()),
    ]);
    let resp = client.send(&HttpRequest {
        url: token_endpoint.clone(),
        method: HttpMethod::PostForm,
        headers: vec![(
            "Content-Type".to_string(),
            "application/x-www-form-urlencoded".to_string(),
        )],
        body: Some(body.into_bytes()),
    })?;
    if !(200..300).contains(&resp.status) {
        return Err(HttpAuthError::HttpError("token_endpoint_non_2xx"));
    }
    let tr: TokenResponse = serde_json::from_slice(&resp.body)
        .map_err(|_| HttpAuthError::HttpError("token_response_malformed_json"))?;
    // Codex R1 MUST-FIX:若 response 声明了 token_type,必须 eq_ignore_ascii_case "Bearer"。
    // ADR §D3 已强制 PRM.bearer_methods_supported 含 "header",此处 token_type 一致性守;
    // `token_type=None` 宽容接受(RFC 6749 建议但非强制,真实 AS 偶尔省略)。
    if let Some(ref tt) = tr.token_type {
        if !tt.eq_ignore_ascii_case("Bearer") {
            return Err(HttpAuthError::HttpError("token_type_not_bearer"));
        }
    }
    Ok(tr)
}

/// I10c-α1(ADR 0011 §6 refresh flow):用 refresh token 换新 access token(RFC 6749 §6 +
/// RFC 8707 resource indicator)。
///
/// **安全约束**:
/// - refresh token 本身是 **secret**,本函数入参 `&str` 只做一次性传递,caller 负责从
///   `SecretStore` 取出 + 不留 log / audit
/// - `resource` 必须与原 access token 的 `resource` 一致 —— 否则 AS 可能签发不绑 audience
///   的 token,破坏 §I-10.6 audience 绑定不变量
/// - `client_id` 用 public client 形态(无 secret);I10c-α2 再支持 confidential client
/// - 响应的 `token_type` 校验与 `exchange_code_for_token` 一致
pub fn exchange_refresh_token_for_token(
    client: &dyn HttpClient,
    token_endpoint: &Url,
    client_id: &str,
    refresh_token: &str,
    resource: &Url,
) -> Result<TokenResponse, HttpAuthError> {
    let body = form_urlencode(&[
        ("grant_type", "refresh_token"),
        ("refresh_token", refresh_token),
        ("client_id", client_id),
        ("resource", resource.as_str()),
    ]);
    let resp = client.send(&HttpRequest {
        url: token_endpoint.clone(),
        method: HttpMethod::PostForm,
        headers: vec![(
            "Content-Type".to_string(),
            "application/x-www-form-urlencoded".to_string(),
        )],
        body: Some(body.into_bytes()),
    })?;
    if !(200..300).contains(&resp.status) {
        return Err(HttpAuthError::HttpError("refresh_endpoint_non_2xx"));
    }
    let tr: TokenResponse = serde_json::from_slice(&resp.body)
        .map_err(|_| HttpAuthError::HttpError("refresh_response_malformed_json"))?;
    if let Some(ref tt) = tr.token_type {
        if !tt.eq_ignore_ascii_case("Bearer") {
            return Err(HttpAuthError::HttpError("token_type_not_bearer"));
        }
    }
    Ok(tr)
}

/// I10c-α2(ADR 0011 §8 opaque):RFC 7662 Token Introspection 响应。
///
/// 只收 Vigil 消费的字段;额外字段由 AS 扩展,我们不使用。
#[derive(Debug, Clone, Deserialize)]
pub struct IntrospectionResponse {
    /// **核心** — token 是否仍然有效(RFC 7662 §2.2)
    pub active: bool,
    /// scope(空格分隔 string)
    #[serde(default)]
    pub scope: Option<String>,
    /// 截止时间(Unix 秒)
    #[serde(default)]
    pub exp: Option<i64>,
    /// AS issuer
    #[serde(default)]
    pub iss: Option<String>,
    /// audience —— 可能是 string 或 array
    #[serde(default)]
    pub aud: Option<serde_json::Value>,
    /// username(可选,不消费)
    #[serde(default)]
    pub username: Option<String>,
    /// token_type(通常 Bearer)
    #[serde(default)]
    pub token_type: Option<String>,
}

impl IntrospectionResponse {
    /// 规范化 aud → Vec<String>(与 `DecodedAccessToken::audience` 语义一致)。
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
}

/// I10c-α2(ADR 0011 §8):RFC 7662 opaque token introspection。
///
/// 用 HTTP Basic auth(`client_secret_basic`)认证 client,发 `POST` form:
/// `token=<opaque>&token_type_hint=access_token`。
///
/// **安全约束**:
/// - `introspection_endpoint` 必须 `https://` 或 loopback(token / client_secret 都是
///   明文,绝不允许公网 http)—— 由 caller 构造时 gate(见 `IntrospectionConfig::new`)
/// - response 的 `active=false` → `TokenExpired`(token 已吊销或过期);caller 走 refresh
/// - 响应字段以 `exp/aud/iss/scope` 为准,不回看 opaque token 本身的"payload"(它**没有** payload)
/// - `token_type` 若存在必须 `Bearer`(与 JWT 路径对齐)
pub fn introspect_token(
    client: &dyn HttpClient,
    introspection_endpoint: &Url,
    client_id: &str,
    client_secret: &str,
    token: &str,
) -> Result<IntrospectionResponse, HttpAuthError> {
    use base64::Engine;
    let body = form_urlencode(&[("token", token), ("token_type_hint", "access_token")]);
    // client_secret_basic(RFC 6749 §2.3.1 + RFC 7617):
    // - `client_id` / `client_secret` **必须**先做 `application/x-www-form-urlencoded`
    //   编码(防 `:` / 空格 / `%` 等保留字符与 Basic Auth 分隔符歧义 / AS 互操作失败)
    // - 再用单个 `:` 拼接,整体 base64 放 `Authorization: Basic <...>`
    //
    // I10c-α2 R1 BLOCKER 修复:之前直接 base64(`client_id:client_secret`)不符合
    // RFC 6749 §2.3.1,client_id 含保留字符时与 AS 实现对不上。
    let encoded_id = percent_encode(client_id);
    let encoded_secret = percent_encode(client_secret);
    let basic =
        base64::engine::general_purpose::STANDARD.encode(format!("{encoded_id}:{encoded_secret}"));
    let resp = client.send(&HttpRequest {
        url: introspection_endpoint.clone(),
        method: HttpMethod::PostForm,
        headers: vec![
            (
                "Content-Type".to_string(),
                "application/x-www-form-urlencoded".to_string(),
            ),
            ("Authorization".to_string(), format!("Basic {basic}")),
        ],
        body: Some(body.into_bytes()),
    })?;
    if !(200..300).contains(&resp.status) {
        return Err(HttpAuthError::HttpError("introspection_non_2xx"));
    }
    let ir: IntrospectionResponse = serde_json::from_slice(&resp.body)
        .map_err(|_| HttpAuthError::HttpError("introspection_response_malformed_json"))?;
    if let Some(ref tt) = ir.token_type {
        if !tt.eq_ignore_ascii_case("Bearer") {
            return Err(HttpAuthError::HttpError("token_type_not_bearer"));
        }
    }
    Ok(ir)
}

fn form_urlencode(pairs: &[(&str, &str)]) -> String {
    pairs
        .iter()
        .map(|(k, v)| format!("{}={}", percent_encode(k), percent_encode(v)))
        .collect::<Vec<_>>()
        .join("&")
}

/// 简化的 percent-encoding(application/x-www-form-urlencoded)。
fn percent_encode(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' => {
                out.push(b as char);
            }
            b' ' => out.push('+'),
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::client::{HttpResponse, MockHttpClient};

    #[test]
    fn build_authorization_url_contains_required_params() {
        let pkce = new_pkce_pair();
        let state = CsrfToken::new_random();
        let url = build_authorization_url(
            &"https://auth.example.com/authorize".parse().unwrap(),
            "client-123",
            &"http://127.0.0.1:9876/callback".parse().unwrap(),
            &["mcp:tools.read".into(), "mcp:tools.write".into()],
            &state,
            &pkce.challenge,
            &"https://mcp.example.com/".parse().unwrap(),
        )
        .unwrap();
        let s = url.as_str();
        for expected in [
            "response_type=code",
            "client_id=client-123",
            "redirect_uri=http",
            "code_challenge_method=S256",
            "resource=https",
        ] {
            assert!(s.contains(expected), "missing {expected} in {s}");
        }
    }

    #[test]
    fn exchange_code_success_returns_token_response() {
        let m = MockHttpClient::new();
        m.register(
            HttpMethod::PostForm,
            "https://auth.example.com/token",
            HttpResponse {
                status: 200,
                body: br#"{"access_token":"jwt.body.sig","token_type":"Bearer","expires_in":3600,"scope":"mcp:tools.read"}"#.to_vec(),
            },
        );
        let pkce = new_pkce_pair();
        let tr = exchange_code_for_token(
            &m,
            &"https://auth.example.com/token".parse().unwrap(),
            "client-123",
            &"http://127.0.0.1:9876/callback".parse().unwrap(),
            "AUTH_CODE_XYZ",
            &pkce.verifier,
            &"https://mcp.example.com/".parse().unwrap(),
        )
        .unwrap();
        assert_eq!(tr.access_token, "jwt.body.sig");
        assert_eq!(tr.token_type.as_deref(), Some("Bearer"));
        assert_eq!(tr.expires_in, Some(3600));
        assert_eq!(tr.scope.as_deref(), Some("mcp:tools.read"));
    }

    /// Codex R1 MUST-FIX:token_type 非 Bearer → fail-closed
    #[test]
    fn exchange_code_rejects_non_bearer_token_type() {
        let m = MockHttpClient::new();
        m.register(
            HttpMethod::PostForm,
            "https://auth.example.com/token",
            HttpResponse {
                status: 200,
                body: br#"{"access_token":"jwt.x.y","token_type":"Mac","expires_in":3600}"#
                    .to_vec(),
            },
        );
        let pkce = new_pkce_pair();
        let err = exchange_code_for_token(
            &m,
            &"https://auth.example.com/token".parse().unwrap(),
            "c",
            &"http://127.0.0.1/cb".parse().unwrap(),
            "CODE",
            &pkce.verifier,
            &"https://mcp.example.com/".parse().unwrap(),
        )
        .unwrap_err();
        assert_eq!(err, HttpAuthError::HttpError("token_type_not_bearer"));
    }

    #[test]
    fn exchange_code_accepts_missing_token_type() {
        // OAuth 规范"推荐"返 token_type,但现实中有 AS 省略;I10a 宽容
        let m = MockHttpClient::new();
        m.register(
            HttpMethod::PostForm,
            "https://auth.example.com/token",
            HttpResponse {
                status: 200,
                body: br#"{"access_token":"jwt.x.y"}"#.to_vec(),
            },
        );
        let pkce = new_pkce_pair();
        let tr = exchange_code_for_token(
            &m,
            &"https://auth.example.com/token".parse().unwrap(),
            "c",
            &"http://127.0.0.1/cb".parse().unwrap(),
            "CODE",
            &pkce.verifier,
            &"https://mcp.example.com/".parse().unwrap(),
        )
        .unwrap();
        assert!(tr.token_type.is_none());
    }

    #[test]
    fn exchange_code_non_2xx_returns_http_error() {
        let m = MockHttpClient::new();
        m.register(
            HttpMethod::PostForm,
            "https://auth.example.com/token",
            HttpResponse {
                status: 400,
                body: br#"{"error":"invalid_grant"}"#.to_vec(),
            },
        );
        let pkce = new_pkce_pair();
        let err = exchange_code_for_token(
            &m,
            &"https://auth.example.com/token".parse().unwrap(),
            "c",
            &"http://127.0.0.1/cb".parse().unwrap(),
            "CODE",
            &pkce.verifier,
            &"https://mcp.example.com/".parse().unwrap(),
        )
        .unwrap_err();
        assert_eq!(err, HttpAuthError::HttpError("token_endpoint_non_2xx"));
    }

    /// I10c-α2 R1 BLOCKER 修复证据:`client_secret_basic` 对 `client_id` / `client_secret`
    /// 正确做 `application/x-www-form-urlencoded` 编码后再拼 `:` 再 base64(RFC 6749 §2.3.1)。
    ///
    /// 验 Authorization header 的 Basic 值是 base64(form_encode(id) + ":" + form_encode(secret))。
    #[test]
    fn introspect_token_basic_auth_percent_encodes_id_and_secret() {
        use base64::Engine;

        let m = MockHttpClient::new();
        let ir_body = br#"{"active":true,"iss":"https://auth.example.com","aud":"https://x/"}"#;
        m.register(
            HttpMethod::PostForm,
            "https://auth.example.com/introspect",
            HttpResponse {
                status: 200,
                body: ir_body.to_vec(),
            },
        );
        // client_id 含 `:`(互操作常见 chaos)+ 空格 + `%`;client_secret 含 `%`
        let client_id = "client:with spaces%";
        let client_secret = "sec%ret";
        let _ = introspect_token(
            &m,
            &"https://auth.example.com/introspect".parse().unwrap(),
            client_id,
            client_secret,
            "OPAQUE",
        )
        .unwrap();
        let calls = m.calls();
        let ip = calls
            .iter()
            .find(|c| c.url.as_str() == "https://auth.example.com/introspect")
            .expect("introspect call");
        let auth = ip
            .headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case("Authorization"))
            .expect("Authorization header");
        let basic_b64 = auth.1.strip_prefix("Basic ").expect("Basic prefix");
        let decoded = base64::engine::general_purpose::STANDARD
            .decode(basic_b64)
            .expect("base64 decode");
        let s = std::str::from_utf8(&decoded).expect("utf-8");

        // 按 RFC 预期:encoded_id ":" encoded_secret
        // percent_encode 把 ':' → %3A, ' ' → +, '%' → %25
        let expect_encoded_id = "client%3Awith+spaces%25";
        let expect_encoded_secret = "sec%25ret";
        let expected = format!("{expect_encoded_id}:{expect_encoded_secret}");
        assert_eq!(
            s, expected,
            "client_secret_basic must form-encode id and secret before base64 (RFC 6749 §2.3.1)"
        );
    }
}
