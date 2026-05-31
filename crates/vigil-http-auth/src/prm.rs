//! Protected Resource Metadata(RFC 9728)—— ADR 0010 §D3。
//!
//! `.well-known/oauth-protected-resource` 返 JSON:
//! ```json
//! {
//!   "resource": "https://mcp.example.com",
//!   "authorization_servers": ["https://auth.example.com"],
//!   "bearer_methods_supported": ["header"],
//!   "scopes_supported": ["mcp:tools.read"]
//! }
//! ```

use serde::{Deserialize, Serialize};
use url::Url;

use crate::client::{HttpClient, HttpMethod, HttpRequest};
use crate::error::HttpAuthError;

/// RFC 9728 Protected Resource Metadata 的 Vigil 投影。
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ProtectedResourceMetadata {
    /// 规范化的 resource URL(通常等于 MCP server base URL)
    pub resource: Url,
    /// 至少一个 authorization server URL
    pub authorization_servers: Vec<Url>,
    /// I10a 必须含 `"header"`(fail-closed 见 §I-10.7)
    pub bearer_methods_supported: Vec<String>,
    /// AS 可能签发的 scope 集合(caller 的 scope 必须是其子集)
    pub scopes_supported: Vec<String>,
    /// RFC 9728 可选字段
    #[serde(skip_serializing_if = "Option::is_none")]
    pub resource_documentation: Option<Url>,
}

/// 校验结构字段(**不**做网络调用)。
///
/// - `resource` 必须 parse(已由 serde 保证)
/// - `authorization_servers` 非空
/// - `bearer_methods_supported` 必须含 `"header"`
/// - `scopes_supported` 非空(I10a 强制,I10b 若真支持零 scope 可放宽)
pub fn validate_prm_struct(prm: &ProtectedResourceMetadata) -> Result<(), HttpAuthError> {
    if prm.authorization_servers.is_empty() {
        return Err(HttpAuthError::MissingAuthorizationServer);
    }
    if !prm.bearer_methods_supported.iter().any(|m| m == "header") {
        return Err(HttpAuthError::BearerHeaderNotSupported);
    }
    if prm.scopes_supported.is_empty() {
        return Err(HttpAuthError::InvalidPrm("scopes_supported_empty"));
    }
    Ok(())
}

/// 从 `.well-known/oauth-protected-resource` 拉取 + 校验 PRM。
///
/// `resource_base` 必须是 `https://host[:port]` 形态(无 path / query);函数内部
/// 追加 `.well-known/oauth-protected-resource`。
///
/// **Codex R1 BLOCKER 修复**:fail-closed 比较 `prm.resource == resource_base` —— 防止
/// 远端 `.well-known` 返回别的 resource,静默改写绑定目标。比较用**规范化**形式:
/// `url::Url` 默认把 `https://x.com` 规为 `https://x.com/`,两边都靠它规范化。
pub fn fetch_and_validate_prm(
    client: &dyn HttpClient,
    resource_base: &Url,
) -> Result<ProtectedResourceMetadata, HttpAuthError> {
    let well_known = resource_base
        .join(".well-known/oauth-protected-resource")
        .map_err(|_| HttpAuthError::InvalidPrm("cannot_join_well_known"))?;
    let resp = client.send(&HttpRequest {
        url: well_known,
        method: HttpMethod::Get,
        headers: Vec::new(),
        body: None,
    })?;
    if resp.status != 200 {
        return Err(HttpAuthError::InvalidPrm("non_200_status"));
    }
    let prm: ProtectedResourceMetadata = serde_json::from_slice(&resp.body)
        .map_err(|_| HttpAuthError::InvalidPrm("malformed_json"))?;
    validate_prm_struct(&prm)?;
    // 资源自校 —— url::Url 的 PartialEq 做规范化比较(scheme/host/port/path)
    if &prm.resource != resource_base {
        return Err(HttpAuthError::InvalidPrm("resource_base_mismatch"));
    }
    Ok(prm)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::client::{HttpResponse, MockHttpClient};

    fn sample_prm() -> ProtectedResourceMetadata {
        ProtectedResourceMetadata {
            resource: "https://mcp.example.com/".parse().unwrap(),
            authorization_servers: vec!["https://auth.example.com/".parse().unwrap()],
            bearer_methods_supported: vec!["header".into()],
            scopes_supported: vec!["mcp:tools.read".into(), "mcp:tools.write".into()],
            resource_documentation: None,
        }
    }

    #[test]
    fn prm_parse_valid_metadata() {
        let json = serde_json::to_vec(&sample_prm()).unwrap();
        let m = MockHttpClient::new();
        let base: Url = "https://mcp.example.com/".parse().unwrap();
        m.register(
            HttpMethod::Get,
            "https://mcp.example.com/.well-known/oauth-protected-resource",
            HttpResponse {
                status: 200,
                body: json,
            },
        );
        let prm = fetch_and_validate_prm(&m, &base).unwrap();
        assert_eq!(
            prm.resource,
            "https://mcp.example.com/".parse::<Url>().unwrap()
        );
    }

    #[test]
    fn prm_rejects_missing_bearer_header_method() {
        let mut prm = sample_prm();
        prm.bearer_methods_supported = vec!["query".into()];
        assert_eq!(
            validate_prm_struct(&prm),
            Err(HttpAuthError::BearerHeaderNotSupported)
        );
    }

    #[test]
    fn prm_rejects_missing_authorization_server() {
        let mut prm = sample_prm();
        prm.authorization_servers.clear();
        assert_eq!(
            validate_prm_struct(&prm),
            Err(HttpAuthError::MissingAuthorizationServer)
        );
    }

    #[test]
    fn prm_rejects_empty_scopes() {
        let mut prm = sample_prm();
        prm.scopes_supported.clear();
        assert_eq!(
            validate_prm_struct(&prm),
            Err(HttpAuthError::InvalidPrm("scopes_supported_empty"))
        );
    }

    /// Codex R1 BLOCKER:PRM resource 与请求 resource_base 不一致 → 拒
    #[test]
    fn prm_rejects_resource_base_mismatch() {
        // 远端返 PRM 声称是别的 resource(攻击面)
        let mut prm = sample_prm();
        prm.resource = "https://other.example.com/".parse().unwrap();
        let json = serde_json::to_vec(&prm).unwrap();
        let m = MockHttpClient::new();
        let base: Url = "https://mcp.example.com/".parse().unwrap();
        m.register(
            HttpMethod::Get,
            "https://mcp.example.com/.well-known/oauth-protected-resource",
            HttpResponse {
                status: 200,
                body: json,
            },
        );
        let err = fetch_and_validate_prm(&m, &base).unwrap_err();
        assert_eq!(err, HttpAuthError::InvalidPrm("resource_base_mismatch"));
    }

    #[test]
    fn prm_fetch_non_200_returns_invalid() {
        let m = MockHttpClient::new();
        let base: Url = "https://mcp.example.com/".parse().unwrap();
        m.register(
            HttpMethod::Get,
            "https://mcp.example.com/.well-known/oauth-protected-resource",
            HttpResponse {
                status: 404,
                body: b"not found".to_vec(),
            },
        );
        let err = fetch_and_validate_prm(&m, &base).unwrap_err();
        assert_eq!(err, HttpAuthError::InvalidPrm("non_200_status"));
    }
}
