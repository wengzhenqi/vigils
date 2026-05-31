//! I10a 审计事件名(ADR 0010 §7)。
//!
//! 审计 payload 由 caller 组装调 `Ledger::append_event`;本模块只声明稳定事件名
//! 常量,供 caller / 测试引用。

use crate::types::ResolvedAccessToken;

/// PRM 发现成功
pub const EVENT_PRM_DISCOVERED: &str = "http_auth.prm_discovered";
/// Token 存储(value 在 SecretStore,**本事件仅记 metadata**)
pub const EVENT_TOKEN_STORED: &str = "http_auth.token_stored";
/// Token 因 resource 不匹配被拒
pub const EVENT_TOKEN_REJECTED_WRONG_RESOURCE: &str = "http_auth.token_rejected_wrong_resource";
/// 客户端 header passthrough 被阻断
pub const EVENT_PASSTHROUGH_BLOCKED: &str = "http_auth.passthrough_blocked";
/// Gateway 成功构造 authorized request
pub const EVENT_REQUEST_AUTHORIZED: &str = "http_auth.request_authorized";

// --- I10b-α1 新增(ADR 0011 §α1-D7) ---
/// Token 因 issuer 不匹配被拒(α1 起触发路径:`TokenStore::resolve_access_token`)
pub const EVENT_TOKEN_REJECTED_WRONG_ISSUER: &str = "http_auth.token_rejected_wrong_issuer";

// --- I10b-α2 / α2 预留常量(α1 只声明,α2 触发点实装) ---
/// JWT 签名验证失败(α2 由 `JwksSignatureVerifier` 触发)
pub const EVENT_JWT_SIGNATURE_REJECTED: &str = "http_auth.jwt_signature_rejected";
/// JWT 签名验证通过
pub const EVENT_JWT_SIGNATURE_VERIFIED: &str = "http_auth.jwt_signature_verified";
/// JWKS 拉取(含 cache_hit 标志)
pub const EVENT_JWKS_FETCHED: &str = "http_auth.jwks_fetched";
/// AS metadata 拉取(含 cache_hit 标志)
pub const EVENT_AS_METADATA_FETCHED: &str = "http_auth.as_metadata_fetched";
/// Upstream 请求发出(α2 由 `HttpUpstream::call` 触发)
pub const EVENT_HTTP_UPSTREAM_REQUEST_SENT: &str = "http_upstream.request_sent";
/// Upstream 请求失败(status != 2xx 或 transport error)
pub const EVENT_HTTP_UPSTREAM_REQUEST_FAILED: &str = "http_upstream.request_failed";

/// 映射事件类别到事件名(便于 caller 统一 dispatch)。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum HttpAuthEvent {
    /// 对应 `EVENT_PRM_DISCOVERED`
    PrmDiscovered,
    /// 对应 `EVENT_TOKEN_STORED`
    TokenStored,
    /// 对应 `EVENT_TOKEN_REJECTED_WRONG_RESOURCE`
    TokenRejectedWrongResource,
    /// 对应 `EVENT_PASSTHROUGH_BLOCKED`
    PassthroughBlocked,
    /// 对应 `EVENT_REQUEST_AUTHORIZED`
    RequestAuthorized,
    /// I10b-α1 新增:对应 `EVENT_TOKEN_REJECTED_WRONG_ISSUER`
    TokenRejectedWrongIssuer,
    /// α2 实装触发:对应 `EVENT_JWT_SIGNATURE_REJECTED`
    JwtSignatureRejected,
    /// α2 实装触发:对应 `EVENT_JWT_SIGNATURE_VERIFIED`
    JwtSignatureVerified,
    /// α2 实装触发:对应 `EVENT_JWKS_FETCHED`
    JwksFetched,
    /// α2 实装触发:对应 `EVENT_AS_METADATA_FETCHED`
    AsMetadataFetched,
    /// α2 实装触发:对应 `EVENT_HTTP_UPSTREAM_REQUEST_SENT`
    HttpUpstreamRequestSent,
    /// α2 实装触发:对应 `EVENT_HTTP_UPSTREAM_REQUEST_FAILED`
    HttpUpstreamRequestFailed,
}

/// 统一常量名查找(caller `ledger.append_event(session, event_type_for(e), ...)` 用)。
pub fn event_type_for(event: HttpAuthEvent) -> &'static str {
    match event {
        HttpAuthEvent::PrmDiscovered => EVENT_PRM_DISCOVERED,
        HttpAuthEvent::TokenStored => EVENT_TOKEN_STORED,
        HttpAuthEvent::TokenRejectedWrongResource => EVENT_TOKEN_REJECTED_WRONG_RESOURCE,
        HttpAuthEvent::PassthroughBlocked => EVENT_PASSTHROUGH_BLOCKED,
        HttpAuthEvent::RequestAuthorized => EVENT_REQUEST_AUTHORIZED,
        HttpAuthEvent::TokenRejectedWrongIssuer => EVENT_TOKEN_REJECTED_WRONG_ISSUER,
        HttpAuthEvent::JwtSignatureRejected => EVENT_JWT_SIGNATURE_REJECTED,
        HttpAuthEvent::JwtSignatureVerified => EVENT_JWT_SIGNATURE_VERIFIED,
        HttpAuthEvent::JwksFetched => EVENT_JWKS_FETCHED,
        HttpAuthEvent::AsMetadataFetched => EVENT_AS_METADATA_FETCHED,
        HttpAuthEvent::HttpUpstreamRequestSent => EVENT_HTTP_UPSTREAM_REQUEST_SENT,
        HttpAuthEvent::HttpUpstreamRequestFailed => EVENT_HTTP_UPSTREAM_REQUEST_FAILED,
    }
}

/// 编译期引用,防止 `ResolvedAccessToken` 因 unused import 警告被裁掉(未来 audit
/// payload 扩展可能用到)。
#[allow(dead_code)]
fn _keep_resolved_in_scope() -> Option<ResolvedAccessToken> {
    None
}
