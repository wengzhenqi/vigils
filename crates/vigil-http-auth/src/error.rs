//! I10a 错误模型(ADR 0010 §4)。
//!
//! **脱敏契约**(§I-10.1):变种字段**不得**含 token raw value / client secret /
//! 原始后端错误文本。所有字符串参数必须是受控的 reason code / 稳定字段名。

use thiserror::Error;

/// HTTP Auth 层错误。
#[derive(Debug, Clone, Error, PartialEq, Eq)]
#[non_exhaustive]
pub enum HttpAuthError {
    /// PRM 字段不合法(稳定 reason code)
    #[error("invalid_prm: {0}")]
    InvalidPrm(&'static str),
    /// PRM 必须包含至少一个 authorization_server
    #[error("missing_authorization_server")]
    MissingAuthorizationServer,
    /// PRM `bearer_methods_supported` 不含 "header"(I10a fail-closed)
    #[error("bearer_header_not_supported")]
    BearerHeaderNotSupported,
    /// 请求 scope 不在 PRM `scopes_supported` 内
    #[error("scope_not_supported: {0}")]
    ScopeNotSupported(String),
    /// Token 不是 JWT 格式(I10a 仅支持 JWT;opaque 留 I10b introspection)
    #[error("unsupported_token_format")]
    UnsupportedTokenFormat,
    /// JWT decode 失败
    #[error("jwt_decode_failed")]
    JwtDecodeFailed,
    /// JWT `aud` 与 PRM resource 不匹配
    #[error("audience_mismatch")]
    AudienceMismatch {
        /// 期望的 resource URL(来自 PRM,已规范化)
        expected: String,
        /// JWT claims 里实际声明的 aud / resource
        actual: String,
    },
    /// JWT `scope` claim 缺失某项请求 scope
    #[error("scope_missing: {0}")]
    ScopeMissing(String),
    /// JWT `exp` 已过期
    #[error("token_expired")]
    TokenExpired,
    /// 请求远程 MCP 但无可用 token → fail-closed(§I-10.4:**不**用 client token)
    #[error("missing_token")]
    MissingToken,
    /// TokenStore 访问失败(Secret 后端 / SQLite);稳定 reason code
    #[error("token_store_error: {0}")]
    TokenStoreError(&'static str),
    /// I10b-α1:JWT `iss` 与 `ExpectedBinding.issuer` 不等(含 `iss` 缺失 → actual=`"(missing)"`)
    #[error("token_rejected_wrong_issuer")]
    TokenRejectedWrongIssuer {
        /// `ExpectedBinding.issuer`
        expected: String,
        /// JWT 实际 iss,缺失时 `"(missing)"`
        actual: String,
    },
    /// I10b-α1:metadata 存在但 SecretStore 找不到 value(跨重启 / keychain 被清)。
    /// 与 `MissingToken`(从未授权)**严格**不同,I10c refresh 入口按此区分。
    #[error("token_rehydrate_required: {reason_code}")]
    TokenRehydrateRequired {
        /// 稳定 reason code,例如 `"secret_missing_for_known_metadata"`
        reason_code: &'static str,
    },
    /// I10b-α1(实装在 α2):JWT 签名校验失败
    #[error("jwt_signature_invalid")]
    JwtSignatureInvalid,
    /// I10b-α1(实装在 α2):JWT `alg` 不在白名单(RS256 / ES256)
    #[error("jwt_alg_rejected: {0}")]
    JwtAlgRejected(&'static str),
    /// I10b-α1(实装在 α2):JWT `kid` 不在 JwkSet
    #[error("jwks_kid_not_found")]
    JwksKidNotFound,
    /// HTTP 传输错(mock / 真;稳定 reason code)
    #[error("http_error: {0}")]
    HttpError(&'static str),
    /// 内部不变量违反
    #[error("internal: {0}")]
    Internal(&'static str),
}

#[cfg(test)]
mod variant_exhaustiveness_guard {
    //! 定义 crate **内部** guard:`#[non_exhaustive]` 对内部 match 不强制 `_` fallback,
    //! 新增 variant 会让本 match 漏分支 → 编译错误,强迫开发者同步外部 golden
    //! (`tests/error_display_golden.rs`)。
    //!
    //! 模式与 `vigil-runner::error::reject_field_guards` 同构。
    use super::HttpAuthError;

    #[test]
    fn all_variants_have_stable_display_contract() {
        // 穷尽 match:漏分支 → 编译错误。新增 variant 时:
        //   1. 加分支并选择 stable token(或 prefix:tail 格式)
        //   2. 更新 `tests/error_display_golden.rs` 的对应分类断言
        //   3. 更新 `http_auth_error_variant_coverage_sanity` 的 `all_known.len() == N`
        fn classify(err: &HttpAuthError) -> &'static str {
            match err {
                HttpAuthError::InvalidPrm(_) => "prefixed",
                HttpAuthError::MissingAuthorizationServer => "pure_token",
                HttpAuthError::BearerHeaderNotSupported => "pure_token",
                HttpAuthError::ScopeNotSupported(_) => "prefixed",
                HttpAuthError::UnsupportedTokenFormat => "pure_token",
                HttpAuthError::JwtDecodeFailed => "pure_token",
                HttpAuthError::AudienceMismatch { .. } => "struct_variant",
                HttpAuthError::ScopeMissing(_) => "prefixed",
                HttpAuthError::TokenExpired => "pure_token",
                HttpAuthError::MissingToken => "pure_token",
                HttpAuthError::TokenStoreError(_) => "prefixed",
                HttpAuthError::TokenRejectedWrongIssuer { .. } => "struct_variant",
                HttpAuthError::TokenRehydrateRequired { .. } => "prefixed",
                HttpAuthError::JwtSignatureInvalid => "pure_token",
                HttpAuthError::JwtAlgRejected(_) => "prefixed",
                HttpAuthError::JwksKidNotFound => "pure_token",
                HttpAuthError::HttpError(_) => "prefixed",
                HttpAuthError::Internal(_) => "prefixed",
            }
        }
        // 本测试不对具体 classification 断言(那由外部 golden 覆盖);
        // 仅依赖上面 match 的穷尽性来守"新增 variant 必须在此显式分类"。
        let sample = HttpAuthError::MissingToken;
        let c = classify(&sample);
        assert!(matches!(c, "pure_token" | "prefixed" | "struct_variant"));
    }
}
