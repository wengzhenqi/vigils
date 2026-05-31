//! I10a 运行时类型:`ResolvedAccessToken`。
//!
//! JWT claim 解析的键常量:`scope` claim 是**空格分隔** string(OAuth 2.0 惯例,RFC 8693)。

use vigil_lease::SecretValue;

/// JWT `scope` claim 的分隔符(OAuth 2.0 / RFC 8693)。
pub const SCOPES_CLAIM_DELIMITER: &str = " ";

/// 运行时解析的 access token —— 真值包在 `SecretValue`(零化),metadata 明文。
pub struct ResolvedAccessToken {
    /// 真值(`expose()` 是唯一访问点)
    pub raw: SecretValue,
    /// 来自 JWT `aud` / `resource` claim
    pub resource: String,
    /// 来自 JWT `scope` claim(已 split by space)
    pub scope_set: Vec<String>,
    /// 来自 JWT `exp` claim(Unix 秒);None 表示 JWT 无 exp(I10a 仍允许但审计标记)
    pub expires_at: Option<i64>,
}

impl std::fmt::Debug for ResolvedAccessToken {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // 不印 raw(SecretValue Debug 已只打长度;这里显式省略,避免误派生)
        f.debug_struct("ResolvedAccessToken")
            .field("resource", &self.resource)
            .field("scope_set", &self.scope_set)
            .field("expires_at", &self.expires_at)
            .finish_non_exhaustive()
    }
}
