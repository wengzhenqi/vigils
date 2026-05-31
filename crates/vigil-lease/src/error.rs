//! Lease / SecretStore 的错误模型。
//!
//! ADR 0006 §D3:
//! - `ContextMismatch`:bound 三元组不匹配(**必写审计**)
//! - `Expired` / `Revoked` / `NotFound`:lease 生命周期错误
//! - `StoreError`:底层 keychain 访问失败

use thiserror::Error;

/// `SecretStore` 读写失败。
///
/// **Codex R1 BLOCKER-2 修复**:backend 错误用结构化枚举,不接任意字符串 —— 避免
/// keyring / DBus 后端的错误消息里意外回显真实 value 时,`Display` 被写入 SQLite
/// / audit payload 造成 secret 泄漏。可读 `reason_code` 是固定常量集,`Display`
/// 只输出 `{backend}:{code}`,不含后端原始错误文本。
#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
pub enum SecretStoreError {
    /// `secret_ref` 在 store 中不存在。
    #[error("secret_not_found")]
    NotFound,
    /// 锁中毒 / 内部不变量违反。
    #[error("backend:lock_poisoned")]
    LockPoisoned,
    /// I/O 或底层 API 不可用(网络 / DBus unavailable / keychain locked 等)。
    /// 不承载任何后端原文 —— 原文只在 debug build 的 tracing(若启用)中记录。
    #[error("backend:unavailable")]
    BackendUnavailable,
    /// 后端显式拒绝(权限不足 / user denied 等)。
    #[error("backend:denied")]
    BackendDenied,
    /// 其他 backend 失败,归类为通用错误(不含文本)。
    #[error("backend:other")]
    BackendOther,
}

impl SecretStoreError {
    /// 稳定字符串 code(审计 payload 用,不含任何敏感文本)。
    pub fn reason_code(self) -> &'static str {
        match self {
            SecretStoreError::NotFound => "secret_not_found",
            SecretStoreError::LockPoisoned => "lock_poisoned",
            SecretStoreError::BackendUnavailable => "backend_unavailable",
            SecretStoreError::BackendDenied => "backend_denied",
            SecretStoreError::BackendOther => "backend_other",
        }
    }
}

/// Lease 操作失败。
#[derive(Debug, Error)]
pub enum LeaseError {
    /// `lease_id` 未知(可能已 revoke 或从未 mint)。
    #[error("lease not found: {0}")]
    NotFound(String),
    /// Lease 已过期(lazy eviction 在 resolve 时判定)。
    #[error("lease expired: {0}")]
    Expired(String),
    /// Lease 已被显式 revoke。
    #[error("lease revoked: {0}")]
    Revoked(String),
    /// bound 三元组(session / server / tool)与 `ResolveContext` 不一致 ——
    /// **必写 `secret.lease_misuse_attempt` 审计事件**。
    #[error("lease context mismatch: {lease_id}")]
    ContextMismatch {
        /// 触发 mismatch 的 lease_id。
        lease_id: String,
        /// 哪一维不匹配(便于 audit payload 定位,不含真实值)。
        field: MismatchField,
    },
    /// 底层 `SecretStore` 失败。
    #[error("secret store error: {0}")]
    StoreError(#[from] SecretStoreError),
    /// 请求的注入方式 I06 不支持(fail-closed,ADR 0006 §D4)。
    #[error("injection method unsupported in I06: {0:?}")]
    UnsupportedInjectionMethod(vigil_types::InjectionMethod),
    /// 其他内部错误(锁中毒等)。
    #[error("internal error: {0}")]
    Internal(&'static str),
}

/// 三元组中哪一维不匹配 —— 仅为审计定位,不含真实值。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MismatchField {
    /// `session_id` 不匹配。
    Session,
    /// `server_id` 不匹配。
    Server,
    /// `tool_name` 不匹配。
    Tool,
}

impl MismatchField {
    /// 审计 payload 字段名(稳定字符串契约)。
    pub fn as_str(self) -> &'static str {
        match self {
            MismatchField::Session => "session",
            MismatchField::Server => "server",
            MismatchField::Tool => "tool",
        }
    }
}
