//! `UiError`:协议层错误(ADR 0008 §I-8.2:不得含真实 secret / 原始后端文本)。

use serde::{Deserialize, Serialize};
use thiserror::Error;

/// UI 协议错误。所有变种**不得**含真实 secret 或原始 SQL / keyring 后端文本。
/// `LedgerError` 只承载 `AuditError::Display` 的结果,`AuditError` 自身已结构化脱敏。
#[derive(Debug, Clone, Error, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "kind", content = "detail")]
#[non_exhaustive]
pub enum UiError {
    /// 资源不存在(approval / session / profile / server)
    #[error("not_found: {0}")]
    NotFound(String),
    /// 输入不合法 —— 稳定字符串 reason,不含 raw 输入
    #[error("invalid: {0}")]
    Invalid(&'static str),
    /// 权限不足
    #[error("capability_denied: required={required}")]
    CapabilityDenied {
        /// 需要的 capability(`ui.read` / `ui.write`)
        required: &'static str,
    },
    /// Ledger 层错误转译;caller 应看 reason_code 而非原文
    #[error("ledger_error: {reason_code}")]
    LedgerError {
        /// 稳定 reason code(audit 层已结构化)
        reason_code: &'static str,
    },
    /// argv 含硬指纹 secret(D5 fail-closed 入口)
    #[error("secret_in_argv: server={server_id} rule={rule}")]
    SecretInArgv {
        /// 触发的 server id(非敏感)
        server_id: String,
        /// 命中的规则名(github_token / openai_key / pem_private_key / ...)
        rule: &'static str,
    },
    /// Sandbox profile JCS 规范化失败
    #[error("profile_serialize_failed")]
    ProfileSerializeFailed,
}
