//! AuditEvent：append-only 审计事件（接入 vigil-audit 的 hash chain 账本）。

use serde::{Deserialize, Serialize};

/// append-only 事件条目。
///
/// 不变量：
/// - `payload_json` 必须已由 `vigil-redaction` 脱敏，不得含原始 secret。
/// - `event_hash = SHA256(prev_hash || canonical_json(payload) || created_at)`（I01 实装）。
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AuditEvent {
    /// 自增序号（由账本签发）。
    pub event_id: i64,
    /// 所属 session。
    pub session_id: String,
    /// 事件类型（如 `tool_call.evaluated` / `secret.lease_minted` / `approval.resolved`）。
    pub event_type: String,
    /// 已脱敏的负载。
    pub payload_json: serde_json::Value,
    /// 供 FTS 检索的脱敏纯文本摘要（可选）。
    pub redacted_text: Option<String>,
    /// 前一条事件的 `event_hash`（创世块为空串）。
    pub prev_hash: String,
    /// 本条事件的 hash。
    pub event_hash: String,
    /// 创建时间（Unix epoch 秒）。
    pub created_at: i64,
}
