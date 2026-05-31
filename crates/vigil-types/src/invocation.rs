//! ToolInvocation：一次工具调用请求（进入 firewall 前的原始形态）。

use serde::{Deserialize, Serialize};

/// 一次工具调用请求。
///
/// 生命周期：client → MCP Hub → ToolInvocation → Firewall → DecisionRecord → Execute。
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ToolInvocation {
    /// 唯一 id（UUIDv4 文本）。
    pub invocation_id: String,
    /// 归属 session。
    pub session_id: String,
    /// 目标 server。
    pub server_id: String,
    /// upstream 工具名。
    pub tool_name: String,
    /// 原始参数（来自 MCP `tools/call` 的 `arguments` 字段）。
    pub args: serde_json::Value,
    /// 调用时 pin 的 descriptor hash；若漂移则本次调用需重新审批。
    pub descriptor_hash: String,
    /// 请求到达时间（Unix epoch 秒）。
    pub requested_at: i64,
}
