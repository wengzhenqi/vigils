//! ApprovalRequest：需要人类或策略批准的请求。

use crate::effect::EffectVector;
use serde::{Deserialize, Serialize};

/// 一条待审批请求。
///
/// 生命周期状态机（I03 实装）：Pending → (Approved | Denied | Expired | Cancelled)。
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ApprovalRequest {
    /// 唯一 id。
    pub approval_id: String,
    /// 对应裁决。
    pub decision_id: String,
    /// 被审批的 tool-call invocation。
    /// 绑定 `ApprovalScope::Once`:一次批准只对本 invocation 生效(ADR 0003 §D6)。
    pub invocation_id: String,
    /// 所属 session。
    pub session_id: String,
    /// 卡片标题（面向用户）。
    pub title: String,
    /// 卡片摘要（已脱敏，不含原始 args）。
    pub summary: String,
    /// 被审批的效应向量（用户能直接看到"会做什么"）。
    pub effect_vector: EffectVector,
    /// 到期时间（Unix epoch 秒）；到期后视为 Expired。
    pub expires_at: i64,
    /// 当前状态。
    pub status: ApprovalStatus,
}

/// 审批状态。
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[non_exhaustive]
#[serde(rename_all = "PascalCase")]
pub enum ApprovalStatus {
    /// 等待用户决策。
    Pending,
    /// 已批准。
    Approved,
    /// 已拒绝。
    Denied,
    /// TTL 到期。
    Expired,
    /// 上游取消（session 结束 / agent 中断等）。
    Cancelled,
}

/// 审批范围(ADR 0003 §D6)。
///
/// I02+I03 实装:`Once` / `ThisSession`。后两项放占位,I05+ 启用。
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[non_exhaustive]
#[serde(rename_all = "PascalCase")]
pub enum ApprovalScope {
    /// 只对当前 `invocation_id` 生效,消费即失效。
    Once,
    /// 对同一 `session_id` 下、`(server_id, tool_name, args_hash)` 相同的后续调用自动放行。
    ThisSession,
    /// 跨 session,对相同 `args_hash` 的调用放行(I05+)。
    ForToolWithSameArgsHash,
    /// 派生为临时 allow 规则(I05+)。
    ForPolicyTemplate,
}

/// 审批最终解析结果。`wait_for_resolution` 的返回值。
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ApprovalResolution {
    /// 被解析的审批 id。
    pub approval_id: String,
    /// 绑定到的 `invocation_id`(首次创建 approval 时由 decision 关联)。
    /// 供 I04 MCP Hub 在 `ApprovalScope::Once` 下做"仅本次 invocation 放行"校验。
    pub invocation_id: String,
    /// 终态。
    pub status: ApprovalStatus,
    /// 若 `status == Approved`,携带用户选择的范围;其它状态下为 `None`。
    pub scope: Option<ApprovalScope>,
    /// 解析人标识(用户名 / "system" / "auto-expired")。
    pub resolved_by: Option<String>,
    /// 解析时间(Unix epoch 秒)。
    pub resolved_at: i64,
}
