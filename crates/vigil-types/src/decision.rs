//! DecisionRecord：Vigil 的核心真相 —— 每次调用是否放行的裁决。

use serde::{Deserialize, Serialize};

/// 每次 tool call 的裁决记录；进入账本不可删改（只能新增反向记录）。
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DecisionRecord {
    /// 唯一 id。
    pub decision_id: String,
    /// 对应的 invocation。
    pub invocation_id: String,
    /// 裁决类型。
    pub decision: DecisionKind,
    /// 风险评分（0-100）。
    pub risk_score: u8,
    /// 可读的理由列表（用于 UI / 审计展示）。
    pub reasons: Vec<String>,
    /// 命中的 policy id 列表（可审计回溯规则）。
    pub policy_ids: Vec<String>,
    /// 创建时间（Unix epoch 秒）。
    pub created_at: i64,
}

/// 裁决类型。
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[non_exhaustive]
#[serde(rename_all = "PascalCase")]
pub enum DecisionKind {
    /// 直接放行。
    Allow,
    /// 直接拒绝。
    Deny,
    /// 进入审批队列。
    Approve,
}
