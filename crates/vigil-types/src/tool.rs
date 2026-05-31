//! ToolDescriptor：MCP `tools/list` 得到的工具描述。
//!
//! 注意：**descriptor 内容默认不可信**。`description` / `annotations` 仅作为输入参考，
//! 实际风险由 firewall 的 `EffectExtractor` 在 args 上重新推断（AGENTS.md §5）。

use serde::{Deserialize, Serialize};

/// MCP 工具描述符快照。
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ToolDescriptor {
    /// 该工具所属 server。
    pub server_id: String,
    /// 工具名（upstream 原始名，未 namespaced）。
    pub tool_name: String,
    /// MCP 提供的 JSON schema。
    pub schema_json: serde_json::Value,
    /// 工具描述文本。
    pub description: Option<String>,
    /// MCP 规范中的 annotations（readOnlyHint 等）。
    pub annotations: serde_json::Value,
    /// descriptor 的规范化哈希（sha256(hex)）；I05 descriptor pinning 的唯一信任锚。
    ///
    /// 下游消费者应以此字段为权威,**不要**把其它字段(`description` / `annotations`)
    /// 当作已审批的可信输入 —— 它们的内容只要发生任何变化,`descriptor_hash`
    /// 就会改变,进而触发再审批。
    pub descriptor_hash: String,
    /// 首次见到的时间（Unix epoch 秒）。
    pub first_seen_at: i64,
    /// 若已审批：**对当前 `descriptor_hash` 的**审批时间（Unix epoch 秒）。
    ///
    /// 语义澄清(AGENTS.md §5):被审批的是"这一份 hash 所代表的 descriptor 快照",
    /// 而非"本 server 提供的该工具永久可信"。descriptor 内容的任何漂移会让 hash 改变,
    /// 下游必须把 `Some(_) && descriptor_hash == current` 作为唯一可信判据。
    pub approved_at: Option<i64>,
}
