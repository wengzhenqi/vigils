//! Session：一次 agent / browser / MCP 活动上下文。

use serde::{Deserialize, Serialize};

/// 一次活动上下文的起止 + 来源。
///
/// `risk_score` 为该 session 的累计风险评分（0-100），由 firewall 增量累加。
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Session {
    /// 唯一 id（UUIDv4 文本形式）。
    pub id: String,
    /// 来源通道。
    pub source: SessionSource,
    /// 可选：发起端应用标识（如 "Cursor" / "Claude Desktop" / "Chrome"）。
    pub app_name: Option<String>,
    /// Unix epoch 秒。
    pub started_at: i64,
    /// Unix epoch 秒；None 表示仍在活动中。
    pub ended_at: Option<i64>,
    /// 累计风险评分（0-100）。
    pub risk_score: u8,
}

/// session 的发起通道。
///
/// `#[non_exhaustive]` 是故意的：后续迭代新增通道（如 Ide / IdeExtension）时，
/// 下游消费者必须显式处理 _，避免漏分支导致安全失败。
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[non_exhaustive]
#[serde(rename_all = "PascalCase")]
pub enum SessionSource {
    /// 通过 MCP 协议进入。
    McpClient,
    /// 通过浏览器扩展进入。
    Browser,
    /// 直接由桌面 UI 发起。
    Desktop,
    /// 命令行 / 脚本。
    Cli,
}
