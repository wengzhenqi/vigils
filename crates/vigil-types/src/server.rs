//! ServerProfile：一个 MCP server 或本地工具 server 的身份档案。

use crate::principal::TrustLevel;
use serde::{Deserialize, Serialize};

/// 一个 MCP server 的身份档案 —— 启动命令、传输方式、信任等级、绑定的 sandbox profile。
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ServerProfile {
    /// 唯一 id。
    pub server_id: String,
    /// 传输类型。
    pub transport: TransportKind,
    /// Stdio 启动时的 argv（完整命令）；Http 时为 None。
    pub command: Option<Vec<String>>,
    /// Http 传输时的 URL；Stdio 时为 None。
    pub url: Option<String>,
    /// 首次登记时间（Unix epoch 秒）。
    pub first_seen_at: i64,
    /// Stdio 传输时：`sha256(argv)` 的十六进制；用于识别命令漂移。
    pub command_hash: Option<String>,
    /// 聚合后的工具描述符 hash；用于 I05 descriptor pinning。
    pub descriptor_hash: Option<String>,
    /// 信任等级。
    pub trust_level: TrustLevel,
    /// 绑定到某个 sandbox profile；None 表示继承默认最小权限。
    pub sandbox_profile_id: Option<String>,
}

/// MCP 传输类型。
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[non_exhaustive]
#[serde(rename_all = "PascalCase")]
pub enum TransportKind {
    /// 本地子进程 stdio。
    Stdio,
    /// 远端 HTTP（Streamable HTTP / SSE）。
    Http,
}
