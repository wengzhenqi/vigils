//! Principal：发起动作的主体。

use serde::{Deserialize, Serialize};

/// 发起动作的主体。
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Principal {
    /// 唯一 id。
    pub id: String,
    /// 主体类型。
    pub kind: PrincipalKind,
    /// 面向用户的展示名。
    pub display_name: String,
    /// 信任等级。
    pub trust_level: TrustLevel,
}

/// 主体类型。
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[non_exhaustive]
#[serde(rename_all = "PascalCase")]
pub enum PrincipalKind {
    /// 人类用户。
    User,
    /// AI Agent。
    Agent,
    /// 浏览器扩展。
    BrowserExtension,
    /// MCP server。
    McpServer,
}

/// 信任等级。
///
/// 不变量：新注册的主体默认为 `Untrusted`，只有通过显式审批才可提升。
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash, PartialOrd, Ord)]
#[non_exhaustive]
#[serde(rename_all = "PascalCase")]
pub enum TrustLevel {
    /// 首次见到 / 未审批。
    Untrusted,
    /// 已审批一次。
    Limited,
    /// 已审批并标记为常用。
    Trusted,
}

impl Default for TrustLevel {
    /// 默认为 `Untrusted` —— 对应 `AGENTS.md` §6 "Side effects require allow / deny / approve decisions"。
    fn default() -> Self {
        Self::Untrusted
    }
}
