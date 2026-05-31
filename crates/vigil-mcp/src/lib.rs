//! vigil-mcp —— Vigil Hub(I04 实装,ADR 0004)。
//!
//! 对 agent client(Cursor / Claude Desktop 等)暴露为**唯一 MCP server**,
//! 内部聚合并转发到已审批的上游 server。每次 `tools/call` 经 Firewall 评估、
//! 必要时等待 Approval、对高危外发走 Outbox。

#![deny(missing_docs)]
#![forbid(unsafe_code)]
#![allow(clippy::expect_used)]
#![cfg_attr(test, allow(clippy::unwrap_used))]

pub mod descriptor;
pub mod hub;
pub mod namespace;
pub mod oracle;
pub mod protocol;
pub mod stdio;
pub mod upstream;

pub use descriptor::{descriptor_hash, DESCRIPTOR_DOMAIN_TAG};
pub use hub::{
    compute_argv_hash, Hub, HubConfig, HubError, EVENT_RAW_SECRET_ATTEMPT_DETECTED,
    EVENT_SECRET_LEAK_DETECTED,
};
pub use namespace::{NamespaceError, ToolRoute, ToolRouter};
pub use oracle::RegistryDescriptorOracle;
pub use protocol::{JsonRpcError, JsonRpcRequest, JsonRpcResponse};
pub use upstream::{McpUpstream, UpstreamError};

/// 当前迭代号。
pub const ITERATION: &str = "I04";
