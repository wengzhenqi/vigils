//! 生产环境的 `DescriptorOracle` 实现:基于 [`Ledger`] 的 server registry。
//!
//! I04 范围内的信任判定:
//! - 若 server 未登记 / trust_level = Untrusted → `FirstSeen`
//! - 若 server.descriptor_hash 为 None(从未见过任何工具) → `FirstSeen`
//! - 若 server.descriptor_hash 与本次调用传入的 hash 不等 → `Drifted`(I05 再做正式 re-approval)
//! - 否则 → `ApprovedStable`
//!
//! Hub 在 `tools/list` 时会更新 server 的聚合 descriptor_hash;`tools/call`
//! 时传入该工具的 descriptor_hash,oracle 对比判定。

use std::sync::Arc;

use vigil_audit::Ledger;
use vigil_firewall::scorer::{DescriptorOracle, DescriptorStatus};
use vigil_types::TrustLevel;

/// Registry 支持的 DescriptorOracle。
#[derive(Clone)]
pub struct RegistryDescriptorOracle {
    ledger: Arc<Ledger>,
}

impl std::fmt::Debug for RegistryDescriptorOracle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RegistryDescriptorOracle").finish()
    }
}

impl RegistryDescriptorOracle {
    /// 构造。
    pub fn new(ledger: Arc<Ledger>) -> Self {
        Self { ledger }
    }
}

impl DescriptorOracle for RegistryDescriptorOracle {
    fn status(&self, server_id: &str, tool_name: &str, descriptor_hash: &str) -> DescriptorStatus {
        // B1(Codex I04 review):改用 **per-tool** hash 比对。
        // 权威来源是 `tool_descriptors` 表;server trust_level 只作前置门闸。
        let Ok(Some(profile)) = self.ledger.get_server(server_id) else {
            return DescriptorStatus::FirstSeen;
        };
        if !matches!(
            profile.trust_level,
            TrustLevel::Limited | TrustLevel::Trusted
        ) {
            return DescriptorStatus::FirstSeen;
        }
        match self.ledger.get_pinned_tool_hash(server_id, tool_name) {
            Ok(Some(h)) if h == descriptor_hash => DescriptorStatus::ApprovedStable,
            Ok(Some(_)) => DescriptorStatus::Drifted,
            // 未登记或查询失败 → FirstSeen
            _ => DescriptorStatus::FirstSeen,
        }
    }
}
