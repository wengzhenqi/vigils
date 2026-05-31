//! vigil-types
//!
//! 跨 crate 共享的核心数据类型。严格对应主方案 §2 的 10 个对象。
//!
//! I00 仅声明类型骨架并锁定不变量：
//!   - Debug / Display 对 `SecretLease` 等敏感类型必须脱敏
//!   - 枚举必须是 `#[non_exhaustive]`（跨 crate），以便后续迭代扩展而不破坏 ABI
//!   - 所有类型支持 serde（审计账本、UI 协议、lease broker 都要序列化）
//!
//! 运行时行为（存储 / 校验 / hash chain）不在本 crate 范围，参见各专用 crate。

#![deny(missing_docs)]
#![forbid(unsafe_code)]

pub mod approval;
pub mod audit;
pub mod decision;
pub mod effect;
pub mod invocation;
pub mod lease;
pub mod principal;
pub mod server;
pub mod session;
pub mod tool;

pub use approval::{ApprovalRequest, ApprovalResolution, ApprovalScope, ApprovalStatus};
pub use audit::AuditEvent;
pub use decision::{DecisionKind, DecisionRecord};
pub use effect::{EffectKind, EffectVector};
pub use invocation::ToolInvocation;
pub use lease::{InjectionMethod, SecretLease};
pub use principal::{Principal, PrincipalKind, TrustLevel};
pub use server::{ServerProfile, TransportKind};
pub use session::{Session, SessionSource};
pub use tool::ToolDescriptor;
