//! vigil-lease
//!
//! I06(ADR 0006):secret alias + 短期 lease + OS Keychain 适配。
//!
//! 本 crate 提供:
//! - [`SecretStore`][] trait:真实值读写边界
//! - [`InMemorySecretStore`][]:默认测试实现
//! - `KeyringSecretStore`:可选 feature `os-keychain`
//! - [`SecretValue`][]:真实 secret 零化包装(`expose()` 是唯一访问点)
//! - [`LeaseBroker`][]:`mint_lease` / `resolve_value` / `revoke_lease` / `sweep_expired`
//! - [`MintRequest`][] / [`ResolveContext`][] / [`LeaseError`][] / [`MismatchField`][]
//!
//! 所有真实 secret 值从不离开 `SecretValue` / `LeaseBroker` 的边界;审计 payload 只
//! 含 alias 和 metadata,严格遵守 AGENTS.md §4。

#![deny(missing_docs)]
#![forbid(unsafe_code)]
// 测试代码允许 unwrap/expect/panic(与其他 crate 一致,AGENTS.md "Implementation rules" 允许)
#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used, clippy::panic))]

mod broker;
mod error;
mod store;
mod value;

pub use broker::{LeaseBroker, MintRequest, PreparedChildEnv, ResolveContext};
pub use error::{LeaseError, MismatchField, SecretStoreError};
#[cfg(feature = "os-keychain")]
pub use store::KeyringSecretStore;
pub use store::{InMemorySecretStore, SecretStore};
pub use value::SecretValue;

/// 当前迭代号。
pub const ITERATION: &str = "I06";
