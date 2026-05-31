//! vigil-runner
//!
//! I07(ADR 0007):Sandbox Runner —— Wasm + Native 统一执行计划与安全边界。
//!
//! ADR 0018 v0.13 split:pure types + env policy 抽到 `vigil-runner-types`,
//! 本 crate 含 concrete impl(`spawn_native` / `WasmRunner` / `default_scrub` /
//! `leak_scan`)。Backward compat 通过 `pub use vigil_runner_types::*` 保留 —
//! downstream(例:`use vigil_runner::SandboxProfile;`)继续可用,无需改 import。
//!
//! 对外公共 API(types 来自 vigil-runner-types,impl 来自本 crate):
//! - `ExecutionPlan` / `RunnerKind` / `RunnerSpecific` / `ExecutionResult`(types)
//! - `SandboxProfile`(types)
//! - `RunnerError` / `RejectField`(types)
//! - `ScrubCallback`(types,type alias)+ `default_scrub`(impl,vigil-redaction 依赖)
//! - `apply_native_env_policy` / `RESERVED_SYSTEM_ENV_KEYS` / `is_reserved_env_key`(types)
//! - `NullAuditSink` / `RunnerAuditSink` / `RunnerEvent`(types)
//! - `spawn_native`:Native runner 入口(async,本 crate impl)
//! - `prescreen_native`(本 crate impl)
//! - `WasmRunner`(仅 `wasm` feature 下编译,本 crate impl)
//!
//! 严格遵守 ADR 0007 的 9 条安全不变量(§I-7.1 ~ §I-7.9,I07.5 Landlock 增项)。

#![deny(missing_docs)]
#![forbid(unsafe_code)]
#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used, clippy::panic))]

// ISS-020:post-exec leak detection helper(native + wasm 共用,vigil-redaction dep)
mod leak_scan;
mod native;

#[cfg(feature = "wasm")]
mod wasm;

// ADR 0018:re-export 全部 pure types + env policy 给 backward compat,
// downstream `use vigil_runner::*` 调用全部保持,无需改 import。
pub use vigil_runner_types::{
    apply_native_env_policy, is_reserved_env_key, ExecutionPlan, ExecutionResult, NullAuditSink,
    RejectField, RunnerAuditSink, RunnerError, RunnerEvent, RunnerKind, RunnerSpecific,
    SandboxProfile, ScrubCallback, RESERVED_SYSTEM_ENV_KEYS,
};

// concrete impl(本 crate)
pub use native::{default_scrub, prescreen_native, spawn_native};

#[cfg(feature = "wasm")]
pub use wasm::WasmRunner;

/// 当前迭代号。
pub const ITERATION: &str = "I07";
