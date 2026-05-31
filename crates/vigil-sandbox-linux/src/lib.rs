//! vigil-sandbox-linux —— I07.5(ADR 0007 §8.6 "Linux Landlock 延 I07.5"承诺)。
//!
//! 职责:用 Linux 5.13+ 的 Landlock LSM 把 `read_dirs` / `write_dirs` 声明式白名单
//! 编译成 kernel-enforced 文件系统访问策略,并注入到 `std::process::Command::pre_exec`,
//! 让 Native 子进程**在 fork 后 exec 前**自我限制 —— 子进程无法再访问白名单外的路径。
//!
//! # 为什么单独成 crate
//!
//! - `std::os::unix::process::CommandExt::pre_exec` 是 **unsafe API**(pre_exec 在 fork 后
//!   exec 前运行,约束极严,只能调 async-signal-safe 的函数;Rust 标准库通过 `unsafe fn`
//!   声明语义责任归调用方)。把 unsafe 局部化到本 crate,所有其他 `vigil-*` 仍保持
//!   `forbid(unsafe_code)`,审计面最小。
//! - Landlock 只在 Linux 存在。本 crate `Cargo.toml` 用 `[target.'cfg(target_os="linux")']`
//!   gated 依赖,非 Linux 目标编译该 crate 时 `landlock` dep 根本不引入;`lib.rs` 本体
//!   被整个 `#[cfg(target_os = "linux")]` 包裹,非 Linux 编译出空 crate。
//!
//! # 安全不变量
//!
//! 1. `LandlockPolicy::install_into` 是**唯一** unsafe 出现点;用 `#[allow(unsafe_code)]`
//!    局部放开 deny 级 lint,便于静态审计定位。
//! 2. pre_exec 闭包内禁止 allocate / 禁止调用非 async-signal-safe 函数 —— 当前实现只
//!    调 `landlock::Ruleset::restrict_self`,它内部只做 `prctl` / `seccomp` 相关 syscall。
//! 3. 路径 FD 在**父进程**主线程打开(pre_exec **之前**),`PathFd` 生命周期贯穿 Command
//!    spawn;子进程 fork 继承 FD,pre_exec 构建 ruleset 用这些 FD,restrict_self 应用后
//!    exec,ruleset 生效于新镜像。
//! 4. Landlock 无法撤销 —— 一旦 `restrict_self`,当前进程(child)永不能再放宽;因此所有
//!    规则必须在 `from_dirs` 阶段构造完整。
//! 5. fail-closed:任何构造期错误(路径不存在 / Landlock ABI 不支持 / ruleset 构建失败)
//!    → `Err(LandlockError)`,caller 应拒绝 spawn;**绝不**降级为"无 Landlock 但照常 spawn"。
//!
//! # 非 Linux 目标
//!
//! 整个 `pub` API 仅在 `cfg(target_os = "linux")` 下存在。依赖本 crate 的 caller 需要
//! 在自己的 `Cargo.toml` 里用同样的 target gate 声明 dep,或用 `cfg(target_os="linux")`
//! 包裹调用代码。

#![cfg_attr(docsrs, feature(doc_cfg))]

#[cfg(target_os = "linux")]
mod linux;

#[cfg(target_os = "linux")]
pub use linux::{kernel_supports_landlock, LandlockError, LandlockPolicy, LANDLOCK_PRE_EXEC_ERRNO};

/// 当前迭代号。
pub const ITERATION: &str = "I07.5";
