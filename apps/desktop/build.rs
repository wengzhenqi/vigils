//! I08b 构建脚本 — feature `gui` 启用时调用 `tauri_build::try_build(...)`,非 gui 路径零开销。
//!
//! # feature detection
//!
//! Cargo 对 build script 同时支持两种 feature 感知方式(见 Cargo reference):
//! 1. **`#[cfg(feature = "...")]` 属性**:Cargo 把 `CARGO_FEATURE_*` 映射为
//!    `--cfg feature="..."` 传给 rustc 编译 build.rs,所以属性 gate 有效
//! 2. **`CARGO_FEATURE_<NAME>` 环境变量**:build.rs 运行时可读
//!
//! 这里选择 **`#[cfg]` 编译期 gate**,因为 `tauri_build` 只在 `gui` feature 启用时
//! 作为 optional build-dependency 出现;**非 gui 路径下该 crate 根本不在依赖图中,
//! 符号无法解析**。若用 runtime env 检查而不 gate 编译,rustc 会 BLOCKER(E0433)。
//!
//! # Re-run triggers
//!
//! 下列文件变更让 Cargo 重跑本脚本。声明放在 cfg 块**外面**以便两种 feature 路径都生效。
//!
//! # β1: AppManifest command 白名单(ADR 0008 α1 R1 遗留技术债兑付)
//!
//! `tauri_build::Attributes::app_manifest(AppManifest::new().commands(INVOKE_COMMANDS))`
//! 在构建期为列表中每条命令生成 `allow-{slugified}` / `deny-{slugified}` 权限 TOML,
//! 命令名 underscore → hyphen(见 `tauri-utils::acl::build` 第 290 行 `slugified_command`)。
//! 例:`list_sessions` → permission identifier `allow-list-sessions`。
//! `capabilities/default.json` 对应引用 hyphenated identifier,无前缀 = APP_ACL_KEY(应用自身)。
//!
//! 未列入 `INVOKE_COMMANDS` 的 handler,即使出现在 `generate_handler!`,frontend invoke
//! 也会被 ACL 拒绝 —— 这是 hard gate,兑付 α1 时承诺延期的"AppManifest 级真白名单"。

// SSOT include:commands.rs 的 `pub const INVOKE_COMMANDS` 被 build.rs 和 lib.rs 共用。
// 文件里的 `#[cfg(test)] mod tests { ... }` 在 build.rs 构建时 cfg(test)=false,
// 被 Rust 前端 gate 掉,不污染 build.rs 顶层。
include!("src/commands.rs");

fn main() {
    println!("cargo:rerun-if-changed=tauri.conf.json");
    println!("cargo:rerun-if-changed=capabilities");
    println!("cargo:rerun-if-changed=icons");
    println!("cargo:rerun-if-changed=src/commands.rs");
    println!("cargo:rerun-if-env-changed=CARGO_FEATURE_GUI");

    // gui feature 启用时(且仅当)编译 + 调用 tauri_build::try_build
    #[cfg(feature = "gui")]
    {
        use tauri_build::{AppManifest, Attributes};
        let attributes =
            Attributes::new().app_manifest(AppManifest::new().commands(INVOKE_COMMANDS));
        if let Err(err) = tauri_build::try_build(attributes) {
            // 与 tauri_build::build() 原 panic 等价的失败语义,保留 `{err:#}` 链式展示便于排错。
            eprintln!("tauri_build::try_build failed: {err:#}");
            std::process::exit(1);
        }
    }
}
