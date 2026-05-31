//! Native runner env 政策(ADR 0007 §I-7.1 helper)+ `ScrubCallback` type alias。
//!
//! 从 `vigil-runner/src/native.rs` 抽出(ADR 0018 v0.13)。0 vigil deps,可
//! 独立 publish + 被 `vigil-mcp` / `vigil-ui-protocol` 直接 path-dep。
//!
//! `default_scrub` 不在本模块(它依赖 `vigil-redaction::scrub_text`),仍由
//! `vigil-runner` 主 crate 提供。`ScrubCallback` type alias 在此,允许
//! consumer 在不拉 vigil-redaction 的情况下构造自己的 scrub。

use std::sync::Arc;

/// 脱敏回调:接受任意字符串,返回脱敏后字符串(同长度或更短)。
///
/// 默认实现 `default_scrub` 用 `vigil_redaction::scrub_text`(在 `vigil-runner`
/// 主 crate),consumer 也可注入 identity / 更严格的实现。
pub type ScrubCallback = Arc<dyn Fn(&str) -> String + Send + Sync>;

/// Windows 下会被 runner 自动注入的最小系统 env 集合 —— caller 通过
/// `bind_tool_secret` 声明的 `env_var_name` **不允许**命中这些保留名字,
/// 否则 runner 的 defense-in-depth 会让系统 env 在注入顺序上早于用户 env,
/// 语义变得难以预期。registry 层应在 `bind_tool_secret` 入口做大小写不敏感拒绝。
pub const RESERVED_SYSTEM_ENV_KEYS: &[&str] = &[
    "SystemRoot",
    "SYSTEMROOT",
    "windir",
    "WINDIR",
    "SystemDrive",
    "SYSTEMDRIVE",
];

/// 判定一个 env key 是否属于 Windows 保留系统 env(大小写不敏感)。
/// Linux/macOS 亦按保守口径拒绝(保持跨平台一致 binding)。
pub fn is_reserved_env_key(key: &str) -> bool {
    RESERVED_SYSTEM_ENV_KEYS
        .iter()
        .any(|k| k.eq_ignore_ascii_case(key))
}

/// I07.5+ (ADR 0007 §I-7.1 helper 抽取承诺兑现):统一 Native spawn 的 env 政策。
///
/// **原子三步**(不可改序,不可在中间插其他 `cmd` 操作):
/// 1. `env_clear()`(AGENTS §7 / §I-7.3)
/// 2. **仅 Windows**:注入 `RESERVED_SYSTEM_ENV_KEYS`(`SystemRoot` / `windir` / `SystemDrive`
///    及其大小写变体)—— 让 cmd.exe / ping 等系统命令能解析 System32 DLL;`env_clear` 后
///    缺失它们会让绝大部分 Windows 系统命令以 exit=1 退出;这些 env 本身非敏感。
///    Linux/macOS 不做此注入(/bin/sh 不依赖 env 查 DLL)
/// 3. `envs(user_env)` —— 用户批准的 env 最后注入,顺序最后保证优先级最高(即使
///    registry 漏检也压过 system 保留键;registry 层已通过 `is_reserved_env_key`
///    主动拒绝 binding 使用这些名字)
///
/// **§I-7.3 compliance**:本函数是**原子单元**,内部三步无 log / audit / Debug 调用。
/// 调用方应在**取得 user_env 后立即**调用本函数,之间不插入任何其他 cmd 操作(典型:
/// `cmd.arg()` / `cmd.current_dir()` 等应**先于**本函数,stdio/stdin 配置可后于)。
///
/// **I07.5+ 动机**:此前 `spawn_native` 和 `vigil_mcp::StdioUpstream::spawn` 各自实现
/// env 政策,存在 Windows SystemRoot 注入漂移(StdioUpstream 缺失)。抽共享 helper
/// 消除漂移,同时兑现 ADR 0007 §I-7.1 承诺。
pub fn apply_native_env_policy<I, K, V>(cmd: &mut std::process::Command, user_env: I)
where
    I: IntoIterator<Item = (K, V)>,
    K: AsRef<std::ffi::OsStr>,
    V: AsRef<std::ffi::OsStr>,
{
    cmd.env_clear();
    #[cfg(windows)]
    for key in RESERVED_SYSTEM_ENV_KEYS {
        if let Ok(v) = std::env::var(key) {
            cmd.env(key, v);
        }
    }
    cmd.envs(user_env);
}
