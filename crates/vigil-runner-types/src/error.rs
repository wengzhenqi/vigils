//! Runner 错误类型(ADR 0007 §3 数据模型)。

use thiserror::Error;

/// 预检拒绝的字段定位 —— 稳定 token,审计 payload 的 `field` 用此枚举的字符串。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum RejectField {
    /// cwd 无效或不在 read_dirs
    Cwd,
    /// read_dir 无法 canonicalize
    ReadDir,
    /// write_dir 不在 read_dirs
    WriteDir,
    /// sandbox_profile_id 无效
    ProfileId,
    /// argv 缺失或 binary 不可执行
    Argv,
    /// runner 本身不支持(如 Wasm 未启用 feature)
    Runner,
    /// I07.5:Linux Landlock 无法注入或内核不支持 —— fail-closed 拒绝 spawn
    Sandbox,
}

impl RejectField {
    /// 审计 payload 稳定字符串。
    ///
    /// `#[non_exhaustive]` 契约纪律:即使定义 crate 内也保留 fail-closed `_` 分支,
    /// 未来新增变体时不破坏 stable audit payload(未登记变体走通用 "rejected")。
    /// `unreachable_patterns` allow 是**有意识选择** —— 防御性 `_` 优先于编译器的
    /// 可达性分析,因为本枚举的"稳定字符串"是审计契约的一部分。
    #[allow(unreachable_patterns)]
    pub fn as_str(self) -> &'static str {
        match self {
            RejectField::Cwd => "cwd",
            RejectField::ReadDir => "read_dir",
            RejectField::WriteDir => "write_dir",
            RejectField::ProfileId => "profile_id",
            RejectField::Argv => "argv",
            RejectField::Runner => "runner",
            RejectField::Sandbox => "sandbox",
            _ => "rejected",
        }
    }

    /// 已知所有变体清单(稳定契约一部分 —— 新增变体**必须**在此同步追加)。
    ///
    /// 目的:外部 golden test 以此为真 —— 断言 `ALL_KNOWN.len() == N` + 遍历验证每个
    /// 变体的 `as_str()` 映射。由于 `RejectField` 是 `#[non_exhaustive]`,外部 crate
    /// 无法自行穷举 match,此常量是"告诉外部测试:已登记变体是这些,仅此而已"的
    /// 权威来源。
    ///
    /// **若你在此添加新变体**:同步在 `as_str` 的 match 里加分支 + 更新外部
    /// `audit_strings_golden.rs` 的 `ALL_KNOWN.len()` 期望。
    pub const ALL_KNOWN: &'static [RejectField] = &[
        RejectField::Cwd,
        RejectField::ReadDir,
        RejectField::WriteDir,
        RejectField::ProfileId,
        RejectField::Argv,
        RejectField::Runner,
        RejectField::Sandbox,
    ];
}

#[cfg(test)]
mod reject_field_guards {
    //! 定义 crate **内部** guard:`#[non_exhaustive]` 对内部 match 不强制 `_` fallback,
    //! 内部穷尽 match 才是真穷尽 —— 新增变体会编译错误,强迫开发者同步 `ALL_KNOWN`。
    //! 这是 R2 Important 修复:外部 golden(integration test)无法穷举 `#[non_exhaustive]`,
    //! 只有定义 crate 内的 `#[cfg(test)]` 模块能做到。
    use super::RejectField;

    /// **关键守门**:穷尽 match 每个变体 → 新增变体编译错误 → 必须更新 ALL_KNOWN。
    /// 同时断言每个变体**确实在** `ALL_KNOWN` 里(正向覆盖)。
    #[test]
    fn all_known_contains_every_defined_variant() {
        // 穷尽 match:定义 crate 内 #[non_exhaustive] 不强制 _,漏分支 → 编译错误。
        // 若未来新增 `RejectField::Foo`,本 match 会编译失败,提示开发者:
        //   1. 在 `RejectField::ALL_KNOWN` 里追加 `RejectField::Foo`
        //   2. 在 `as_str` match 里加 `Foo => "foo"` 分支
        //   3. 在外部 `audit_strings_golden.rs` 的 expected 表里加 golden 断言
        fn require_known(v: RejectField) {
            match v {
                RejectField::Cwd
                | RejectField::ReadDir
                | RejectField::WriteDir
                | RejectField::ProfileId
                | RejectField::Argv
                | RejectField::Runner
                | RejectField::Sandbox => {
                    // 穷尽保证 —— 每个 variant 都走到这里
                    assert!(
                        RejectField::ALL_KNOWN.contains(&v),
                        "RejectField::{:?} 漏登记 ALL_KNOWN",
                        v
                    );
                }
            }
        }
        // 逐一调用 —— 若新增 variant,上面 match 漏分支会编译错误
        require_known(RejectField::Cwd);
        require_known(RejectField::ReadDir);
        require_known(RejectField::WriteDir);
        require_known(RejectField::ProfileId);
        require_known(RejectField::Argv);
        require_known(RejectField::Runner);
        require_known(RejectField::Sandbox);
    }
}

/// runner 错误(ADR 0007 §3)。所有变种**必须**产审计事件(§I-7.6)。
#[derive(Debug, Error, Clone)]
#[non_exhaustive]
pub enum RunnerError {
    /// 预检失败(path 越界 / profile deny / unsupported) → 审计 `runner.rejected`
    #[error("rejected: field={field:?} reason={reason_code}")]
    Rejected {
        /// 失败字段
        field: RejectField,
        /// 稳定 reason code
        reason_code: &'static str,
    },
    /// wall_ms 耗尽 → 审计 `runner.killed_by_timeout`
    #[error("timeout: wall_ms={wall_ms}")]
    Timeout {
        /// 配置的 wall 超时(毫秒)
        wall_ms: u64,
    },
    /// stdin/stdout/stderr pipe 失败 → 审计 `runner.io_error`
    #[error("io_error: phase={phase} reason={reason_code}")]
    Io {
        /// spawn / stdout_read / stderr_read / wait 等
        phase: &'static str,
        /// 稳定 reason code(不含 OS 原文,脱敏)
        reason_code: &'static str,
    },
    /// wasmtime 返回 trap(已脱敏的 trap 消息)
    #[error("wasm_trap: {0}")]
    WasmTrap(String),
    /// 内部不变量违反(锁 / 闭包等)
    #[error("internal: {0}")]
    Internal(&'static str),
}
