//! Golden test:锁定 `RejectField::as_str` 的稳定字符串契约(+ fail-closed `_` fallback)。
//!
//! 本 enum 进 `RunnerError::Rejected { field, reason_code }` 的 audit payload 稳定 token。
//! I07.5 加过 `Sandbox` 变体 + `#[non_exhaustive]` 后,新增变体必须同步本 golden。
//!
//! 参见 `crates/vigil-lease/tests/audit_strings_golden.rs` 的失败处理指南。

use vigil_runner::RejectField;

#[test]
fn reject_field_as_str_golden() {
    // 变体 × 字符串 golden 清单(必须与 `ALL_KNOWN` 一一对应)
    let expected: &[(RejectField, &str)] = &[
        (RejectField::Cwd, "cwd"),
        (RejectField::ReadDir, "read_dir"),
        (RejectField::WriteDir, "write_dir"),
        (RejectField::ProfileId, "profile_id"),
        (RejectField::Argv, "argv"),
        (RejectField::Runner, "runner"),
        (RejectField::Sandbox, "sandbox"),
    ];
    for &(v, s) in expected {
        assert_eq!(v.as_str(), s, "{:?} 映射字符串漂移", v);
    }

    // 外部 golden 做 `ALL_KNOWN` 与 `expected` 双向校验。
    // **注意**:本层只能检测"`ALL_KNOWN` 与 golden 期望不一致"。"定义侧新增 variant
    // 但漏同步 `ALL_KNOWN`"的那层守门由**定义 crate 内** `#[cfg(test)] mod
    // reject_field_guards` 完成(穷尽 match 对 `#[non_exhaustive]` enum 在定义 crate
    // 内部有效,漏分支 → 编译错误)。两层 guard 组合起来真正闭合"新增 variant 未
    // 同步 golden"的洞。
    assert_eq!(
        RejectField::ALL_KNOWN.len(),
        expected.len(),
        "ALL_KNOWN 常量与 golden 期望长度不一致:检查 ALL_KNOWN 和本 golden 表是否同步"
    );
    // ALL_KNOWN 里每一个都能在 golden 表中找到(反向覆盖)
    for v in RejectField::ALL_KNOWN {
        assert!(
            expected.iter().any(|(ev, _)| ev == v),
            "RejectField::ALL_KNOWN 含 {:?},但 golden 期望表漏缺 —— 请同步",
            v
        );
    }
}

/// `as_str` 的 `_ => "rejected"` fallback 契约:防御性 `_` 分支的稳定字符串
/// (即使未来新增未同步 variant,fallback 保证审计链仍出 "rejected" 而非 panic)。
///
/// 本测试无法构造"未知变体"(Rust 不允许),但通过所有已知 variant **不**返回
/// "rejected" 来间接验证 fallback 只在真的未知时触发(== fail-closed 期望)。
#[test]
fn reject_field_fallback_never_triggered_for_known_variants() {
    let known = [
        RejectField::Cwd,
        RejectField::ReadDir,
        RejectField::WriteDir,
        RejectField::ProfileId,
        RejectField::Argv,
        RejectField::Runner,
        RejectField::Sandbox,
    ];
    for v in known {
        assert_ne!(v.as_str(), "rejected", "{:?} 不应落入 fallback 分支", v);
    }
}
