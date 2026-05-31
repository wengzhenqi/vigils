//! Golden test:锁定 `MismatchField::as_str` 的稳定字符串契约。
//!
//! **为什么**:`as_str` 输出进审计 payload;字符串一旦改变,下游消费方(UI / 日志聚合 /
//! metrics)全链路断裂。加 golden test 防止未来迭代无意修改。
//!
//! **失败时怎么办**:如果这个测试失败,说明你改了 `MismatchField` 的变体或映射字符串。
//! 三种处理:
//! 1. **有意改名**(rare):同步更新下游消费方 + 本 golden 清单
//! 2. **新增 variant**:给新 variant 写稳定字符串 + 在本 golden 加一行断言
//! 3. **意外改动**:回滚改动;稳定字符串是跨模块契约,不可轻动

use vigil_lease::{MismatchField, SecretStoreError};

#[test]
fn mismatch_field_as_str_golden() {
    // 穷举每个变体,断言映射字符串。
    // 新增 variant 时,编译器不会提醒本处(as_str 内部 match 已穷尽),但本断言数量
    // 不变会暴露覆盖不全 —— 参见文件顶注释的处理建议。
    assert_eq!(MismatchField::Session.as_str(), "session");
    assert_eq!(MismatchField::Server.as_str(), "server");
    assert_eq!(MismatchField::Tool.as_str(), "tool");

    // variant count 守门:若未来新增变体但未在此加断言,本断言会失败
    // (通过穷举 match 来强制 caller 更新本测试)。
    fn variant_count(v: MismatchField) -> u8 {
        match v {
            MismatchField::Session => 1,
            MismatchField::Server => 2,
            MismatchField::Tool => 3,
        }
    }
    // 已知最高变体编号 == 3;若新增 variant,上述 match 编译错误 → 提示更新本测试
    assert_eq!(variant_count(MismatchField::Tool), 3);
}

/// Golden:`SecretStoreError::reason_code` 稳定字符串 + `thiserror` `Display` 一致性。
///
/// **为什么**:
/// - `reason_code()` 进审计 payload(ADR 0006 §I-6.5 secret-access 事件)
/// - `#[error("...")]` 派生的 `Display` 被 `LeaseError::StoreError(#[from])` 透传进
///   `thiserror` 链,出现在日志和 tracing,**字符串必须与 reason_code 一致**,
///   否则审计聚合和日志同源字段相悖
#[test]
fn secret_store_error_reason_code_golden() {
    assert_eq!(SecretStoreError::NotFound.reason_code(), "secret_not_found");
    assert_eq!(
        SecretStoreError::LockPoisoned.reason_code(),
        "lock_poisoned"
    );
    assert_eq!(
        SecretStoreError::BackendUnavailable.reason_code(),
        "backend_unavailable"
    );
    assert_eq!(
        SecretStoreError::BackendDenied.reason_code(),
        "backend_denied"
    );
    assert_eq!(
        SecretStoreError::BackendOther.reason_code(),
        "backend_other"
    );

    // variant 计数 guard
    fn count(v: SecretStoreError) -> u8 {
        match v {
            SecretStoreError::NotFound => 1,
            SecretStoreError::LockPoisoned => 2,
            SecretStoreError::BackendUnavailable => 3,
            SecretStoreError::BackendDenied => 4,
            SecretStoreError::BackendOther => 5,
        }
    }
    assert_eq!(count(SecretStoreError::BackendOther), 5);
}

/// 契约一致性:`thiserror` `Display` 输出的 `"{backend}:{code}"` 或 `"secret_not_found"`
/// 与 `reason_code()` 保持可解析关系 —— 具体规则:
/// - `NotFound` 的 Display 直接是 "secret_not_found"(==reason_code,无前缀)
/// - 其他 4 个 `Backend*` 的 Display 是 `backend:<tail>`,其中 `<tail>` 与 reason_code
///   的 `backend_` 前缀去掉后相同(如 Display "backend:unavailable" ↔ reason_code
///   "backend_unavailable")。这两套字符串共享同一稳定契约,任何一边漂移都应暴露。
#[test]
fn secret_store_error_display_matches_reason_code() {
    // NotFound 特殊:两路径字符串完全相同
    assert_eq!(
        format!("{}", SecretStoreError::NotFound),
        SecretStoreError::NotFound.reason_code()
    );
    // Backend* 4 条:Display 形如 "backend:<tail>",reason_code 形如 "backend_<tail>"
    let backend_cases = [
        (
            SecretStoreError::LockPoisoned,
            "backend:lock_poisoned",
            "lock_poisoned",
        ),
        (
            SecretStoreError::BackendUnavailable,
            "backend:unavailable",
            "backend_unavailable",
        ),
        (
            SecretStoreError::BackendDenied,
            "backend:denied",
            "backend_denied",
        ),
        (
            SecretStoreError::BackendOther,
            "backend:other",
            "backend_other",
        ),
    ];
    for (v, expected_display, expected_reason) in backend_cases {
        assert_eq!(
            format!("{}", v),
            expected_display,
            "Display mismatch {:?}",
            v
        );
        assert_eq!(
            v.reason_code(),
            expected_reason,
            "reason_code mismatch {:?}",
            v
        );
    }
}
