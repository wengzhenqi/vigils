//! I10b-α1 §α1-D4 守门:从**消费者 crate**(integration test 视作独立 crate)
//! 验证 `UpstreamError` 的 `#[non_exhaustive]` 约束真能迫使 caller 用 `_ =>` 兜底。
//!
//! 若未来有人把 `#[non_exhaustive]` 去掉,本 match 的 `_ =>` 会变成 "unreachable
//! pattern";反之,增加新变体时本 match 仍能编译通过 —— 这是跨 crate 边界的关键
//! 不变量。

#![allow(clippy::unwrap_used)]

use std::time::Duration;

use vigil_mcp::UpstreamError;

#[test]
fn upstream_error_forces_wildcard_match_from_consumer_crate() {
    let e = UpstreamError::TransportIo("x");
    let label = match &e {
        UpstreamError::TransportIo(r) => format!("io:{r}"),
        UpstreamError::TimedOut(d) => format!("timeout:{d:?}"),
        UpstreamError::Unauthorized { reason_code } => format!("401:{reason_code}"),
        UpstreamError::Forbidden => "403".to_string(),
        UpstreamError::JsonRpc {
            code,
            message_sha256,
        } => format!("rpc:{code}:{message_sha256}"),
        UpstreamError::TokenRehydrateRequired { reason_code } => {
            format!("rehydrate:{reason_code}")
        }
        UpstreamError::AuthError(r) => format!("auth:{r}"),
        UpstreamError::Internal(r) => format!("internal:{r}"),
        // `#[non_exhaustive]` 约束:跨 crate 必须有 `_`;α2 新增变体不会破坏本 match。
        _ => "unknown".to_string(),
    };
    assert_eq!(label, "io:x");
}

#[test]
fn all_i10b_alpha1_variants_reachable_from_consumer_crate() {
    // 烟雾测试:每个 α1 明文声明的变体都能构造 + 走 label 路径
    let cases: Vec<UpstreamError> = vec![
        UpstreamError::TransportIo("io"),
        UpstreamError::TimedOut(Duration::from_millis(10)),
        UpstreamError::Unauthorized {
            reason_code: "bearer_expired",
        },
        UpstreamError::Forbidden,
        UpstreamError::JsonRpc {
            code: -32000,
            message_sha256: "abc".to_string(),
        },
        UpstreamError::TokenRehydrateRequired {
            reason_code: "secret_missing_for_known_metadata",
        },
        UpstreamError::AuthError("any"),
        UpstreamError::Internal("any"),
    ];
    for c in cases {
        // 能显式 Display
        let _ = format!("{c}");
    }
}
