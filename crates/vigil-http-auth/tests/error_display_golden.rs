//! Golden test:锁定 `HttpAuthError` 的 `thiserror` `Display` 稳定 token 契约。
//!
//! `Display` 输出进审计链(logger / tracing 消费)+ 下游告警规则按 prefix 分发
//! (如 运维规则匹配 `"token_expired"` 触发 token refresh 告警)。字符串漂移会静默
//! 断裂告警 / 日志聚合。
//!
//! 范围界定(Codex R3 建议):仅对"下游当 machine-readable token 消费"的 variant
//! 做 golden;不把所有 display 文本升级成稳定契约。本文件覆盖:
//!
//! - 纯 token(无字段占位):`missing_token` / `token_expired` 等
//! - 前缀 + 变长 tail(稳定 prefix):`invalid_prm: {0}` / `http_error: {0}` 等
//!   —— 只锁定 prefix 部分(`split(':').next()`),tail 是诊断信息不锁
//!
//! 参见 `crates/vigil-lease/tests/audit_strings_golden.rs` 的失败处理指南。

#![allow(clippy::unwrap_used)]

use vigil_http_auth::HttpAuthError;

/// 纯 token variants:Display 完全等于 stable string(无占位)。
#[test]
fn http_auth_error_pure_tokens_golden() {
    let cases: &[(HttpAuthError, &str)] = &[
        (
            HttpAuthError::MissingAuthorizationServer,
            "missing_authorization_server",
        ),
        (
            HttpAuthError::BearerHeaderNotSupported,
            "bearer_header_not_supported",
        ),
        (
            HttpAuthError::UnsupportedTokenFormat,
            "unsupported_token_format",
        ),
        (HttpAuthError::JwtDecodeFailed, "jwt_decode_failed"),
        (HttpAuthError::TokenExpired, "token_expired"),
        (HttpAuthError::MissingToken, "missing_token"),
        (HttpAuthError::JwtSignatureInvalid, "jwt_signature_invalid"),
        (HttpAuthError::JwksKidNotFound, "jwks_kid_not_found"),
    ];
    for (err, expected) in cases {
        assert_eq!(
            format!("{}", err),
            *expected,
            "Display 漂移:{:?} 不再输出稳定 token",
            err
        );
    }
}

/// 结构体 variants(含字段)但 Display **只输出 stable token**,不含字段值:
/// `AudienceMismatch { expected, actual }` → "audience_mismatch"(不含 expected/actual)
/// `TokenRejectedWrongIssuer { expected, actual }` → "token_rejected_wrong_issuer"
#[test]
fn http_auth_error_struct_variants_display_golden() {
    let aud_mismatch = HttpAuthError::AudienceMismatch {
        expected: "https://mcp.example.com".into(),
        actual: "https://evil.example.com".into(),
    };
    assert_eq!(format!("{}", aud_mismatch), "audience_mismatch");

    let wrong_iss = HttpAuthError::TokenRejectedWrongIssuer {
        expected: "https://auth.example.com".into(),
        actual: "(missing)".into(),
    };
    assert_eq!(format!("{}", wrong_iss), "token_rejected_wrong_issuer");
}

/// Prefix + tail variants:Display 形如 `"<stable_prefix>: <tail>"`。
/// 锁定 prefix(审计/告警匹配)+ 验证 tail 正确追加。
#[test]
fn http_auth_error_prefixed_variants_golden() {
    // (err_instance, expected_full_display, stable_prefix)
    let cases: &[(HttpAuthError, &str, &str)] = &[
        (
            HttpAuthError::InvalidPrm("missing_field_xyz"),
            "invalid_prm: missing_field_xyz",
            "invalid_prm",
        ),
        (
            HttpAuthError::ScopeNotSupported("mcp:admin".into()),
            "scope_not_supported: mcp:admin",
            "scope_not_supported",
        ),
        (
            HttpAuthError::ScopeMissing("mcp:tools.write".into()),
            "scope_missing: mcp:tools.write",
            "scope_missing",
        ),
        (
            HttpAuthError::TokenStoreError("secret_store_put_failed"),
            "token_store_error: secret_store_put_failed",
            "token_store_error",
        ),
        (
            HttpAuthError::TokenRehydrateRequired {
                reason_code: "secret_missing_for_known_metadata",
            },
            "token_rehydrate_required: secret_missing_for_known_metadata",
            "token_rehydrate_required",
        ),
        (
            HttpAuthError::JwtAlgRejected("HS256"),
            "jwt_alg_rejected: HS256",
            "jwt_alg_rejected",
        ),
        (
            HttpAuthError::HttpError("mock_unreachable"),
            "http_error: mock_unreachable",
            "http_error",
        ),
        (
            HttpAuthError::Internal("introspection_cache_poisoned"),
            "internal: introspection_cache_poisoned",
            "internal",
        ),
    ];
    for (err, expected_full, expected_prefix) in cases {
        let display = format!("{}", err);
        assert_eq!(display, *expected_full, "Display 字符串漂移:{:?}", err);
        // 稳定 prefix(冒号前)也单独断言 —— 告警规则通常按 prefix 匹配
        let actual_prefix = display.split(':').next().unwrap();
        assert_eq!(
            actual_prefix, *expected_prefix,
            "stable prefix 漂移:{:?}",
            err
        );
    }
}

/// 契约一致性 guard:`HttpAuthError` 是 `#[non_exhaustive]`;
/// 定义 crate 用穷尽 match 守完整性(新增 variant 触发编译错误,强迫同步 golden)。
///
/// 注意:外部 integration test crate **无法**真正穷尽 match `#[non_exhaustive]` enum,
/// 所以这里用"所有已知 variant 至少触发一次 Display"来间接证明覆盖;真新增-同步 guard
/// 需要在 `vigil-http-auth` lib 内部的 `#[cfg(test)] mod` 里写穷尽 match。
/// 本轮仅做外部 golden(`HttpAuthError` 的内部穷尽 guard 留 follow-up)。
#[test]
fn http_auth_error_variant_coverage_sanity() {
    // 构造所有**已知** variant 的最小实例,断言 Display 非空(防止 thiserror 派生损坏)。
    // 新增 variant 时,本测试数量不变但 R1 审查会暴露漏同步。
    let all_known = [
        HttpAuthError::MissingAuthorizationServer,
        HttpAuthError::BearerHeaderNotSupported,
        HttpAuthError::UnsupportedTokenFormat,
        HttpAuthError::JwtDecodeFailed,
        HttpAuthError::TokenExpired,
        HttpAuthError::MissingToken,
        HttpAuthError::JwtSignatureInvalid,
        HttpAuthError::JwksKidNotFound,
        HttpAuthError::InvalidPrm("x"),
        HttpAuthError::ScopeNotSupported("x".into()),
        HttpAuthError::ScopeMissing("x".into()),
        HttpAuthError::TokenStoreError("x"),
        HttpAuthError::TokenRehydrateRequired { reason_code: "x" },
        HttpAuthError::JwtAlgRejected("x"),
        HttpAuthError::HttpError("x"),
        HttpAuthError::Internal("x"),
        HttpAuthError::AudienceMismatch {
            expected: "x".into(),
            actual: "y".into(),
        },
        HttpAuthError::TokenRejectedWrongIssuer {
            expected: "x".into(),
            actual: "y".into(),
        },
    ];
    assert_eq!(
        all_known.len(),
        18,
        "HttpAuthError 已知 variant 数漂移;请同步更新本 golden + 上面 pure/struct/prefixed 三组测试"
    );
    for err in &all_known {
        let display = format!("{}", err);
        assert!(!display.is_empty(), "{:?} Display 为空", err);
    }
}
