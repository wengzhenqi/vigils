//! Golden test:锁定 `TokenKind::{as_path_segment, as_str}` 的稳定字符串契约。
//!
//! 这两个字符串同时是:
//! - SecretStore key 路径片段(`token://oauth/{kind}/...`,由 `as_path_segment` 构造)
//! - SQLite `oauth_token_metadata.token_kind` 列值(由 `as_str` 注入,序列化持久化)
//! - 审计 payload / 日志 聚合的稳定 token(由 `as_str` 输出)
//!
//! 任何漂移会:
//! 1. SecretStore key 空间分裂(旧 token 无法通过新 key 找到)
//! 2. SQLite 老库迁移失败(列值枚举不匹配)
//! 3. 审计聚合断裂
//!
//! 参见 `crates/vigil-lease/tests/audit_strings_golden.rs` 的失败处理指南。

#![allow(clippy::unwrap_used)]

use vigil_http_auth::TokenKind;

#[test]
fn token_kind_as_path_segment_golden() {
    assert_eq!(TokenKind::Access.as_path_segment(), "access");
    assert_eq!(TokenKind::Refresh.as_path_segment(), "refresh");

    // variant 计数 guard
    fn count(v: TokenKind) -> u8 {
        match v {
            TokenKind::Access => 1,
            TokenKind::Refresh => 2,
        }
    }
    assert_eq!(count(TokenKind::Refresh), 2);
}

#[test]
fn token_kind_as_str_golden() {
    assert_eq!(TokenKind::Access.as_str(), "access");
    assert_eq!(TokenKind::Refresh.as_str(), "refresh");
}

/// 契约一致性:`as_path_segment` 与 `as_str` **必须返回相同字符串**。
/// 两个方法分出来是为文档清晰(path 用途 vs 审计用途),但字符串契约必须一致,
/// 否则 SQLite 列值(as_str)与 SecretStore key(as_path_segment)会错位,
/// metadata 查不到对应 secret。
#[test]
fn token_kind_as_path_segment_and_as_str_agree() {
    for v in [TokenKind::Access, TokenKind::Refresh] {
        assert_eq!(
            v.as_path_segment(),
            v.as_str(),
            "as_path_segment 与 as_str 必须一致 for {:?}",
            v
        );
    }
}

/// serde 契约验证:`TokenKind` 的 `#[serde(rename_all = "lowercase")]` 输出应与
/// `as_str` 一致(两路径同一字符串,持久化 / audit 都通过)。
#[test]
fn token_kind_serde_matches_as_str() {
    let cases = [
        (TokenKind::Access, "access"),
        (TokenKind::Refresh, "refresh"),
    ];
    for (v, expected) in cases {
        let serde_out = serde_json::to_string(&v).unwrap();
        let unquoted = serde_out.trim_matches('"');
        assert_eq!(v.as_str(), unquoted, "as_str vs serde mismatch for {:?}", v);
        assert_eq!(v.as_str(), expected);
    }
}
