//! I10b-α1 JWKS 发现抽象(ADR 0011 §α1-D5)。
//!
//! α1 只定义 **trait** 和 **mock** 实装;真 HTTP 的 `HttpJwksSource` 留在 α2
//! `vigil-http-transport` crate 里落。
//!
//! **并发不变量 §I-11.6**:同一 `(issuer, jwks_uri)` 的刷新必须 **singleflight** ——
//! 同一时刻最多一个 in-flight fetch,其余等待同一结果。α2 实装需兑现此约束;α1 的
//! `MockJwksSource` 不并发,无需 singleflight。

use std::collections::{BTreeMap, HashMap};
use std::sync::{Arc, Mutex};

use serde::{Deserialize, Serialize};

use crate::error::HttpAuthError;

/// JWKS 一项 key(RFC 7517)。
///
/// `kid` / `kty` / `alg` 是 Vigil 必用的结构化字段;其余 JWK 参数(RSA:`n`, `e`;
/// EC:`crv`, `x`, `y` 等)通过 `extra` 保留原 JSON,供 α2 `JwksSignatureVerifier`
/// 调用 `jsonwebtoken::DecodingKey::from_jwk` 时重建完整 JWK。
///
/// 设计理由:结构化字段少是为了 API 稳定(BTreeMap 向后兼容地接纳新字段);
/// 保留原始 JSON 子段是为了 α2 能真做签名验证(否则只能校 alg/kid 的结构面,
/// 直接回潮到 "不验签")。
///
/// # Semver 声明(I10b-α2 代码 R1 NICE-TO-HAVE 3)
///
/// 本结构体字段集从 α2 起扩展 `extra` 字段。这是**向后不兼容**的命名字段构造语法
/// 变更 —— 任何老代码里 `Jwk { kid, kty, alg }` 都需要追加 `extra: Default::default()`。
///
/// 约定:**`Jwk` 不承诺字段级 semver 稳定**;调用方如需稳定,请用 serde roundtrip
/// (通过 `serde_json::Value` 互转)或在构造端使用 `..Default::default()`。
/// 这是 ADR 0010/0011 跨版本契约的已知豁免点;`OAuthTokenMetadata` 之外的类型
/// 可根据安全/协议演化需要扩字段。
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Jwk {
    /// Key ID(用于 header.kid 索引)
    pub kid: String,
    /// Key Type(`"RSA"` / `"EC"` / ...)
    pub kty: String,
    /// 允许的算法(若声明)
    #[serde(default)]
    pub alg: Option<String>,
    /// 其余 JWK 字段(RFC 7517)—— 由 serde `flatten` 存原 JSON。
    /// α1 测试可用 `extra: Default::default()` 构造空 map。
    #[serde(flatten, default)]
    pub extra: BTreeMap<String, serde_json::Value>,
}

/// JwkSet —— `jwks_uri` 响应的 typed 投影。
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct JwkSet {
    /// 当前可用的 key 列表
    pub keys: Vec<Jwk>,
}

impl JwkSet {
    /// 按 `kid` 查一个 key。
    pub fn find_by_kid(&self, kid: &str) -> Option<&Jwk> {
        self.keys.iter().find(|k| k.kid == kid)
    }
}

/// JWKS 发现 + 缓存抽象。
///
/// 实现约束(ADR 0011 §I-11.4 + §I-11.6):
/// - 缓存按 `(issuer, jwks_uri)` **联合** 索引:同一 `jwks_uri` 被不同 issuer 引用 →
///   视作独立条目,绝不共享 key
/// - `force_refresh_for_kid = Some(kid)` 语义:token 带此 `kid` 但本地缓存没有,强制
///   刷新一次;仍没有则 caller fail-closed(`JwksKidNotFound`)
/// - **并发**:force_refresh 路径必须 singleflight
pub trait JwksSource: Send + Sync + std::fmt::Debug {
    /// 获取 / 刷新 JwkSet。
    fn get(
        &self,
        issuer: &str,
        jwks_uri: &str,
        force_refresh_for_kid: Option<&str>,
    ) -> Result<Arc<JwkSet>, HttpAuthError>;
}

/// α1 测试用的内存 JWKS 源(`HashMap<(issuer, jwks_uri), JwkSet>`)。
/// 不并发 / 不刷新 / 不 fetch;纯预录。
#[derive(Debug, Default)]
pub struct MockJwksSource {
    // 使用 Mutex 只是为了 Send+Sync;pub API 保持不变
    entries: Mutex<HashMap<(String, String), Arc<JwkSet>>>,
}

impl MockJwksSource {
    /// 新建空源。
    pub fn new() -> Self {
        Self {
            entries: Mutex::new(HashMap::new()),
        }
    }

    /// 预录一组 key。
    pub fn insert(&self, issuer: impl Into<String>, jwks_uri: impl Into<String>, set: JwkSet) {
        self.entries
            .lock()
            .expect("mock jwks lock")
            .insert((issuer.into(), jwks_uri.into()), Arc::new(set));
    }
}

impl JwksSource for MockJwksSource {
    fn get(
        &self,
        issuer: &str,
        jwks_uri: &str,
        _force_refresh_for_kid: Option<&str>,
    ) -> Result<Arc<JwkSet>, HttpAuthError> {
        let entries = self.entries.lock().expect("mock jwks lock");
        match entries.get(&(issuer.to_string(), jwks_uri.to_string())) {
            Some(s) => Ok(Arc::clone(s)),
            None => Err(HttpAuthError::TokenStoreError("jwks_not_mocked")),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mock_jwks_source_isolates_by_issuer_jwks_uri_pair() {
        // 不变量 §I-11.4:同一 jwks_uri 被两个 issuer 引用视作独立条目
        let src = MockJwksSource::new();
        let set_a = JwkSet {
            keys: vec![Jwk {
                kid: "a1".into(),
                kty: "RSA".into(),
                alg: Some("RS256".into()),
                extra: Default::default(),
            }],
        };
        let set_b = JwkSet {
            keys: vec![Jwk {
                kid: "b1".into(),
                kty: "RSA".into(),
                alg: Some("RS256".into()),
                extra: Default::default(),
            }],
        };
        let shared_uri = "https://keys.example.com/.well-known/jwks.json";
        src.insert("https://auth-A.example.com", shared_uri, set_a);
        src.insert("https://auth-B.example.com", shared_uri, set_b);

        let got_a = src
            .get("https://auth-A.example.com", shared_uri, None)
            .unwrap();
        let got_b = src
            .get("https://auth-B.example.com", shared_uri, None)
            .unwrap();
        assert_eq!(got_a.keys[0].kid, "a1");
        assert_eq!(got_b.keys[0].kid, "b1");
        assert!(got_a.find_by_kid("b1").is_none(), "issuer 间 key 不得穿透");
    }

    #[test]
    fn jwk_set_find_by_kid() {
        let s = JwkSet {
            keys: vec![
                Jwk {
                    kid: "k1".into(),
                    kty: "RSA".into(),
                    alg: None,
                    extra: Default::default(),
                },
                Jwk {
                    kid: "k2".into(),
                    kty: "EC".into(),
                    alg: Some("ES256".into()),
                    extra: Default::default(),
                },
            ],
        };
        assert!(s.find_by_kid("k1").is_some());
        assert!(s.find_by_kid("k2").is_some());
        assert!(s.find_by_kid("k3").is_none());
    }

    #[test]
    fn mock_jwks_source_missing_entry_fails_closed() {
        let src = MockJwksSource::new();
        let err = src
            .get(
                "https://auth.example.com",
                "https://keys.example.com/jwks.json",
                None,
            )
            .unwrap_err();
        assert_eq!(err, HttpAuthError::TokenStoreError("jwks_not_mocked"));
    }
}
