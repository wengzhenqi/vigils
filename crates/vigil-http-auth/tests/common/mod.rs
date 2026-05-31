//! I10b-α1 integration test **本地**夹具(ADR 0011 §α1-D3)。
//!
//! 这个模块**只**被 integration tests crate 编译,**不**进 `vigil-http-auth` lib。
//! 按 Cargo 规则,`tests/common/mod.rs` 不是一个独立 test target;其他 test file 通过
//! `mod common;` 在自身作用域内 `include` 即可。
//!
//! 生产构建(`cargo build` / `cargo build --release`)**不**会编译此文件。
//!
//! **守门**:如果未来有人把 `AlwaysAcceptVerifier` 移进 `crates/vigil-http-auth/src/`,
//! `git grep "AlwaysAcceptVerifier" crates/vigil-http-auth/src/` 会立刻报警 —— R4
//! ACCEPT 的前提就是该标识符永远不出现在 `src/` 下。

#![allow(dead_code, unreachable_pub)]

use std::sync::Arc;

use vigil_http_auth::{ExpectedBinding, HttpAuthError, JoseHeader, JwtKeyVerifier};

/// α1 测试用的"所有 JWT 都接受签名"的 verifier。
///
/// α2 起被 `JwksSignatureVerifier` 替换;α1 阶段单元的"签名层"还没实装,
/// 所以测试路径通过此 verifier 直接跳过签名验证,专注回归契约 / claims / issuer。
#[derive(Debug)]
pub(crate) struct AlwaysAcceptVerifier;

impl JwtKeyVerifier for AlwaysAcceptVerifier {
    fn verify(
        &self,
        _raw_jwt: &str,
        _header: &JoseHeader,
        _expected_issuer: &str,
    ) -> Result<(), HttpAuthError> {
        Ok(())
    }
}

/// 便捷构造:把 I10a 9 条测试常用的 resource/issuer/scopes 组合封装。
pub(crate) fn binding_for_test(resource: &str, issuer: &str, scopes: &[&str]) -> ExpectedBinding {
    ExpectedBinding {
        resource: resource.to_string(),
        issuer: issuer.to_string(),
        scopes: scopes.iter().map(|s| s.to_string()).collect(),
        key_verifier: Arc::new(AlwaysAcceptVerifier),
        introspection: None,
    }
}
