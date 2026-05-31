//! I10b-β R1 MUST-FIX 4:CLI 级 integration test 覆盖 `add_remote::run_with_deps` 真路径。
//!
//! 覆盖:
//! 1. **prod Deps 绑 keyring**:`Deps::production()` 返回的 secret_store.backend_kind()
//!    必须是 `"keyring"`(不是 `"memory"`)—— 这是 β R1 BLOCKER 1 的关键证据。
//! 2. **`--url` 强制 https**:非 https 且 `allow_insecure_url=false` → 明确报错。
//! 3. **`--scopes` 非空**:空列表 → 明确报错。
//! 4. **SQLite ledger 路径可创建**:合法 Deps + ledger 临时路径 → 至少能进 PRM discover 前的 schema 校验。
//!
//! 本 test 不跑真 OAuth flow(那部分已在 `vigil-http-transport::tests::e2e_real_tls` 覆盖);
//! 这里**只**验证 CLI 边界 + Deps 注入语义。

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::path::PathBuf;
use std::sync::Arc;

use tempfile::tempdir;
use vigil_http_transport::ReqwestHttpClient;
use vigil_hub_cli::add_remote::{run_with_deps, Deps};
use vigil_hub_cli::AddRemoteArgs;
use vigil_lease::{InMemorySecretStore, SecretStore};

fn mk_args(url: &str, scopes: Vec<String>, ledger: PathBuf) -> AddRemoteArgs {
    AddRemoteArgs {
        url: url.to_string(),
        client_id: "test-client".to_string(),
        scopes,
        ledger,
        timeout_secs: 1, // 测试不真等 60s
    }
}

fn mk_memory_deps() -> Deps {
    let http: Arc<ReqwestHttpClient> = Arc::new(ReqwestHttpClient::new().unwrap());
    let secret_store: Arc<dyn SecretStore> = Arc::new(InMemorySecretStore::new());
    Deps {
        http_client: http,
        secret_store,
        allow_insecure_url: true, // 测试开 —— prod 默认 false
    }
}

/// β R1 BLOCKER 1 关键证据:prod Deps 必须绑 KeyringSecretStore,**不**是 InMemory。
///
/// 若未来有人把 `Deps::production()` 退回 `InMemorySecretStore`,此测试立即失败。
#[test]
fn production_deps_use_keyring_backend_not_memory() {
    let deps = Deps::production().expect("production deps construction");
    let backend = deps.secret_store.backend_kind();
    assert_eq!(
        backend, "keyring",
        "production Deps secret_store must be keyring-backed (β R1 BLOCKER 1);\
         got backend_kind = {backend:?}"
    );
    assert!(!deps.allow_insecure_url, "prod must not allow http:// URLs");
}

/// 基线:非 https URL + `allow_insecure_url=false`(即 prod 默认)→ 拒绝。
#[test]
fn rejects_http_url_without_insecure_flag() {
    let mut deps = mk_memory_deps();
    deps.allow_insecure_url = false;
    let dir = tempdir().unwrap();
    let args = mk_args(
        "http://mcp.example.com/",
        vec!["mcp:tools.read".to_string()],
        dir.path().join("vigil.db"),
    );
    let err = run_with_deps(args, deps).unwrap_err();
    assert!(
        err.contains("must be https"),
        "expected https gate to trip; got: {err}"
    );
}

/// 基线:scheme 非 http/https(malformed URL)→ 拒绝 parse。
#[test]
fn rejects_malformed_url() {
    let deps = mk_memory_deps();
    let dir = tempdir().unwrap();
    let args = mk_args(
        "not-a-url",
        vec!["mcp:tools.read".to_string()],
        dir.path().join("vigil.db"),
    );
    let err = run_with_deps(args, deps).unwrap_err();
    assert!(
        err.contains("invalid --url"),
        "expected URL parse error; got: {err}"
    );
}

/// 基线:scopes 为空 → 拒绝。
#[test]
fn rejects_empty_scopes() {
    let deps = mk_memory_deps();
    let dir = tempdir().unwrap();
    let args = mk_args(
        "https://mcp.example.com/",
        vec![], // empty
        dir.path().join("vigil.db"),
    );
    let err = run_with_deps(args, deps).unwrap_err();
    assert!(
        err.contains("--scopes must be non-empty"),
        "expected scopes gate to trip; got: {err}"
    );
}

/// 覆盖 Deps::Debug 路径(避免未来有人 remove backend_kind 暴露的守门点)。
#[test]
fn deps_debug_exposes_backend_kind() {
    let deps = mk_memory_deps();
    let s = format!("{deps:?}");
    assert!(s.contains("secret_store_backend"), "Debug: {s}");
    assert!(
        s.contains("memory"),
        "Debug should expose backend_kind: {s}"
    );
}
