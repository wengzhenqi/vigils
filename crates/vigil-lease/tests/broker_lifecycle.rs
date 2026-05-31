//! I06 LeaseBroker 生命周期 + bound 校验集成测试(ADR 0006 §D2 §D3 §D7)。
//!
//! 覆盖:
//! - mint → resolve → revoke 正常路径
//! - bound 三元组(session / server / tool)不匹配 → ContextMismatch + 审计
//! - lease 过期 → Expired(lazy 淘汰)
//! - revoke 后 resolve → NotFound(secret 立即零化)
//! - sweep_expired 清扫
//! - keychain 不可达 → StoreError + lease.mint_failed 审计
//! - shutdown drain cache

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::err_expect,
    clippy::panic
)]

use std::sync::Arc;

use vigil_audit::Ledger;
use vigil_lease::{
    InMemorySecretStore, LeaseBroker, LeaseError, MintRequest, MismatchField, ResolveContext,
    SecretStore, SecretValue,
};
use vigil_types::InjectionMethod;

fn setup() -> (Arc<Ledger>, Arc<InMemorySecretStore>, LeaseBroker, String) {
    let l = Arc::new(Ledger::open_in_memory().unwrap());
    let sid = l.start_session("i06_test", None).unwrap();
    let s: Arc<InMemorySecretStore> = Arc::new(InMemorySecretStore::new());
    let b = LeaseBroker::new(s.clone(), l.clone());
    (l, s, b, sid)
}

fn mint_req(session: &str, server: &str, tool: &str, secret_ref: &str, ttl: i64) -> MintRequest {
    MintRequest {
        secret_ref: secret_ref.into(),
        session_id: session.into(),
        server_id: server.into(),
        tool_name: tool.into(),
        approval_id: Some("approval-1".into()),
        injection_method: InjectionMethod::ChildEnv,
        ttl_secs: ttl,
    }
}

fn ctx(session: &str, server: &str, tool: &str) -> ResolveContext {
    ResolveContext {
        session_id: session.into(),
        server_id: server.into(),
        tool_name: tool.into(),
    }
}

#[test]
fn mint_resolve_revoke_happy_path() {
    let (_l, store, broker, sid) = setup();
    store
        .put("secret://gh/rw", SecretValue::new("gh_pat_xxxxx"))
        .unwrap();

    let lease = broker
        .mint_lease(mint_req(
            &sid,
            "github",
            "create_issue",
            "secret://gh/rw",
            300,
        ))
        .unwrap();
    assert_eq!(lease.secret_ref, "secret://gh/rw");
    assert_eq!(lease.bound_server_id, "github");

    let v = broker
        .resolve_value(&lease.lease_id, &ctx(&sid, "github", "create_issue"))
        .unwrap();
    assert_eq!(v.expose(), "gh_pat_xxxxx");

    broker.revoke_lease(&lease.lease_id).unwrap();
    // revoke 后 cache 里没有,应返 NotFound
    let err = broker
        .resolve_value(&lease.lease_id, &ctx(&sid, "github", "create_issue"))
        .unwrap_err();
    assert!(matches!(err, LeaseError::NotFound(_)));
}

#[test]
fn resolve_with_wrong_session_returns_context_mismatch() {
    let (l, store, broker, sid) = setup();
    store
        .put("secret://gh/rw", SecretValue::new("tok"))
        .unwrap();
    let lease = broker
        .mint_lease(mint_req(&sid, "github", "read", "secret://gh/rw", 300))
        .unwrap();
    let wrong_sid = l.start_session("other", None).unwrap();

    let err = broker
        .resolve_value(&lease.lease_id, &ctx(&wrong_sid, "github", "read"))
        .unwrap_err();
    match err {
        LeaseError::ContextMismatch { field, .. } => assert_eq!(field, MismatchField::Session),
        other => panic!("期望 Session mismatch,得到 {other:?}"),
    }

    // 审计:secret.lease_misuse_attempt 在 wrong_sid 里
    let hits = l.fts_search("lease_misuse_attempt").unwrap();
    assert!(hits
        .iter()
        .any(|h| h.event_type == "secret.lease_misuse_attempt"));
}

#[test]
fn resolve_with_wrong_server_returns_context_mismatch() {
    let (_l, store, broker, sid) = setup();
    store.put("secret://x", SecretValue::new("tok")).unwrap();
    let lease = broker
        .mint_lease(mint_req(&sid, "github", "read", "secret://x", 300))
        .unwrap();
    let err = broker
        .resolve_value(&lease.lease_id, &ctx(&sid, "gitlab", "read"))
        .unwrap_err();
    match err {
        LeaseError::ContextMismatch { field, .. } => assert_eq!(field, MismatchField::Server),
        other => panic!("期望 Server mismatch,得到 {other:?}"),
    }
}

#[test]
fn resolve_with_wrong_tool_returns_context_mismatch() {
    let (_l, store, broker, sid) = setup();
    store.put("secret://x", SecretValue::new("tok")).unwrap();
    let lease = broker
        .mint_lease(mint_req(&sid, "github", "read", "secret://x", 300))
        .unwrap();
    let err = broker
        .resolve_value(&lease.lease_id, &ctx(&sid, "github", "delete"))
        .unwrap_err();
    match err {
        LeaseError::ContextMismatch { field, .. } => assert_eq!(field, MismatchField::Tool),
        other => panic!("期望 Tool mismatch,得到 {other:?}"),
    }
}

#[test]
fn resolve_after_expiry_returns_expired_error() {
    let (_l, store, broker, sid) = setup();
    store.put("secret://x", SecretValue::new("tok")).unwrap();
    // ttl_secs = -1 → expires_at 已过
    let lease = broker
        .mint_lease(mint_req(&sid, "s", "t", "secret://x", -1))
        .unwrap();
    let err = broker
        .resolve_value(&lease.lease_id, &ctx(&sid, "s", "t"))
        .unwrap_err();
    assert!(matches!(err, LeaseError::Expired(_)));
    // lazy 淘汰:下次 resolve 应返 NotFound
    let err2 = broker
        .resolve_value(&lease.lease_id, &ctx(&sid, "s", "t"))
        .unwrap_err();
    assert!(matches!(err2, LeaseError::NotFound(_)));
}

#[test]
fn revoked_lease_resolve_fails() {
    let (_l, store, broker, sid) = setup();
    store.put("secret://x", SecretValue::new("tok")).unwrap();
    let lease = broker
        .mint_lease(mint_req(&sid, "s", "t", "secret://x", 300))
        .unwrap();
    broker.revoke_lease(&lease.lease_id).unwrap();
    let err = broker
        .resolve_value(&lease.lease_id, &ctx(&sid, "s", "t"))
        .unwrap_err();
    assert!(matches!(err, LeaseError::NotFound(_)));
}

#[test]
fn keychain_not_found_returns_store_error_and_audits() {
    let (l, _store, broker, sid) = setup();
    // store 里没 put "secret://missing"
    let err = broker
        .mint_lease(mint_req(&sid, "s", "t", "secret://missing", 300))
        .unwrap_err();
    assert!(matches!(err, LeaseError::StoreError(_)));

    let hits = l.fts_search("lease_mint_failed").unwrap();
    assert!(
        hits.iter()
            .any(|h| h.event_type == "secret.lease_mint_failed"),
        "keychain 失败必须写 secret.lease_mint_failed"
    );
}

#[test]
fn sweep_expired_removes_old_and_zeroizes() {
    let (_l, store, broker, sid) = setup();
    store.put("secret://a", SecretValue::new("v1")).unwrap();
    store.put("secret://b", SecretValue::new("v2")).unwrap();
    let _ = broker
        .mint_lease(mint_req(&sid, "s", "t", "secret://a", -10))
        .unwrap();
    let _ = broker
        .mint_lease(mint_req(&sid, "s", "t", "secret://b", 300))
        .unwrap();
    assert_eq!(broker.cache_len(), 2);
    let swept = broker.sweep_expired().unwrap();
    assert_eq!(swept, 1);
    assert_eq!(broker.cache_len(), 1);
}

#[test]
fn shutdown_drains_cache() {
    let (_l, store, broker, sid) = setup();
    store.put("secret://x", SecretValue::new("tok")).unwrap();
    broker
        .mint_lease(mint_req(&sid, "s", "t", "secret://x", 300))
        .unwrap();
    assert_eq!(broker.cache_len(), 1);
    broker.shutdown();
    assert_eq!(broker.cache_len(), 0);
}

#[test]
fn mint_writes_lease_minted_audit() {
    let (l, store, broker, sid) = setup();
    store.put("secret://x", SecretValue::new("tok")).unwrap();
    let lease = broker
        .mint_lease(mint_req(&sid, "s", "t", "secret://x", 300))
        .unwrap();
    let hits = l.fts_search("lease_minted").unwrap();
    assert!(hits.iter().any(|h| {
        h.event_type == "secret.lease_minted"
            && h.redacted_text
                .as_deref()
                .is_some_and(|t| t.contains(&lease.lease_id))
    }));
}

/// Codex R1 (I07) MUST-FIX 2 回归:`bind_tool_secret` 拒绝保留 Windows 系统 env 名,
/// 覆盖大小写不敏感。
#[test]
fn bind_tool_secret_rejects_reserved_env_keys() {
    use vigil_audit::ToolSecretBinding;
    let l = Arc::new(Ledger::open_in_memory().unwrap());
    l.register_secret_ref("secret://x", "X", "mock").unwrap();
    for name in [
        "SystemRoot",
        "systemroot",
        "WINDIR",
        "windir",
        "SYSTEMDRIVE",
    ] {
        let err = l.bind_tool_secret(&ToolSecretBinding {
            server_id: "s".into(),
            tool_name: "*".into(),
            secret_ref: "secret://x".into(),
            injection_method: "ChildEnv".into(),
            env_var_name: Some(name.into()),
        });
        assert!(
            matches!(err, Err(vigil_audit::AuditError::InvalidInput { .. })),
            "{name} 应被拒绝"
        );
    }
    // 正常 env_var_name 仍可通过
    l.bind_tool_secret(&ToolSecretBinding {
        server_id: "s".into(),
        tool_name: "*".into(),
        secret_ref: "secret://x".into(),
        injection_method: "ChildEnv".into(),
        env_var_name: Some("GITHUB_TOKEN".into()),
    })
    .unwrap();
}

/// Codex R1 (I07) MUST-FIX 2 跨 crate 一致性:vigil-audit 的 `is_reserved_env_key_name`
/// 必须与 vigil-runner 的 `is_reserved_env_key` 对所有保留 key 返回同样的结果。
#[test]
fn reserved_env_keys_are_in_sync_across_crates() {
    use vigil_audit::is_reserved_env_key_name;
    use vigil_runner::{is_reserved_env_key, RESERVED_SYSTEM_ENV_KEYS};
    // 每个 RESERVED_SYSTEM_ENV_KEYS 都应被两个 crate 同时识别
    for key in RESERVED_SYSTEM_ENV_KEYS {
        assert!(
            is_reserved_env_key(key),
            "vigil-runner is_reserved_env_key('{key}') 应 true"
        );
        assert!(
            is_reserved_env_key_name(key),
            "vigil-audit is_reserved_env_key_name('{key}') 应 true"
        );
        // 大小写不敏感
        let lower = key.to_ascii_lowercase();
        assert!(is_reserved_env_key(&lower));
        assert!(is_reserved_env_key_name(&lower));
    }
    // 非保留 key 两边都 false
    for key in ["GITHUB_TOKEN", "USER_API_KEY", "DATABASE_URL"] {
        assert!(!is_reserved_env_key(key));
        assert!(!is_reserved_env_key_name(key));
    }
}

/// Codex R1 MUST-FIX:`bind_tool_secret` 拒非 ChildEnv(直接在 registry 入口)。
#[test]
fn bind_tool_secret_rejects_non_child_env() {
    use vigil_audit::ToolSecretBinding;
    let l = Arc::new(Ledger::open_in_memory().unwrap());
    l.register_secret_ref("secret://x", "X", "mock").unwrap();
    for method in ["HttpHeader", "Pipe", "TempFile"] {
        let err = l.bind_tool_secret(&ToolSecretBinding {
            server_id: "s".into(),
            tool_name: "*".into(),
            secret_ref: "secret://x".into(),
            injection_method: method.into(),
            env_var_name: None,
        });
        assert!(
            matches!(err, Err(vigil_audit::AuditError::InvalidInput { .. })),
            "{method} 必须被拒绝"
        );
    }
}

/// Codex R1 NICE-TO-HAVE:mint 成功后 last_used_at 必须被更新。
#[test]
fn mint_updates_last_used_at() {
    use vigil_audit::ToolSecretBinding;
    let (l, store, _broker, sid) = setup();
    let broker = Arc::new(LeaseBroker::new(store.clone(), l.clone()));
    store.put("secret://x", SecretValue::new("tok")).unwrap();
    l.register_secret_ref("secret://x", "X", "mock").unwrap();
    l.bind_tool_secret(&ToolSecretBinding {
        server_id: "s".into(),
        tool_name: "*".into(),
        secret_ref: "secret://x".into(),
        injection_method: "ChildEnv".into(),
        env_var_name: Some("X_TOKEN".into()),
    })
    .unwrap();

    let before = l.list_secret_refs().unwrap()[0].last_used_at;
    assert!(before.is_none(), "register 后 last_used_at 应为 None");

    let _ = broker
        .mint_lease(mint_req(&sid, "s", "t", "secret://x", 300))
        .unwrap();

    let after = l.list_secret_refs().unwrap()[0].last_used_at;
    assert!(after.is_some(), "mint 后 last_used_at 必须被写入");
}

#[test]
fn unsupported_injection_method_fails_closed() {
    assert!(matches!(
        LeaseBroker::assert_injection_supported(InjectionMethod::HttpHeader),
        Err(LeaseError::UnsupportedInjectionMethod(
            InjectionMethod::HttpHeader
        ))
    ));
    assert!(matches!(
        LeaseBroker::assert_injection_supported(InjectionMethod::Pipe),
        Err(LeaseError::UnsupportedInjectionMethod(_))
    ));
    assert!(matches!(
        LeaseBroker::assert_injection_supported(InjectionMethod::TempFile),
        Err(LeaseError::UnsupportedInjectionMethod(_))
    ));
    // ChildEnv 通过
    assert!(LeaseBroker::assert_injection_supported(InjectionMethod::ChildEnv).is_ok());
}

#[test]
fn prepared_child_env_auto_revokes_on_drop() {
    use vigil_audit::ToolSecretBinding;
    let (l, store, _broker, sid) = setup();
    let broker = Arc::new(LeaseBroker::new(store.clone(), l.clone()));
    store.put("secret://x", SecretValue::new("tok")).unwrap();
    l.register_secret_ref("secret://x", "X", "mock").unwrap();
    l.bind_tool_secret(&ToolSecretBinding {
        server_id: "s".into(),
        tool_name: "*".into(),
        secret_ref: "secret://x".into(),
        injection_method: "ChildEnv".into(),
        env_var_name: Some("X_TOKEN".into()),
    })
    .unwrap();

    {
        let mut prepared = broker
            .prepare_child_env(
                &ResolveContext {
                    session_id: sid.clone(),
                    server_id: "s".into(),
                    tool_name: "t".into(),
                },
                None,
                300,
            )
            .unwrap();
        // Codex R1 BLOCKER-1:env 字段私有,只能通过 take_env() 单次消费
        let env = prepared.take_env().unwrap();
        assert_eq!(env.get("X_TOKEN").map(String::as_str), Some("tok"));
        assert_eq!(broker.cache_len(), 1, "prepared 期间应有 1 条 lease");
    } // drop → auto revoke
    assert_eq!(broker.cache_len(), 0, "Drop 后 cache 必须清空");
}

#[test]
fn revoke_writes_lease_revoked_audit() {
    let (l, store, broker, sid) = setup();
    store.put("secret://x", SecretValue::new("tok")).unwrap();
    let lease = broker
        .mint_lease(mint_req(&sid, "s", "t", "secret://x", 300))
        .unwrap();
    broker.revoke_lease(&lease.lease_id).unwrap();
    let hits = l.fts_search("lease_revoked").unwrap();
    assert!(hits.iter().any(|h| {
        h.event_type == "secret.lease_revoked"
            && h.redacted_text
                .as_deref()
                .is_some_and(|t| t.contains(&lease.lease_id))
    }));
}
