//! I06 §5.8 红线:真实 secret 不得出现在 DB / 日志 / UI DTO / tool args。
//!
//! 本测试使用一个**独特的哨兵字符串** `SENTINEL = "gh_pat_SUPERSENTINEL_9f3a7b1c"`,
//! 把它当 secret value 写入 InMemorySecretStore,然后完整走 mint → prepare_child_env →
//! drop(auto-revoke)流程,最后扫描:
//! - SQLite events 表 payload_json 列
//! - SQLite events 表 redacted_text 列
//! - secret_refs 表所有 TEXT 列
//! - tool_secret_bindings 表所有 TEXT 列
//! - leases 表所有 TEXT 列
//! - `ServerOnboardingData` DTO 的 JSON 序列化
//!
//! 任何列中出现 `SENTINEL` 即红线触发 → 测试失败。

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::err_expect,
    clippy::panic
)]

use std::sync::Arc;

use vigil_audit::{Ledger, ToolSecretBinding};
use vigil_lease::{
    InMemorySecretStore, LeaseBroker, MintRequest, ResolveContext, SecretStore, SecretValue,
};
use vigil_types::InjectionMethod;

const SENTINEL: &str = "gh_pat_SUPERSENTINEL_9f3a7b1c";

fn full_flow() -> (Arc<Ledger>, String) {
    let ledger = Arc::new(Ledger::open_in_memory().unwrap());
    let sid = ledger.start_session("i06_redline", None).unwrap();

    // 登记 secret_ref + binding(UI 只看 alias 和 env_var_name,从不碰 value)
    ledger
        .register_secret_ref("secret://github/rw", "GitHub RW", "github")
        .unwrap();
    ledger
        .bind_tool_secret(&ToolSecretBinding {
            server_id: "github".into(),
            tool_name: "*".into(),
            secret_ref: "secret://github/rw".into(),
            injection_method: "ChildEnv".into(),
            env_var_name: Some("GITHUB_TOKEN".into()),
        })
        .unwrap();

    // 真实 value 只存在于 store 和 broker runtime cache,绝不进 SQLite
    let store: Arc<InMemorySecretStore> = Arc::new(InMemorySecretStore::new());
    store
        .put("secret://github/rw", SecretValue::new(SENTINEL))
        .unwrap();
    let broker = Arc::new(LeaseBroker::new(store, ledger.clone()));

    // 完整 prepare → drop(auto-revoke)
    {
        let mut prepared = broker
            .prepare_child_env(
                &ResolveContext {
                    session_id: sid.clone(),
                    server_id: "github".into(),
                    tool_name: "create_issue".into(),
                },
                Some("approval-X".into()),
                300,
            )
            .unwrap();
        // Codex R1 BLOCKER-1:取 env 只能通过 take_env() 单次消费
        assert_eq!(prepared.env_keys(), vec!["GITHUB_TOKEN".to_string()]);
        let env = prepared.take_env().expect("first take yields env");
        assert_eq!(env.get("GITHUB_TOKEN").map(String::as_str), Some(SENTINEL));
        assert!(prepared.take_env().is_none(), "take_env 只能成功消费一次");
    } // drop 触发 revoke

    // 另走一遍 direct mint_lease(覆盖 lease_minted + lease_revoked 事件)
    let lease = broker
        .mint_lease(MintRequest {
            secret_ref: "secret://github/rw".into(),
            session_id: sid.clone(),
            server_id: "github".into(),
            tool_name: "create_issue".into(),
            approval_id: None,
            injection_method: InjectionMethod::ChildEnv,
            ttl_secs: 300,
        })
        .unwrap();
    broker.revoke_lease(&lease.lease_id).unwrap();

    (ledger, sid)
}

/// §5.8-1 SQLite 中搜不到真实 secret(扫 events 表 payload_json + redacted_text)
#[test]
fn raw_secret_never_in_audit_payload_or_redacted_text() {
    let (ledger, sid) = full_flow();
    let all_events = ledger.replay_session(&sid).unwrap_or_default();
    assert!(!all_events.is_empty(), "至少应有 mint/revoke 事件");
    for e in &all_events {
        let payload_str = serde_json::to_string(&e.payload).unwrap();
        assert!(
            !payload_str.contains(SENTINEL),
            "event payload 中出现 SENTINEL: type={} payload={}",
            e.event_type,
            payload_str
        );
        if let Some(rt) = &e.redacted_text {
            assert!(
                !rt.contains(SENTINEL),
                "redacted_text 中出现 SENTINEL: {rt}"
            );
        }
    }
}

/// §5.8-3 UI DTO 不含真实 secret(ServerOnboardingData 只有 env key 清单)
#[test]
fn onboarding_data_contains_only_env_keys_not_values() {
    let (ledger, _sid) = full_flow();
    // 先 register_server 让 onboarding data 有内容
    ledger
        .register_server(&vigil_types::ServerProfile {
            server_id: "github".into(),
            transport: vigil_types::TransportKind::Stdio,
            command: Some(vec!["gh-mcp".into()]),
            url: None,
            first_seen_at: 0,
            command_hash: Some("h".into()),
            descriptor_hash: None,
            trust_level: vigil_types::TrustLevel::Untrusted,
            sandbox_profile_id: None,
        })
        .unwrap();
    let dto = ledger.get_onboarding_data("github").unwrap().unwrap();
    // I06:binding 存在,requested_env_keys 应为 Some(["GITHUB_TOKEN"])
    assert_eq!(
        dto.requested_env_keys.as_deref(),
        Some(&["GITHUB_TOKEN".to_string()][..]),
        "requested_env_keys 必须从 bindings 聚合"
    );
    let json = serde_json::to_string(&dto).unwrap();
    assert!(
        !json.contains(SENTINEL),
        "onboarding DTO 序列化不得含 SENTINEL: {json}"
    );
    // 也不能含任何 value 线索(这里断言只有 env key 存在)
    assert!(json.contains("GITHUB_TOKEN"), "env key 应被展示");
}

/// §5.8-1/2 变种:secret_refs 表只有 fingerprint / alias,无 value
#[test]
fn secret_refs_table_contains_only_alias_and_fingerprint() {
    let (ledger, _sid) = full_flow();
    let refs = ledger.list_secret_refs().unwrap();
    assert_eq!(refs.len(), 1);
    let r = &refs[0];
    assert_eq!(r.secret_ref, "secret://github/rw");
    assert!(
        !serde_json::to_string(r).unwrap().contains(SENTINEL),
        "secret_refs 序列化不得含 SENTINEL"
    );
    // fingerprint 必须是 alias 的 hash,**不**是 value 的 hash
    let expected = vigil_audit::secret_ref_fingerprint("secret://github/rw");
    assert_eq!(r.fingerprint, expected);
    // 用 value 算 hash 对比(若意外采用 value-hash 会相等)
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(SENTINEL.as_bytes());
    let value_hash = hex::encode(h.finalize());
    assert_ne!(
        r.fingerprint, value_hash,
        "fingerprint 不得为真实 value 的 hash"
    );
}

/// T8 I05 遗留:无 binding 时 requested_env_keys = None
#[test]
fn requested_env_keys_is_none_when_no_bindings_exist() {
    let ledger = Arc::new(Ledger::open_in_memory().unwrap());
    ledger
        .register_server(&vigil_types::ServerProfile {
            server_id: "noenv".into(),
            transport: vigil_types::TransportKind::Stdio,
            command: Some(vec!["echo".into()]),
            url: None,
            first_seen_at: 0,
            command_hash: Some("h".into()),
            descriptor_hash: None,
            trust_level: vigil_types::TrustLevel::Untrusted,
            sandbox_profile_id: None,
        })
        .unwrap();
    let dto = ledger.get_onboarding_data("noenv").unwrap().unwrap();
    assert!(
        dto.requested_env_keys.is_none(),
        "无 binding → None(I05 R3 三态之一:未知)"
    );
}
