//! 可逆脱敏 Slice 2 对抗测试:`secret://<alias>` 在工具边界 detokenize。
//!
//! 验证往返的 **args 半边**(Slice 1 已验结果半边):agent 在 tool args 里写 `secret://<alias>`
//! 占位符(远端 LLM 只见占位符),Vigil 在 `invoke_upstream` 的 detokenize seam 把它替换成**真值**
//! 后才送上游;而真值**绝不**进审计账本。覆盖设计 D3/D4 + Codex review 对抗清单:
//! - 核心往返:upstream 收到真值、占位符已消解、真值不入账本
//! - H2 子串替换:`Bearer secret://x` / URL 内嵌 alias 被消解
//! - H5 oracle 防御:跨 server alias 解析 deny
//! - 未知 alias fail-closed deny(+ `secret.alias_unresolved` 审计)
//! - 精确 token:`secret://k2` 解析为 `k2`(不与 `secret://k` 混淆);未声明则 deny
//! - object key 位 `secret://` deny(不支持改写 key)
//!
//! 用 `CapturingUpstream`(记录收到的 params)替代真实 transport,直接断言"上游实际收到什么"。

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::err_expect,
    clippy::panic
)]

use std::sync::{Arc, Mutex};
use std::time::Duration;

use serde_json::{json, Value};
use sha2::{Digest, Sha256};

use vigil_audit::Ledger;
use vigil_firewall::{scorer::StaticDescriptorOracle, Firewall, FirewallConfig};
use vigil_lease::SecretValue;
use vigil_mcp::protocol::JsonRpcRequest;
use vigil_mcp::upstream::{McpUpstream, UpstreamError};
use vigil_mcp::{
    compute_argv_hash, Hub, HubConfig, JsonRpcError, SecretAliasMap, EVENT_SECRET_ALIAS_UNRESOLVED,
};
use vigil_policy::{defaults::default_ruleset, PolicyEngine};
use vigil_types::{
    ApprovalScope, DecisionKind, DecisionRecord, EffectVector, ServerProfile, TransportKind,
    TrustLevel,
};

/// 记录"上游实际收到的 params"的 Mock 上游 —— 让测试断言 detokenize 后送出的真值。
#[derive(Debug)]
struct CapturingUpstream {
    server_id: String,
    /// 最近一次 `call` 收到的 `params`(含 `arguments` —— 即 detokenize 后的真值)。
    last_params: Mutex<Option<Value>>,
}

impl CapturingUpstream {
    fn new(server_id: &str) -> Self {
        Self {
            server_id: server_id.to_string(),
            last_params: Mutex::new(None),
        }
    }
    /// 取最近一次 upstream 收到的 `arguments`(detokenize 结果)。
    fn last_arguments(&self) -> Option<Value> {
        self.last_params
            .lock()
            .unwrap()
            .as_ref()
            .and_then(|p| p.get("arguments").cloned())
    }
}

impl McpUpstream for CapturingUpstream {
    fn server_id(&self) -> &str {
        &self.server_id
    }
    fn transport(&self) -> TransportKind {
        TransportKind::Stdio
    }
    fn call(
        &self,
        _method: &str,
        params: Option<Value>,
        _timeout: Duration,
    ) -> Result<Value, UpstreamError> {
        *self.last_params.lock().unwrap() = params;
        Ok(json!({ "ok": true }))
    }
    fn shutdown(&self) {}
}

fn jcs_hash(v: &Value) -> String {
    let b = serde_jcs::to_vec(v).unwrap();
    let mut h = Sha256::new();
    h.update(&b);
    hex::encode(h.finalize())
}

/// 装一个 Hub + ledger + capturing upstream(server_id="fs", tool="read_file"),注入指定
/// `aliases`,并预埋一条匹配 `call_args` 的 ThisSession approval 让调用走 scope 快路径进
/// `invoke_upstream`(scope 快路径在 alias 决策前门**之后**,故 deny 测试仍会先被前门拦)。
fn setup(
    aliases: SecretAliasMap,
    call_args: &Value,
) -> (Arc<Ledger>, Arc<Hub>, String, Arc<CapturingUpstream>) {
    let l = Arc::new(Ledger::open_in_memory().unwrap());
    let policy = PolicyEngine::new(default_ruleset());
    let fw = Arc::new(Firewall::new(
        l.clone(),
        policy,
        FirewallConfig {
            project_roots: vec!["/proj".into()],
            ..Default::default()
        },
    ));
    let oracle: Arc<dyn vigil_firewall::scorer::DescriptorOracle> = Arc::new(
        StaticDescriptorOracle(vigil_firewall::scorer::DescriptorStatus::ApprovedStable),
    );
    let hub = Arc::new(Hub::new(
        l.clone(),
        fw,
        oracle,
        HubConfig {
            approval_wait: Duration::from_millis(200),
            ..Default::default()
        },
        aliases,
    ));

    let argv = vec!["mock".to_string()];
    let command_hash = compute_argv_hash(&argv).unwrap();
    let profile = ServerProfile {
        server_id: "fs".into(),
        transport: TransportKind::Stdio,
        command: Some(argv.clone()),
        url: None,
        first_seen_at: 0,
        command_hash: Some(command_hash),
        descriptor_hash: None,
        trust_level: TrustLevel::Untrusted,
        sandbox_profile_id: None,
    };
    l.register_server(&profile).unwrap();
    l.approve_server("fs", TrustLevel::Limited).unwrap();

    let cap = Arc::new(CapturingUpstream::new("fs"));
    hub.attach_upstream("fs", &argv, cap.clone()).unwrap();

    let session_id = l.start_session("alias_test", None).unwrap();
    hub.set_session_id_for_test(&session_id).unwrap();
    hub.inject_route_for_test("fs", "read_file", "hash_abc")
        .unwrap();

    // 预埋 ThisSession approval,匹配 (fs, read_file, hash(call_args))
    let args_hash = jcs_hash(call_args);
    let dec = DecisionRecord {
        decision_id: "d-prev".into(),
        invocation_id: "inv-prev".into(),
        decision: DecisionKind::Approve,
        risk_score: 0,
        reasons: vec![],
        policy_ids: vec![],
        created_at: 0,
    };
    let ctx = vigil_audit::ApprovalTargetContext {
        server_id: Some("fs"),
        tool_name: Some("read_file"),
        args_hash: Some(&args_hash),
    };
    let prev = l
        .create_approval(
            &session_id,
            &dec,
            &EffectVector::default(),
            "t",
            "s",
            600,
            ctx,
        )
        .unwrap();
    l.approve(&prev.approval_id, ApprovalScope::ThisSession, Some("u"))
        .unwrap();

    (l, hub, session_id, cap)
}

fn call_with_args(hub: &Hub, args: &Value) -> vigil_mcp::protocol::JsonRpcResponse {
    let req = JsonRpcRequest {
        jsonrpc: "2.0".into(),
        id: Some(json!(7)),
        method: "tools/call".into(),
        params: Some(json!({ "name": "fs__read_file", "arguments": args })),
    };
    hub.handle_request(req).unwrap().unwrap()
}

/// 一条 server-scoped alias 的便捷构造。
fn alias_map(entries: &[(&str, &str, &str)]) -> SecretAliasMap {
    let mut m = SecretAliasMap::default();
    for (alias, value, server) in entries {
        m.insert(*alias, SecretValue::new(*value), *server);
    }
    m
}

/// 断言整条审计链的任何事件 payload / summary 里都**不含** `needle`(真值不入账本不变量)。
fn assert_value_not_in_ledger(l: &Ledger, session_id: &str, needle: &str) {
    let events = l.replay_session_verified(session_id).unwrap();
    for e in &events {
        let payload_str = serde_json::to_string(&e.payload).unwrap();
        assert!(
            !payload_str.contains(needle),
            "真值绝不能出现在审计事件 `{}` payload 里: {payload_str}",
            e.event_type
        );
        if let Some(redacted) = &e.redacted_text {
            assert!(
                !redacted.contains(needle),
                "真值绝不能出现在事件 `{}` redacted_text 里: {redacted}",
                e.event_type
            );
        }
    }
}

// ── 核心往返:upstream 收真值、占位符消解、真值不入账本 ──────────────────────────

#[test]
fn alias_resolves_real_value_to_upstream_and_value_never_in_ledger() {
    let real = "ghp_REAL_VALUE_1234567890abcdef1234567890";
    let args = json!({ "path": "secret://gh_token" });
    let (l, hub, session_id, cap) = setup(alias_map(&[("gh_token", real, "fs")]), &args);

    let resp = call_with_args(&hub, &args);
    assert!(resp.error.is_none(), "合法 alias 应放行, got: {resp:?}");

    // 上游实际收到的 arguments.path 必须是**真值**,不再是占位符
    let got = cap.last_arguments().expect("upstream 应被调用");
    assert_eq!(
        got.get("path").and_then(Value::as_str),
        Some(real),
        "upstream 必须收到 detokenize 后的真值"
    );
    assert!(
        !serde_json::to_string(&got).unwrap().contains("secret://"),
        "占位符必须已消解,不得残留 secret://"
    );

    // 真值绝不入账本(no-plaintext 不变量;只有占位符可能留痕)
    assert_value_not_in_ledger(&l, &session_id, real);
}

// ── H2 子串替换:URL / Bearer 内嵌 alias ────────────────────────────────────────

#[test]
fn alias_embedded_in_url_is_substring_resolved() {
    let real = "ghp_EMBEDDED_tok_abcdef1234567890abcdef1234";
    // 注意:刻意**不**用 `access_token=secret://...` —— 那会先被 Slice 1 raw-secret 门的
    // env_assignment 规则(`*token=<非空>`)拦下(strip 后仍像 `key=value`,纵深防御正确行为)。
    // 用非 marker 查询键 `ref=`(env_assignment 不命中)+ Bearer header(H2 典型嵌入)验子串替换。
    let args = json!({
        "url": "https://api.example.com/repos?ref=secret://gh_token&page=1",
        "header": "Authorization: Bearer secret://gh_token"
    });
    let (l, hub, session_id, cap) = setup(alias_map(&[("gh_token", real, "fs")]), &args);

    let resp = call_with_args(&hub, &args);
    assert!(resp.error.is_none(), "合法嵌入 alias 应放行, got: {resp:?}");

    let got = cap.last_arguments().unwrap();
    assert_eq!(
        got.get("url").and_then(Value::as_str),
        Some(format!("https://api.example.com/repos?ref={real}&page=1").as_str()),
        "URL 内嵌 alias 必须子串替换为真值,保留前后文(& 终止 token)"
    );
    assert_eq!(
        got.get("header").and_then(Value::as_str),
        Some(format!("Authorization: Bearer {real}").as_str()),
        "Bearer 内嵌 alias 必须子串替换"
    );
    assert_value_not_in_ledger(&l, &session_id, real);
}

// ── H5 oracle 防御:跨 server alias deny ────────────────────────────────────────

#[test]
fn cross_server_alias_is_denied() {
    // alias 限定到 "other"(≠ 本次 route 的 "fs")→ 决策前门 deny,upstream 不被调用
    let args = json!({ "path": "secret://gh_token" });
    let (_l, hub, _sid, cap) = setup(alias_map(&[("gh_token", "ghp_REAL_xxxx", "other")]), &args);

    let resp = call_with_args(&hub, &args);
    assert!(resp.error.is_some(), "跨 server alias 必须 deny");
    assert_eq!(
        resp.error.as_ref().unwrap().code,
        JsonRpcError::VIGIL_DENIED
    );
    assert!(
        cap.last_arguments().is_none(),
        "deny 时 upstream 绝不能被调用(无真值送出)"
    );
}

// ── 未知 alias fail-closed deny + 审计 ──────────────────────────────────────────

#[test]
fn unknown_alias_fail_closed_deny_with_audit() {
    let args = json!({ "path": "secret://nonexistent" });
    // map 里只有 gh_token,引用 nonexistent → Unknown → deny
    let (l, hub, session_id, cap) = setup(alias_map(&[("gh_token", "ghp_REAL_xxxx", "fs")]), &args);

    let resp = call_with_args(&hub, &args);
    assert!(resp.error.is_some(), "未知 alias 必须 fail-closed deny");
    assert_eq!(
        resp.error.as_ref().unwrap().code,
        JsonRpcError::VIGIL_DENIED
    );
    assert!(cap.last_arguments().is_none(), "deny 时 upstream 不被调用");

    // 必须产 secret.alias_unresolved 审计事件
    let events = l.replay_session_verified(&session_id).unwrap();
    assert!(
        events
            .iter()
            .any(|e| e.event_type == EVENT_SECRET_ALIAS_UNRESOLVED),
        "未知 alias deny 必须留 secret.alias_unresolved 审计,实际: {:?}",
        events.iter().map(|e| &e.event_type).collect::<Vec<_>>()
    );
}

// ── 精确 token:secret://k2 不与 secret://k 混淆 ─────────────────────────────────

#[test]
fn exact_token_resolution_no_prefix_confusion() {
    // 只声明 k2;引用 secret://k2 应解析为 k2 的真值(贪婪取完整 body)
    let real_k2 = "VALUE_FOR_K2_abcdef";
    let args = json!({ "v": "secret://k2" });
    let (_l, hub, _sid, cap) = setup(alias_map(&[("k2", real_k2, "fs")]), &args);

    let resp = call_with_args(&hub, &args);
    assert!(resp.error.is_none(), "secret://k2 应解析为 alias k2");
    assert_eq!(
        cap.last_arguments()
            .unwrap()
            .get("v")
            .and_then(Value::as_str),
        Some(real_k2)
    );
}

#[test]
fn shorter_prefix_alias_not_matched_by_longer_token() {
    // 只声明 k;引用 secret://k2 → token 贪婪取 "k2"(≠ "k")→ Unknown{k2} → deny。
    // 杜绝 naive substring 把 secret://k2 当成 secret://k + 残留 "2"。
    let args = json!({ "v": "secret://k2" });
    let (_l, hub, _sid, cap) = setup(alias_map(&[("k", "VALUE_FOR_K", "fs")]), &args);

    let resp = call_with_args(&hub, &args);
    assert!(
        resp.error.is_some(),
        "secret://k2 不应被 alias k 部分匹配,必须 deny"
    );
    assert_eq!(
        resp.error.as_ref().unwrap().code,
        JsonRpcError::VIGIL_DENIED
    );
    assert!(cap.last_arguments().is_none());
}

// ── object key 位 secret:// deny ────────────────────────────────────────────────

#[test]
fn secret_alias_in_object_key_is_denied() {
    // alias 落在 object KEY 位 → KeyPosition → deny(不支持改写 key)
    let mut obj = serde_json::Map::new();
    obj.insert("secret://gh_token".to_string(), json!("x"));
    let args = Value::Object(obj);
    let (_l, hub, _sid, cap) = setup(alias_map(&[("gh_token", "ghp_REAL_xxxx", "fs")]), &args);

    let resp = call_with_args(&hub, &args);
    assert!(resp.error.is_some(), "key 位 secret:// 必须 deny");
    assert_eq!(
        resp.error.as_ref().unwrap().code,
        JsonRpcError::VIGIL_DENIED
    );
    assert!(cap.last_arguments().is_none());
}

// ── 嵌套 array / object 递归 detokenize ─────────────────────────────────────────

#[test]
fn nested_array_alias_resolved() {
    let real = "ghp_NESTED_abcdef1234567890abcdef1234567890";
    let args = json!({ "items": ["a", "secret://gh_token", { "k": "secret://gh_token" }] });
    let (l, hub, session_id, cap) = setup(alias_map(&[("gh_token", real, "fs")]), &args);

    let resp = call_with_args(&hub, &args);
    assert!(resp.error.is_none());
    let got = cap.last_arguments().unwrap();
    let items = got.get("items").and_then(Value::as_array).unwrap();
    assert_eq!(items[1].as_str(), Some(real), "array 内 alias 应解析");
    assert_eq!(
        items[2].get("k").and_then(Value::as_str),
        Some(real),
        "嵌套 object value 内 alias 应解析"
    );
    assert_value_not_in_ledger(&l, &session_id, real);
}

// ── Code R1 High:不可信 alias body 绝不回显到错误/审计 ──────────────────────────

#[test]
fn raw_secret_in_alias_position_denied_and_not_echoed() {
    // 把真 secret 伪装成 alias 引用:`secret://ghp_...`。`strip_aliases` 会豁免它绕过 raw-secret 门,
    // 但 resolve 必须显式拒(RawSecretInAlias)+ 错误响应(回给 agent/LLM)**绝不**含该 secret。
    let raw = "ghp_1234567890abcdef1234567890abcdef12345678";
    let args = json!({ "path": format!("secret://{raw}") });
    let (l, hub, session_id, cap) = setup(alias_map(&[("gh_token", "ghp_REAL_xxxx", "fs")]), &args);

    let resp = call_with_args(&hub, &args);
    assert!(resp.error.is_some(), "alias 位塞真 secret 必须 deny");
    assert_eq!(
        resp.error.as_ref().unwrap().code,
        JsonRpcError::VIGIL_DENIED
    );
    assert!(cap.last_arguments().is_none(), "deny 时上游不被调用");
    // 关键:回给 agent/LLM 的错误响应绝不能含原 secret
    let err_str = serde_json::to_string(&resp.error).unwrap();
    assert!(
        !err_str.contains(raw),
        "错误响应不得回显 alias 位的真 secret: {err_str}"
    );
    // 账本同样不得含原 secret
    assert_value_not_in_ledger(&l, &session_id, raw);
}

#[test]
fn unknown_alias_error_does_not_echo_alias_body() {
    // 非指纹但敏感的 alias body(模拟攻击者塞入不希望泄漏的内容)→ Unknown → reason 用 sha256 前缀,
    // **不回显**原文。守 Code R1 High:错误回 agent/LLM 时不泄漏不可信 alias 原文。
    let sensitive = "supersensitive_payload_not_a_fingerprint_zzz";
    let args = json!({ "v": format!("secret://{sensitive}") });
    let (_l, hub, _sid, _cap) = setup(alias_map(&[("k", "v", "fs")]), &args);

    let resp = call_with_args(&hub, &args);
    assert!(resp.error.is_some(), "未知 alias 应 deny");
    let err_str = serde_json::to_string(&resp.error).unwrap();
    assert!(
        !err_str.contains(sensitive),
        "unknown alias 错误不得回显 alias 原文: {err_str}"
    );
    assert!(
        err_str.contains("sha256:"),
        "应以 sha256 前缀关联(而非原文): {err_str}"
    );
}
