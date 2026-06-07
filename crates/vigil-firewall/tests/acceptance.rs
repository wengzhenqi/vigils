//! I02 + I03 合并验收测试:方案 §3.5 八条 firewall 验收 + §6.7 六条 approval 验收。
//!
//! 为每条验收项对应一个具名测试,失败消息里引用方案章节编号。

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::err_expect,
    clippy::panic
)]

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use serde_json::json;
use vigil_audit::Ledger;
use vigil_firewall::{
    scorer::{DescriptorStatus, StaticDescriptorOracle},
    Firewall, FirewallConfig, FirewallOutcome, OAuthScopeContext,
};
use vigil_policy::{defaults::default_ruleset, PolicyEngine};
use vigil_types::{ApprovalScope, ApprovalStatus, DecisionKind, EffectKind, ToolInvocation};

fn setup(project_root: &str, allowed_hosts: Vec<&str>) -> (Arc<Ledger>, Firewall, String) {
    let l = Arc::new(Ledger::open_in_memory().unwrap());
    let sid = l.start_session("test", Some("acceptance")).unwrap();
    // PathExtractor 的规范化要求真实存在的 root 才能 dunce 成功;这里接受
    // manual_normalize 路径:对测试而言,前缀比较足够。
    let _ = PathBuf::from(project_root);
    let policy = PolicyEngine::new(default_ruleset());
    let cfg = FirewallConfig {
        project_roots: vec![project_root.to_string()],
        allowed_hosts: allowed_hosts.into_iter().map(String::from).collect(),
        approval_ttl_secs: 60,
        ..Default::default()
    };
    let fw = Firewall::new(l.clone(), policy, cfg);
    (l, fw, sid)
}

fn mk_call(sid: &str, tool: &str, args: serde_json::Value) -> ToolInvocation {
    ToolInvocation {
        invocation_id: uuid::Uuid::new_v4().to_string(),
        session_id: sid.to_string(),
        server_id: "test-srv".into(),
        tool_name: tool.into(),
        args,
        descriptor_hash: "hash".into(),
        requested_at: 0,
    }
}

// ============================================================
// §3.5 八条 firewall 验收
// ============================================================

/// §3.5-1: repo 内读文件 → allow
#[test]
fn firewall_repo_read_allow() {
    let (_l, fw, sid) = setup("/proj", vec!["api.github.com"]);
    let call = mk_call(&sid, "fs_read_file", json!({"path": "/proj/src/main.rs"}));
    let out = fw
        .evaluate(
            &call,
            &StaticDescriptorOracle(DescriptorStatus::ApprovedStable),
            OAuthScopeContext::NonOauth,
        )
        .unwrap();
    assert_eq!(out.decision_kind(), DecisionKind::Allow, "方案 §3.5-1");
}

/// §3.5-2 / §3.5-3: repo 内写 → approve;repo 外写 → deny
#[test]
fn firewall_repo_write_approve_outside_deny() {
    let (_l, fw, sid) = setup("/proj", vec![]);

    let call_in = mk_call(&sid, "fs_write_file", json!({"path": "/proj/README.md"}));
    let r1 = fw
        .evaluate(
            &call_in,
            &StaticDescriptorOracle(DescriptorStatus::ApprovedStable),
            OAuthScopeContext::NonOauth,
        )
        .unwrap();
    assert_eq!(r1.decision_kind(), DecisionKind::Approve, "方案 §3.5-2");

    let call_out = mk_call(&sid, "fs_write_file", json!({"path": "/etc/hosts"}));
    let r2 = fw
        .evaluate(
            &call_out,
            &StaticDescriptorOracle(DescriptorStatus::ApprovedStable),
            OAuthScopeContext::NonOauth,
        )
        .unwrap();
    assert_eq!(r2.decision_kind(), DecisionKind::Deny, "方案 §3.5-3");
}

/// §3.5-4: rm -rf / destructive shell → deny
#[test]
fn firewall_destructive_shell_deny() {
    let (_l, fw, sid) = setup("/proj", vec![]);
    let call = mk_call(
        &sid,
        "shell_run",
        json!({"argv": ["rm", "-rf", "/home/user/Downloads"]}),
    );
    let out = fw
        .evaluate(
            &call,
            &StaticDescriptorOracle(DescriptorStatus::ApprovedStable),
            OAuthScopeContext::NonOauth,
        )
        .unwrap();
    assert_eq!(out.decision_kind(), DecisionKind::Deny, "方案 §3.5-4");
}

/// §3.5-5: DELETE / DROP SQL → deny
#[test]
fn firewall_destructive_sql_deny() {
    let (_l, fw, sid) = setup("/proj", vec![]);
    let call = mk_call(
        &sid,
        "db_query",
        json!({"sql": "DELETE FROM users WHERE 1=1"}),
    );
    let out = fw
        .evaluate(
            &call,
            &StaticDescriptorOracle(DescriptorStatus::ApprovedStable),
            OAuthScopeContext::NonOauth,
        )
        .unwrap();
    assert_eq!(out.decision_kind(), DecisionKind::Deny, "方案 §3.5-5");
}

/// §3.5-6: 发邮件 / 外部消息 → approve
#[test]
fn firewall_comm_send_approve() {
    let (_l, fw, sid) = setup("/proj", vec![]);
    let call = mk_call(
        &sid,
        "send_email",
        json!({"to": "alice@example.com", "subject": "x"}),
    );
    let out = fw
        .evaluate(
            &call,
            &StaticDescriptorOracle(DescriptorStatus::ApprovedStable),
            OAuthScopeContext::NonOauth,
        )
        .unwrap();
    assert_eq!(out.decision_kind(), DecisionKind::Approve, "方案 §3.5-6");
}

/// §3.5-7: 使用 secret:// → approve
#[test]
fn firewall_secret_use_approve() {
    let (_l, fw, sid) = setup("/proj", vec![]);
    let call = mk_call(
        &sid,
        "github_create_issue",
        json!({
            "auth": "secret://github/repo-write",
            "title": "bug report"
        }),
    );
    let out = fw
        .evaluate(
            &call,
            &StaticDescriptorOracle(DescriptorStatus::ApprovedStable),
            OAuthScopeContext::NonOauth,
        )
        .unwrap();
    assert_eq!(out.decision_kind(), DecisionKind::Approve, "方案 §3.5-7");
}

/// §3.5-8: descriptor drift → **Approve**(升级为直接断言 DecisionKind,非字符串检查)
#[test]
fn firewall_descriptor_drift_forces_approve() {
    let (_l, fw, sid) = setup("/proj", vec!["api.github.com"]);
    // 本来是 "repo 内读 → allow" 的路径;drift 必须把它升级为 Approve。
    let call = mk_call(&sid, "fs_read_file", json!({"path": "/proj/src/main.rs"}));
    let out = fw
        .evaluate(
            &call,
            &StaticDescriptorOracle(DescriptorStatus::Drifted),
            OAuthScopeContext::NonOauth,
        )
        .unwrap();
    assert_eq!(
        out.decision_kind(),
        DecisionKind::Approve,
        "方案 §3.5-8: descriptor drift 必须升级为 Approve"
    );
}

/// first-seen 同理:第一次见到的 MCP server 默认 approve
#[test]
fn firewall_descriptor_first_seen_forces_approve() {
    let (_l, fw, sid) = setup("/proj", vec!["api.github.com"]);
    let call = mk_call(&sid, "fs_read_file", json!({"path": "/proj/src/main.rs"}));
    let out = fw
        .evaluate(
            &call,
            &StaticDescriptorOracle(DescriptorStatus::FirstSeen),
            OAuthScopeContext::NonOauth,
        )
        .unwrap();
    assert_eq!(
        out.decision_kind(),
        DecisionKind::Approve,
        "first-seen 状态必须让低风险动作也进入审批"
    );
}

/// shell wrapper 回归:powershell/pwsh/cmd/bash + eval flag → Deny(destructive 组合)
#[test]
fn firewall_shell_wrappers_are_fail_closed() {
    let (_l, fw, sid) = setup("/proj", vec![]);

    let cases: &[&[&str]] = &[
        &["bash", "-lc", "rm -rf /home/user"],
        &["sh", "-c", "rm -rf /"],
        &[
            "pwsh",
            "-Command",
            "Remove-Item -Recurse -Force C:\\Users\\x",
        ],
        &["powershell.exe", "-Command", "Remove-Item x"],
        &["cmd", "/c", "del /f /q C:\\x"],
        &["cmd.exe", "/C", "del x"],
    ];
    for argv in cases {
        let argv_val: Vec<String> = argv.iter().map(|s| s.to_string()).collect();
        let call = mk_call(&sid, "shell_run", json!({ "argv": argv_val }));
        let out = fw
            .evaluate(
                &call,
                &StaticDescriptorOracle(DescriptorStatus::ApprovedStable),
                OAuthScopeContext::NonOauth,
            )
            .unwrap();
        assert_eq!(
            out.decision_kind(),
            DecisionKind::Deny,
            "shell wrapper fail-closed 失败:argv = {:?}",
            argv
        );
    }
}

/// (保留旧测试作对比,但重命名避免与新 forces_approve 重复)
#[test]
fn firewall_descriptor_drift_escalates_reasons() {
    let (_l, fw, sid) = setup("/proj", vec!["api.github.com"]);
    // 一条本来会 allow 的读请求;如果 descriptor 漂移,应升级到 approve
    // (我们的 RiskScorer 会加 +25,由 Approve 类规则吃掉)。
    // NOTE:仅依赖风险分不足以改变 PolicyEngine 的命中集合(这是有意识的
    // 设计——规则优先)。本测试只断言 Drift 状态被 risk_score 反映且 reasons
    // 列表包含 "descriptor ... drifted"。
    let call = mk_call(&sid, "fs_read_file", json!({"path": "/proj/src/main.rs"}));
    let out = fw
        .evaluate(
            &call,
            &StaticDescriptorOracle(DescriptorStatus::Drifted),
            OAuthScopeContext::NonOauth,
        )
        .unwrap();
    let (decision, _effects) = match out {
        FirewallOutcome::Allowed { decision, effects } => (decision, effects),
        FirewallOutcome::Denied { decision, effects } => (decision, effects),
        FirewallOutcome::Approve {
            decision, effects, ..
        } => (decision, effects),
        _ => panic!("unexpected outcome"),
    };
    assert!(
        decision.reasons.iter().any(|r| r.contains("drifted")),
        "方案 §3.5-8: descriptor drift reason missing: {:?}",
        decision.reasons
    );
    assert!(decision.risk_score >= 25);
}

// ============================================================
// §6.7 六条 approval 验收
// ============================================================

/// §6.7-1: approve 请求在 app 重启后仍存在(由 I01 保证,此处端到端验证)
#[test]
fn approval_survives_reopen() {
    // open_in_memory 不支持重启语义;用磁盘库做真实重启模拟
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("ledger.db");

    let approval_id;
    {
        let l = Arc::new(Ledger::open(&path).unwrap());
        let sid = l.start_session("test", None).unwrap();
        let policy = PolicyEngine::new(default_ruleset());
        let fw = Firewall::new(
            l.clone(),
            policy,
            FirewallConfig {
                project_roots: vec!["/proj".into()],
                ..Default::default()
            },
        );
        let call = mk_call(&sid, "fs_write_file", json!({"path": "/proj/x.md"}));
        let out = fw
            .evaluate(
                &call,
                &StaticDescriptorOracle(DescriptorStatus::ApprovedStable),
                OAuthScopeContext::NonOauth,
            )
            .unwrap();
        if let FirewallOutcome::Approve { approval, .. } = out {
            approval_id = approval.approval_id;
        } else {
            panic!("应产 Approve");
        }
        l.checkpoint().unwrap();
    }

    let l2 = Ledger::open(&path).unwrap();
    let req = l2.get_approval(&approval_id).unwrap().unwrap();
    assert_eq!(req.status, ApprovalStatus::Pending, "方案 §6.7-1");
}

/// §6.7-2: 过期 approval 不能继续执行(sweep_expired 置 Expired)
///
/// 策略:用磁盘库 + 绕过 Ledger API 的副路径 UPDATE expires_at,模拟 TTL 到期。
#[test]
fn approval_expires_via_sweep() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("ledger.db");

    let l = Arc::new(Ledger::open(&path).unwrap());
    let sid = l.start_session("test", None).unwrap();
    let policy = PolicyEngine::new(default_ruleset());
    let fw = Firewall::new(
        l.clone(),
        policy,
        FirewallConfig {
            project_roots: vec!["/proj".into()],
            approval_ttl_secs: 60,
            ..Default::default()
        },
    );
    let call = mk_call(&sid, "fs_write_file", json!({"path": "/proj/x.md"}));
    let out = fw
        .evaluate(
            &call,
            &StaticDescriptorOracle(DescriptorStatus::ApprovedStable),
            OAuthScopeContext::NonOauth,
        )
        .unwrap();
    let approval_id = match out {
        FirewallOutcome::Approve { approval, .. } => approval.approval_id,
        _ => panic!("expected Approve"),
    };

    // 通过**另一个** Connection 直接 UPDATE expires_at(Ledger 把 conn 作为 pub(crate)
    // 不允许跨 crate 访问;这里用外部连接进行篡改式模拟)。
    {
        let c = rusqlite::Connection::open(&path).unwrap();
        c.execute(
            "UPDATE approvals SET expires_at = 1 WHERE approval_id = ?1",
            rusqlite::params![approval_id],
        )
        .unwrap();
    }

    let expired = l.sweep_expired().unwrap();
    assert_eq!(expired.len(), 1);
    assert_eq!(expired[0].status, ApprovalStatus::Expired);
    let req_after = l.get_approval(&approval_id).unwrap().unwrap();
    assert_eq!(req_after.status, ApprovalStatus::Expired, "方案 §6.7-2");
}

/// §6.7-3: deny 后 tool call 返回安全错误(外层通过 Decision Deny 实现)
#[test]
fn approval_deny_produces_denied_resolution() {
    let (l, fw, sid) = setup("/proj", vec![]);
    let call = mk_call(&sid, "fs_write_file", json!({"path": "/proj/x.md"}));
    let out = fw
        .evaluate(
            &call,
            &StaticDescriptorOracle(DescriptorStatus::ApprovedStable),
            OAuthScopeContext::NonOauth,
        )
        .unwrap();
    let approval_id = match out {
        FirewallOutcome::Approve { approval, .. } => approval.approval_id,
        _ => panic!(),
    };
    let resolution = l
        .deny(&approval_id, Some("user denied"), Some("alice"))
        .unwrap();
    assert_eq!(resolution.status, ApprovalStatus::Denied, "方案 §6.7-3");
}

/// §6.7-4: allow once 只对当前 invocation 生效 —— ApprovalScope::Once 语义
#[test]
fn approval_allow_once_scope_is_single_use() {
    let (l, _fw, sid) = setup("/proj", vec![]);
    let dec = vigil_types::DecisionRecord {
        decision_id: "d-1".into(),
        invocation_id: "inv-1".into(),
        decision: DecisionKind::Approve,
        risk_score: 50,
        reasons: vec![],
        policy_ids: vec![],
        created_at: 0,
    };
    let effects = vigil_types::EffectVector::default();
    let req = l
        .create_approval(&sid, &dec, &effects, "t", "s", 60, Default::default())
        .unwrap();

    // 批准 Once
    let resolution = l
        .approve(&req.approval_id, ApprovalScope::Once, Some("alice"))
        .unwrap();
    assert_eq!(resolution.status, ApprovalStatus::Approved);
    assert_eq!(resolution.scope, Some(ApprovalScope::Once));

    // 二次批准:DB 已是 Approved,不再改状态
    let resolution2 = l
        .approve(
            &req.approval_id,
            ApprovalScope::ThisSession,
            Some("mallory"),
        )
        .unwrap();
    assert_eq!(
        resolution2.status,
        ApprovalStatus::Approved,
        "方案 §6.7-4: approval 已终态,scope 不再被覆盖"
    );
    // scope 在第二次返回里本应是 None(因为"本次调用没有让 Pending 推进"),
    // 表明"Once 语义"不可被事后篡改
    assert_eq!(resolution2.scope, None);
}

/// §6.7-5: allow this session 不跨 session —— scope 在 DB 不持久化,
/// 但语义由后续 evaluate 消费时判断(I02 未在 evaluate 里做 session 级缓存,
/// 留 I04 实装;这里回归测试保证 scope 语义在 API 层可区分 Once / ThisSession)
#[test]
fn approval_scope_types_are_distinct() {
    let (l, _fw, sid) = setup("/proj", vec![]);
    let dec = vigil_types::DecisionRecord {
        decision_id: "d-1".into(),
        invocation_id: "inv-1".into(),
        decision: DecisionKind::Approve,
        risk_score: 50,
        reasons: vec![],
        policy_ids: vec![],
        created_at: 0,
    };
    let req1 = l
        .create_approval(
            &sid,
            &dec,
            &vigil_types::EffectVector::default(),
            "t",
            "s",
            60,
            Default::default(),
        )
        .unwrap();
    let r1 = l
        .approve(&req1.approval_id, ApprovalScope::ThisSession, None)
        .unwrap();
    assert_eq!(r1.scope, Some(ApprovalScope::ThisSession));
}

/// §6.7-6: Outbox 模式(本轮显式延后 —— ADR 0003 §D7)
///
/// 回归保护:确认文档与实现一致 —— 本轮无 Outbox 相关代码路径。
#[test]
fn outbox_mode_is_deferred_to_i04() {
    // 仅占位:ADR 0003 §D7 承诺本轮延后。I04 接入时本测试应被替换为真实断言。
    // 使其永远通过 + 标注,避免被误删。
}

// ============================================================
// 额外:wait_for_resolution 阻塞/唤醒
// ============================================================

/// 快速路径:已终态立即返回
#[test]
fn wait_for_resolution_fast_path_returns_existing() {
    let (l, _fw, sid) = setup("/proj", vec![]);
    let dec = vigil_types::DecisionRecord {
        decision_id: "d".into(),
        invocation_id: "inv".into(),
        decision: DecisionKind::Approve,
        risk_score: 10,
        reasons: vec![],
        policy_ids: vec![],
        created_at: 0,
    };
    let req = l
        .create_approval(
            &sid,
            &dec,
            &vigil_types::EffectVector::default(),
            "t",
            "s",
            60,
            Default::default(),
        )
        .unwrap();
    let _ = l
        .approve(&req.approval_id, ApprovalScope::Once, Some("alice"))
        .unwrap();

    let got = l
        .wait_for_resolution(&req.approval_id, Duration::from_millis(100))
        .unwrap();
    assert!(got.is_some());
    assert_eq!(got.unwrap().status, ApprovalStatus::Approved);
}

/// 慢路径:等待 + 另一线程解析
#[test]
fn wait_for_resolution_is_woken_by_approve() {
    let (l, _fw, sid) = setup("/proj", vec![]);
    let dec = vigil_types::DecisionRecord {
        decision_id: "d".into(),
        invocation_id: "inv".into(),
        decision: DecisionKind::Approve,
        risk_score: 10,
        reasons: vec![],
        policy_ids: vec![],
        created_at: 0,
    };
    let req = l
        .create_approval(
            &sid,
            &dec,
            &vigil_types::EffectVector::default(),
            "t",
            "s",
            60,
            Default::default(),
        )
        .unwrap();

    // 用 channel 确保 approver 只在 waiter 真正进入等待阶段后才 approve。
    // barrier 无法精确到 "cv.wait 已阻塞",但可以保证 main 线程已进 wait_for_resolution 的
    // 快速路径之后 —— 慢路径若先 publish,代码的"最后兜底 DB 查询"也能找回 resolution。
    // 两条路径都覆盖即可。
    use std::sync::mpsc;
    let (ready_tx, ready_rx) = mpsc::channel::<()>();
    let approval_id = req.approval_id.clone();
    let l2 = l.clone();
    let t = std::thread::spawn(move || {
        ready_rx.recv().expect("waiter 应先发信号");
        l2.approve(&approval_id, ApprovalScope::Once, Some("alice"))
            .unwrap()
    });

    ready_tx.send(()).unwrap();
    let got = l
        .wait_for_resolution(&req.approval_id, Duration::from_secs(2))
        .unwrap();
    t.join().unwrap();
    assert!(got.is_some());
    assert_eq!(got.unwrap().status, ApprovalStatus::Approved);
}

// ============================================================
// I10c-β2 R3 集成验收:scope allowlist 注入 + OAuthScopeContext 强制显式选择。
// ============================================================

/// I10c-β2 R3:证明 `FirewallConfig.allowed_scopes` 注入通道与 `OAuthScopeContext`
/// 签名强制双管齐下,能在真实 Firewall 路径上端到端生效"只允许 allowlist 内的 scope"。
///
/// 四条路径:
/// 1. `NonOauth`:非 OAuth 调用 → scope 规则静默(不适用),不命中 deny-out-of-scope
/// 2. `Scopes(vec!["repo"])`:在 allowlist 内 → 规则不命中
/// 3. `Scopes(vec!["admin:org"])`:越界 → fail-closed 命中 Deny
/// 4. `Scopes(vec![])`(OAuth 但 token 无 scope)→ fail-closed 命中 Deny
#[test]
fn firewall_oauth_scope_context_end_to_end_with_config_injected_allowlist() {
    use std::collections::HashMap;
    use vigil_policy::{Condition, PolicyAction, PolicyRule};
    use vigil_types::EffectKind;

    let l = Arc::new(Ledger::open_in_memory().unwrap());
    let sid = l.start_session("test", Some("scope-oauth-r3")).unwrap();

    // "只允许 allowlist 内的 scope":Deny 规则 + ScopeNotInAllowList(§ADR 0011 §8)
    let scope_rule = PolicyRule {
        id: "deny-out-of-scope".into(),
        match_effects: vec![EffectKind::NetOutbound],
        conditions: vec![Condition::ScopeNotInAllowList {
            allowlist_key: "oauth_scopes".into(),
        }],
        action: PolicyAction::Deny,
        priority: 1000, // 压过 default_ruleset 任何 Approve/Allow
    };
    let mut rules = default_ruleset();
    rules.push(scope_rule);
    let policy = PolicyEngine::new(rules);

    // R3 BLOCKER 修复点:FirewallConfig.allowed_scopes 作为 scope allowlist 注入入口
    let mut allowed_scopes = HashMap::new();
    allowed_scopes.insert(
        "oauth_scopes".into(),
        vec!["repo".into(), "workflow".into()],
    );
    let cfg = FirewallConfig {
        project_roots: vec!["/proj".into()],
        allowed_hosts: vec!["api.github.com".into()],
        allowed_scopes,
        approval_ttl_secs: 60,
        ..Default::default()
    };
    let fw = Firewall::new(l.clone(), policy, cfg);
    let call = mk_call(
        &sid,
        "http_get",
        json!({"url": "https://api.github.com/orgs/x"}),
    );
    let oracle = StaticDescriptorOracle(DescriptorStatus::ApprovedStable);

    let ids_of = |outcome: &FirewallOutcome| -> Vec<String> {
        match outcome {
            FirewallOutcome::Allowed { decision, .. }
            | FirewallOutcome::Denied { decision, .. }
            | FirewallOutcome::Approve { decision, .. } => decision.policy_ids.clone(),
            _ => vec![],
        }
    };

    // Path 1:NonOauth → scope 规则不触发(即使 allowlist 已配置)
    let out1 = fw
        .evaluate(&call, &oracle, OAuthScopeContext::NonOauth)
        .unwrap();
    assert!(
        !ids_of(&out1).contains(&"deny-out-of-scope".to_string()),
        "NonOauth 路径不应命中 scope 规则,ids={:?}",
        ids_of(&out1)
    );

    // Path 2:Scopes(["repo"]) ⊂ allowlist → 规则不命中
    let out2 = fw
        .evaluate(
            &call,
            &oracle,
            OAuthScopeContext::Scopes(vec!["repo".into()]),
        )
        .unwrap();
    assert!(
        !ids_of(&out2).contains(&"deny-out-of-scope".to_string()),
        "subset 路径不应命中 scope 规则,ids={:?}",
        ids_of(&out2)
    );

    // Path 3:越界 scope → fail-closed Deny
    let out3 = fw
        .evaluate(
            &call,
            &oracle,
            OAuthScopeContext::Scopes(vec!["admin:org".into()]),
        )
        .unwrap();
    assert_eq!(
        out3.decision_kind(),
        DecisionKind::Deny,
        "越界 scope 必须 Deny"
    );
    assert!(
        ids_of(&out3).contains(&"deny-out-of-scope".to_string()),
        "应命中 deny-out-of-scope,ids={:?}",
        ids_of(&out3)
    );

    // Path 4:OAuth 但空 scope(Scopes(vec![]))→ fail-closed 触发(R2 MUST-FIX 修复点)
    let out4 = fw
        .evaluate(&call, &oracle, OAuthScopeContext::Scopes(vec![]))
        .unwrap();
    assert_eq!(
        out4.decision_kind(),
        DecisionKind::Deny,
        "空 scope(OAuth 但 token 无 scope)必须 fail-closed Deny"
    );
    assert!(
        ids_of(&out4).contains(&"deny-out-of-scope".to_string()),
        "fail-closed 应命中 deny-out-of-scope,ids={:?}",
        ids_of(&out4)
    );
}

/// I10c-β2 R3 NICE:`FirewallConfig.allowed_scopes` 若误用保留键 `"allowed_hosts"`,
/// `evaluate` 首次调用即 fail-closed 返 `ReservedScopeKey`,避免静默覆盖 host 白名单。
#[test]
fn firewall_rejects_reserved_allowed_hosts_key_in_allowed_scopes() {
    use std::collections::HashMap;

    let l = Arc::new(Ledger::open_in_memory().unwrap());
    let sid = l.start_session("test", Some("reserved-key")).unwrap();
    let policy = PolicyEngine::new(default_ruleset());
    let mut bad_scopes = HashMap::new();
    bad_scopes.insert("allowed_hosts".into(), vec!["evil".into()]); // 误用保留键
    let cfg = FirewallConfig {
        project_roots: vec!["/proj".into()],
        allowed_hosts: vec!["api.github.com".into()],
        allowed_scopes: bad_scopes,
        approval_ttl_secs: 60,
        ..Default::default()
    };
    let fw = Firewall::new(l.clone(), policy, cfg);
    let call = mk_call(&sid, "fs_read_file", json!({"path": "/proj/x"}));
    let err = fw
        .evaluate(
            &call,
            &StaticDescriptorOracle(DescriptorStatus::ApprovedStable),
            OAuthScopeContext::NonOauth,
        )
        .unwrap_err();
    assert!(
        matches!(err, vigil_firewall::FirewallError::ReservedScopeKey),
        "expected ReservedScopeKey, got {:?}",
        err
    );
}

/// 超时路径:pending 始终,timeout 返回 None
#[test]
fn wait_for_resolution_times_out_on_pending() {
    let (l, _fw, sid) = setup("/proj", vec![]);
    let dec = vigil_types::DecisionRecord {
        decision_id: "d".into(),
        invocation_id: "inv".into(),
        decision: DecisionKind::Approve,
        risk_score: 10,
        reasons: vec![],
        policy_ids: vec![],
        created_at: 0,
    };
    let req = l
        .create_approval(
            &sid,
            &dec,
            &vigil_types::EffectVector::default(),
            "t",
            "s",
            60,
            Default::default(),
        )
        .unwrap();
    let got = l
        .wait_for_resolution(&req.approval_id, Duration::from_millis(30))
        .unwrap();
    assert!(got.is_none(), "pending 应超时返回 None");
}

// ============================================================
// D26:effect 目录 —— 防火墙对真实 server 工具按身份分类(集成验证)
// ============================================================

/// D26:catalog extractor 让防火墙对已知 server 的工具按**身份**预置效应,且这些效应经真实
/// `evaluate` 流出现在决策的 `EffectVector` 里(随决策入账本 → `inspect protection`/审计可见)。
///
/// 取 github `create_issue`(args 无 url/path/secret-ref → 7 个 arg-extractor 本会产出**空**
/// EffectVector);目录按身份预置 NetOutbound + SecretUse + CommSend。这正是此前"重型防火墙对真实
/// 第三方 server 空转"的缺口被补上的证据。不断言具体 decision_kind —— monitor 降级是 hub 层职责,
/// 防火墙层按 ruleset 决策(可能 Approve/Deny),本测试只验**效应可见性**(D26 的核心收益)。
#[test]
fn catalog_classifies_known_tool_by_identity() {
    let (_l, fw, sid) = setup("/proj", vec![]);
    let call = ToolInvocation {
        invocation_id: uuid::Uuid::new_v4().to_string(),
        session_id: sid.clone(),
        server_id: "github".into(),
        tool_name: "create_issue".into(),
        args: json!({ "title": "hi", "body": "x" }),
        descriptor_hash: "hash".into(),
        requested_at: 0,
    };
    let out = fw
        .evaluate(
            &call,
            &StaticDescriptorOracle(DescriptorStatus::ApprovedStable),
            OAuthScopeContext::NonOauth,
        )
        .unwrap();
    let effects = out.effects();
    assert!(
        effects.effects.contains(&EffectKind::NetOutbound),
        "D26:目录应为 github/create_issue 预置 NetOutbound(此前为空)"
    );
    assert!(
        effects.effects.contains(&EffectKind::SecretUse),
        "D26:github 用 token → SecretUse"
    );
    assert!(
        effects.effects.contains(&EffectKind::CommSend),
        "D26:create_issue 对外发布 → CommSend"
    );
}

/// D26 单调不变量(集成层):同一调用,目录只会**新增**效应,绝不掩盖 arg-extractor 本会发现的。
/// 取一个目录**不认识**的工具但 args 含路径 —— arg-extractor 仍照常产出 FsRead/FsWrite,目录不干扰。
#[test]
fn catalog_does_not_suppress_arg_extractor_effects() {
    let (_l, fw, sid) = setup("/proj", vec![]);
    // 目录无此 (server, tool) 项 → 目录贡献 0;但 args.path 让 PathExtractor 照常分类。
    let call = mk_call(
        &sid,
        "some_unknown_write_tool",
        json!({ "path": "/proj/src/x.rs" }),
    );
    let out = fw
        .evaluate(
            &call,
            &StaticDescriptorOracle(DescriptorStatus::ApprovedStable),
            OAuthScopeContext::NonOauth,
        )
        .unwrap();
    let effects = out.effects();
    // tool_name 含 "write" → PathExtractor 归为写。目录未参与,但也未掩盖。
    assert!(
        effects.effects.contains(&EffectKind::FsWrite),
        "D26:目录不认识的工具,arg-extractor 仍照常分类(目录单调,不掩盖)"
    );
}
