//! ISS-010 integration tests:T0 preflight(`scan_text` → PolicyContext.pii_findings
//! + risk_score 加权 + SQLite 审计落库)端到端走通。
//!
//! 设计纪律(与任务 prompt 对齐):
//! - **feedback_production_logic_testable**:承载 fail-closed 语义的 preflight 路径
//!   必须进默认测试矩阵
//! - 使用 **真 `Ledger::open_in_memory`** + **真 `vigil_redaction::scan_text`**,不
//!   mock;`FirewallError::PreflightScanFailed` 的 fail-closed 分支通过"variant 存在"
//!   编译期守门(Stage 1 scan_text 对非空输入不会返 Err,无法在不 mock 的前提下构造)
//! - PolicyEngine 用"Allow-all"最小规则(空 match_effects + 空 conditions),避免
//!   default_ruleset 的 destructive / deny-outside 规则干扰 preflight 断言

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::err_expect
)]

use std::sync::Arc;

use serde_json::json;
use vigil_audit::Ledger;
use vigil_firewall::{
    scorer::{DescriptorStatus, StaticDescriptorOracle},
    Firewall, FirewallConfig, FirewallError, FirewallOutcome, OAuthScopeContext,
};
use vigil_policy::{PolicyAction, PolicyEngine, PolicyRule};
use vigil_types::{DecisionKind, ToolInvocation};

/// 构造一个 Allow-all policy:空 match_effects + 空 conditions → 任何调用都 Allow。
/// 用于"干净背景"测 preflight 自身行为(PII findings / risk 加权 / 审计落库)。
fn allow_all_policy() -> PolicyEngine {
    PolicyEngine::new(vec![PolicyRule {
        id: "test-allow-all".into(),
        match_effects: vec![],
        conditions: vec![],
        action: PolicyAction::Allow,
        priority: 0,
    }])
}

fn setup_allow_all() -> (Arc<Ledger>, Firewall, String) {
    let l = Arc::new(Ledger::open_in_memory().unwrap());
    let sid = l.start_session("iss-010-test", Some("preflight")).unwrap();
    let cfg = FirewallConfig {
        project_roots: vec!["/proj".into()],
        allowed_hosts: vec![],
        approval_ttl_secs: 60,
        ..Default::default()
    };
    let fw = Firewall::new(l.clone(), allow_all_policy(), cfg);
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

// 用真实 HARD_RULES 会命中的 payload 构造"含 secret"的长文本(≥ 100 bytes)。
fn long_github_token_payload() -> String {
    // 100+ bytes prefix + github_token + trailing text
    let pad = "some surrounding natural language prompt content that pads the buffer to exceed threshold limit.";
    format!("{pad} here is the token ghp_abcdefghijklmnopqrstuvwxyzABCDEFGHIJ for later.",)
}

// 拿 DecisionRecord 用于断言 risk_score(所有 outcome variant 都带 decision)。
// FirewallOutcome 是 non_exhaustive,未来新增 variant 时本处需要同步补 arm。
fn decision_of(out: &FirewallOutcome) -> &vigil_types::DecisionRecord {
    match out {
        FirewallOutcome::Allowed { decision, .. } => decision,
        FirewallOutcome::Denied { decision, .. } => decision,
        FirewallOutcome::Approve { decision, .. } => decision,
        _ => panic!("FirewallOutcome 新增 variant,请同步更新 preflight 测试的 decision_of"),
    }
}

// ────────────────────────────────────────────────────────────────────
// 测试 1: preflight 扫到 secret 类 finding → ctx.pii_findings 可被规则消费
// ────────────────────────────────────────────────────────────────────
//
// 语义验证:我们无法直接读 PolicyContext(它是 evaluate 内部构造),改用**一条
// PiiContains(secret, min_count=1) → Deny** 的探针规则,用"这条规则实际命中"
// 间接证明 preflight 确实把 findings 喂进去了。
#[test]
fn preflight_populates_pii_findings_secret_input() {
    use vigil_policy::Condition;

    let l = Arc::new(Ledger::open_in_memory().unwrap());
    let sid = l.start_session("iss-010-test", Some("preflight")).unwrap();
    let policy = PolicyEngine::new(vec![PolicyRule {
        id: "probe-secret-deny".into(),
        match_effects: vec![],
        conditions: vec![Condition::PiiContains {
            label: "secret".into(),
            min_count: 1,
        }],
        action: PolicyAction::Deny,
        priority: 100,
    }]);
    let cfg = FirewallConfig {
        project_roots: vec!["/proj".into()],
        ..Default::default()
    };
    let fw = Firewall::new(l.clone(), policy, cfg);

    let call = mk_call(
        &sid,
        "llm_prompt",
        json!({"prompt": long_github_token_payload()}),
    );
    let out = fw
        .evaluate(
            &call,
            &StaticDescriptorOracle(DescriptorStatus::ApprovedStable),
            OAuthScopeContext::NonOauth,
        )
        .expect("preflight should succeed on valid input");
    assert_eq!(
        out.decision_kind(),
        DecisionKind::Deny,
        "probe 规则 PiiContains(secret) 必须命中 → Deny;若未命中说明 preflight 没把 secret summary 送进 ctx"
    );
}

// ────────────────────────────────────────────────────────────────────
// 测试 2: 多 finding 聚合 —— 两段含 secret 的长文本 → 累加到同一 label 桶
// ────────────────────────────────────────────────────────────────────
//
// 构造 2 个 HARD_RULES 都能命中的 token(github + anthropic,均归 secret 桶)
// 放在两个不同字段,验证 preflight 能跨字段汇总。
#[test]
fn preflight_multiple_findings_aggregated() {
    use vigil_policy::Condition;

    let l = Arc::new(Ledger::open_in_memory().unwrap());
    let sid = l.start_session("iss-010-test", Some("preflight")).unwrap();
    // 探针:secret count ≥ 2 才 Deny(单条不够)
    let policy = PolicyEngine::new(vec![
        PolicyRule {
            id: "probe-secret-multi-deny".into(),
            match_effects: vec![],
            conditions: vec![Condition::PiiContains {
                label: "secret".into(),
                min_count: 2,
            }],
            action: PolicyAction::Deny,
            priority: 100,
        },
        // fallback allow,避免 default-deny 污染对照
        PolicyRule {
            id: "fallback-allow".into(),
            match_effects: vec![],
            conditions: vec![],
            action: PolicyAction::Allow,
            priority: 0,
        },
    ]);
    let fw = Firewall::new(
        l.clone(),
        policy,
        FirewallConfig {
            project_roots: vec!["/proj".into()],
            ..Default::default()
        },
    );

    let pad_a = "a".repeat(110);
    let pad_b = "b".repeat(110);
    let args = json!({
        "field_a": format!("{pad_a} token=ghp_abcdefghijklmnopqrstuvwxyzABCDEFGHIJ"),
        "field_b": format!("{pad_b} key=sk-ant-api03_ABCDEFGHIJKLMNOPQRSTUVWX"),
    });
    let call = mk_call(&sid, "llm_prompt", args);
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
        "跨字段 secret findings 应累加 ≥ 2,触发探针 → Deny;实际 {:?}",
        out.decision_kind()
    );
}

// ────────────────────────────────────────────────────────────────────
// 测试 3: null / empty args —— pii_findings 空,evaluate 不 Err
// ────────────────────────────────────────────────────────────────────
#[test]
fn preflight_null_input_no_panic() {
    let (_l, fw, sid) = setup_allow_all();

    // null args
    let call1 = mk_call(&sid, "noop", serde_json::Value::Null);
    let r1 = fw
        .evaluate(
            &call1,
            &StaticDescriptorOracle(DescriptorStatus::ApprovedStable),
            OAuthScopeContext::NonOauth,
        )
        .unwrap();
    assert_eq!(
        r1.decision_kind(),
        DecisionKind::Allow,
        "null args → allow-all"
    );

    // empty object args
    let call2 = mk_call(&sid, "noop", json!({}));
    let r2 = fw
        .evaluate(
            &call2,
            &StaticDescriptorOracle(DescriptorStatus::ApprovedStable),
            OAuthScopeContext::NonOauth,
        )
        .unwrap();
    assert_eq!(r2.decision_kind(), DecisionKind::Allow);
}

// ────────────────────────────────────────────────────────────────────
// 测试 4: 短文本 < threshold 不扫,不落 findings,不加权
// ────────────────────────────────────────────────────────────────────
//
// 用 threshold=100 + 一个含 github token 但总长 < 100 的字段 → 不应命中
// secret 探针。
//
// **R2 MUST-FIX 3 盲区说明**:threshold 意在过滤"明显无需扫的短值"(如 tool_name
// / uuid / 数字 ID 等)。**短 secret 的兜底防线**:
//   1. vigil-audit::append_event 的 fail-closed 自检(ADR 0002 §D1)会在事件
//      写入时调 `vigil_redaction::detect_hard_secret`,扫描**不受 threshold 影响**,
//      短 secret(如 40 字符 github token)在 audit 层被拦。
//   2. v0.3 `redact` / `scrub_text` 对任意长度 payload 递归脱敏,不看 threshold。
//   3. 浏览器扩展 MV3 content script(ISS-007)对粘贴原文独立扫,亦不受本 threshold 影响。
// 综上,firewall preflight 只承担"长文本明显风险"场景,不是唯一屏障;threshold
// 调小会显著增加 scan 开销而收益有限,故保持 100 作为默认。
#[test]
fn preflight_short_text_below_threshold_skipped() {
    use vigil_policy::Condition;

    let l = Arc::new(Ledger::open_in_memory().unwrap());
    let sid = l.start_session("iss-010-test", Some("preflight")).unwrap();
    let policy = PolicyEngine::new(vec![
        PolicyRule {
            id: "probe-secret-deny".into(),
            match_effects: vec![],
            conditions: vec![Condition::PiiContains {
                label: "secret".into(),
                min_count: 1,
            }],
            action: PolicyAction::Deny,
            priority: 100,
        },
        PolicyRule {
            id: "fallback-allow".into(),
            match_effects: vec![],
            conditions: vec![],
            action: PolicyAction::Allow,
            priority: 0,
        },
    ]);
    let cfg = FirewallConfig {
        project_roots: vec!["/proj".into()],
        long_text_threshold: 100, // 显式对齐默认
        ..Default::default()
    };
    let fw = Firewall::new(l.clone(), policy, cfg);

    // 仅放一个 60 字节的 token,不够 threshold,preflight 应跳过
    let short = "ghp_abcdefghijklmnopqrstuvwxyzABCDEFGHIJ"; // 40 bytes
    assert!(short.len() < 100);
    let call = mk_call(&sid, "noop", json!({"tiny": short}));
    let out = fw
        .evaluate(
            &call,
            &StaticDescriptorOracle(DescriptorStatus::ApprovedStable),
            OAuthScopeContext::NonOauth,
        )
        .unwrap();
    assert_eq!(
        out.decision_kind(),
        DecisionKind::Allow,
        "短文本低于 threshold 不应被扫;探针 secret 规则不应命中"
    );
}

// ────────────────────────────────────────────────────────────────────
// 测试 5: 端到端审计落库 —— redaction_scans + redaction_findings 都写到位
// ────────────────────────────────────────────────────────────────────
#[test]
fn preflight_ledger_scan_persisted() {
    let (l, fw, sid) = setup_allow_all();

    let call = mk_call(
        &sid,
        "llm_prompt",
        json!({"prompt": long_github_token_payload()}),
    );
    let _ = fw
        .evaluate(
            &call,
            &StaticDescriptorOracle(DescriptorStatus::ApprovedStable),
            OAuthScopeContext::NonOauth,
        )
        .unwrap();

    let scans = l.list_redaction_scans_by_session(&sid).unwrap();
    assert!(
        !scans.is_empty(),
        "至少 1 条 redaction scan 应落库;实际 {}",
        scans.len()
    );
    assert_eq!(
        scans[0].source, "tool_arg",
        "ISS-010 preflight 源头固定 tool_arg"
    );

    let findings = l
        .list_redaction_findings_by_scan(&scans[0].scan_id)
        .unwrap();
    assert!(
        !findings.is_empty(),
        "github_token 命中 → findings 应 ≥ 1;实际 {}",
        findings.len()
    );
    assert!(
        findings.iter().any(|f| f.label == "secret"),
        "至少一条 finding 的 label 应为 secret"
    );
    assert!(
        findings.iter().all(|f| f.action_taken == "redacted"),
        "preflight 落库 action_taken 固定 redacted"
    );
}

// ────────────────────────────────────────────────────────────────────
// 测试 6: fail-closed variant 存在(编译期守门)
// ────────────────────────────────────────────────────────────────────
// R2 NICE:FailingScanner 是**测试本地 mock**,不污染 production pub API。
// `vigil_firewall::PiiScanner` 是公共 trait(Firewall::with_scanner 签名需要),
// 但失败注入实现应该留在测试层。
struct TestFailingScanner {
    reason: String,
}
impl vigil_firewall::PiiScanner for TestFailingScanner {
    fn scan(
        &self,
        _text: &str,
    ) -> Result<vigil_redaction::RedactionResult, vigil_redaction::ScanError> {
        Err(vigil_redaction::ScanError::InferenceFailed {
            reason: self.reason.clone(),
        })
    }
}

// R2 BLOCKER 2 修复 + R2 MUST-FIX(TEST)修正:**真走 fail-closed 路径**,注入
// `TestFailingScanner` 触发 `ScanError::InferenceFailed`。断言:
//  - `Firewall::evaluate` 返 `FirewallError::PreflightScanFailed`(不是 panic / Ok)
//  - **没有 approval / decision 被写入 SQLite**(用真 Ledger API 查,非 stub)
//  - reason 字段被转透传
#[test]
fn preflight_fail_closed_on_scan_err() {
    use std::sync::Arc;
    use vigil_firewall::{Firewall, FirewallConfig, FirewallError, OAuthScopeContext};
    use vigil_policy::PolicyEngine;

    let l = Arc::new(vigil_audit::Ledger::open_in_memory().unwrap());
    let sid = l
        .start_session("test", Some("preflight_fail_closed"))
        .unwrap();
    let scanner: Arc<dyn vigil_firewall::PiiScanner> = Arc::new(TestFailingScanner {
        reason: "simulated model crash".into(),
    });
    let fw = Firewall::with_scanner(
        l.clone(),
        PolicyEngine::new(vec![]), // policy 不被触发,空规则足矣
        FirewallConfig::default(),
        scanner,
    );

    // 构造一个含长文本的 args,让 extract_long_text_fields 抓到后送 scanner
    let call = mk_call(&sid, "noop", serde_json::json!({ "text": "x".repeat(200) }));

    // 决策写入前的 baseline:用**真 Ledger API**(replay_session + list_pending_approvals)
    // 观察 decision 事件 / approval 行数,证明 fail-closed 没让 policy / approval 流程继续。
    let decisions_before = count_decision_events(&l, &sid);
    let approvals_before = count_approvals(&l, &sid);

    // scanner 返 InferenceFailed → Firewall::evaluate 应 fail-closed Err
    let outcome = fw.evaluate(
        &call,
        &StaticDescriptorOracle(DescriptorStatus::ApprovedStable),
        OAuthScopeContext::NonOauth,
    );
    match outcome {
        Err(FirewallError::PreflightScanFailed { reason }) => {
            // T4 ISS-008 Phase 2 secret-hygiene:reason 必须是稳定字面量
            // `t0_inference_failed`,**不得**回显 ScanError Debug / 原文片段。
            // 旧 `format!("{e:?}")` 会让底层错误文本(可能含输入 token)流到
            // audit ledger,违反 secret-hygiene。
            assert_eq!(
                reason, "t0_inference_failed",
                "reason 应为稳定 code `t0_inference_failed`,实际:{reason}"
            );
        }
        other => panic!("fail-closed 应返 PreflightScanFailed,实得 {other:?}"),
    }

    // 证明 policy 链未继续走:decisions / approvals 行数没变(**真 Ledger 查询证据**)
    assert_eq!(
        count_decision_events(&l, &sid),
        decisions_before,
        "fail-closed 时不应 record_decision(decision.* 事件不应增加)"
    );
    assert_eq!(
        count_approvals(&l, &sid),
        approvals_before,
        "fail-closed 时不应创建 approval"
    );
}

/// 真 Ledger 查询:数 session 里所有 event_type 以 `decision.` 开头的事件。
/// replay_session 返 ReplayEvent 列表,event_type 字段反映 DecisionKind record_decision 的产出。
fn count_decision_events(l: &vigil_audit::Ledger, session_id: &str) -> usize {
    l.replay_session(session_id)
        .map(|events| {
            events
                .iter()
                .filter(|e| e.event_type.starts_with("decision."))
                .count()
        })
        .unwrap_or(0)
}

/// 真 Ledger 查询:该 session 的 pending approvals 行数。
fn count_approvals(l: &vigil_audit::Ledger, session_id: &str) -> usize {
    l.list_pending_approvals(Some(session_id))
        .map(|v| v.len())
        .unwrap_or(0)
}

// 保留编译期守门作为附加防御:variant 命名稳定。
#[test]
fn preflight_fail_closed_variant_named_stably() {
    let e = FirewallError::PreflightScanFailed {
        reason: "compile guard".into(),
    };
    match e {
        FirewallError::PreflightScanFailed { reason } => assert_eq!(reason, "compile guard"),
        _ => panic!("variant 命名不得漂移"),
    }
}

// ────────────────────────────────────────────────────────────────────
// 测试 7: risk_score 加权回归 —— 单 secret finding → decision.risk_score 至少 +25
// ────────────────────────────────────────────────────────────────────
//
// Baseline:同形状 args 但不含 secret → risk_score(decision 记录的)记 R0;
// With-secret:相同 shape 替换为真 token → risk_score 记 R1,应 `R1 >= R0 + 25`
// (ADR 0012 §1.3 Secret = 25)。
#[test]
fn preflight_risk_score_secret_delta_25() {
    let (_l, fw, sid) = setup_allow_all();

    // Baseline:同长度填充,但不含任何 HARD_RULES 指纹
    let pad = "x".repeat(150);
    let call_baseline = mk_call(&sid, "noop", json!({"prompt": pad.clone()}));
    let out_baseline = fw
        .evaluate(
            &call_baseline,
            &StaticDescriptorOracle(DescriptorStatus::ApprovedStable),
            OAuthScopeContext::NonOauth,
        )
        .unwrap();
    let r0 = decision_of(&out_baseline).risk_score;

    // With secret
    let call_secret = mk_call(&sid, "noop", json!({"prompt": long_github_token_payload()}));
    let out_secret = fw
        .evaluate(
            &call_secret,
            &StaticDescriptorOracle(DescriptorStatus::ApprovedStable),
            OAuthScopeContext::NonOauth,
        )
        .unwrap();
    let r1 = decision_of(&out_secret).risk_score;

    assert!(
        r1 as i32 >= r0 as i32 + 25,
        "Secret 类 finding 应让 risk_score 至少 +25(ADR 0012 §1.3);baseline={r0} with_secret={r1}"
    );
}

// ────────────────────────────────────────────────────────────────────
// 测试 8 (v0.8 Sprint 1 A2.5): scanner 退化路径 — DegradedTimeout 必须落
// audit `engine.degraded` 事件 + decision_reasons 加 stable code,
// 但 evaluate **不**因退化阻断(fall-back Hard-only,仍走 PolicyEngine 决策)。
// ────────────────────────────────────────────────────────────────────

/// RedactionResult 没有 Default impl(`RiskSignals: Default` 但 RedactionResult
/// 不是);测试构造空结果用此 helper(等价"Hard-only 路径无任何 finding")。
fn empty_redaction_result() -> vigil_redaction::RedactionResult {
    vigil_redaction::RedactionResult {
        findings: Vec::new(),
        redacted_text: String::new(),
        risk_signals: vigil_redaction::RiskSignals::default(),
    }
}

/// mock scanner:`scan` 返空 RedactionResult(模拟"模型路径退化为 Hard-only 后无 model finding"),
/// `scan_with_status` override 返 (空 result, DegradedTimeout)。
struct DegradedMockScanner;
impl vigil_firewall::PiiScanner for DegradedMockScanner {
    fn scan(
        &self,
        _text: &str,
    ) -> Result<vigil_redaction::RedactionResult, vigil_redaction::ScanError> {
        // legacy path 不走;若被调用返"扫过但 0 finding",对决策无影响。
        Ok(empty_redaction_result())
    }

    fn scan_with_status(
        &self,
        _text: &str,
    ) -> Result<
        (
            vigil_redaction::RedactionResult,
            vigil_firewall::EngineStatusReport,
        ),
        vigil_redaction::ScanError,
    > {
        Ok((
            empty_redaction_result(),
            vigil_firewall::EngineStatusReport::DegradedTimeout,
        ))
    }
}

#[test]
fn preflight_degraded_timeout_records_audit_and_reason() {
    use std::sync::Arc;
    use vigil_firewall::{Firewall, FirewallConfig, OAuthScopeContext};

    let l = Arc::new(vigil_audit::Ledger::open_in_memory().unwrap());
    let sid = l
        .start_session("a2-test", Some("preflight_degraded"))
        .unwrap();
    let scanner: Arc<dyn vigil_firewall::PiiScanner> = Arc::new(DegradedMockScanner);
    let fw = Firewall::with_scanner(
        l.clone(),
        allow_all_policy(), // allow-all,确保 evaluate 走通到 record_decision
        FirewallConfig {
            project_roots: vec!["/proj".into()],
            ..Default::default()
        },
        scanner,
    );

    // 长文本 ≥ threshold,触发 preflight scan_with_status
    let call = mk_call(&sid, "noop", json!({ "prompt": "x".repeat(200) }));

    let out = fw
        .evaluate(
            &call,
            &StaticDescriptorOracle(DescriptorStatus::ApprovedStable),
            OAuthScopeContext::NonOauth,
        )
        .expect(
            "degraded path 不应阻断 evaluate(fall-back Hard-only,fail-closed 由 PolicyEngine 决策)",
        );
    let decision = decision_of(&out);

    // 断言 1:decision.reasons 含 "engine.status=degraded_timeout"
    assert!(
        decision
            .reasons
            .iter()
            .any(|r| r == "engine.status=degraded_timeout"),
        "decision.reasons 必须含稳定码 `engine.status=degraded_timeout`;实际 reasons={:?}",
        decision.reasons
    );

    // 断言 2:audit ledger 含 `engine.degraded` 事件,且 decision_id 与本次 decision 一致
    let events = l.replay_session(&sid).expect("replay should succeed");
    let degraded_events: Vec<_> = events
        .iter()
        .filter(|e| e.event_type == "engine.degraded")
        .collect();
    assert_eq!(
        degraded_events.len(),
        1,
        "退化路径应落 1 条 engine.degraded 事件;实际 {}",
        degraded_events.len()
    );
    let payload = &degraded_events[0].payload;
    assert_eq!(
        payload.get("status").and_then(|v| v.as_str()),
        Some("degraded_timeout"),
        "payload.status 必须 = degraded_timeout;实际 {payload:?}"
    );
    assert_eq!(
        payload.get("decision_id").and_then(|v| v.as_str()),
        Some(decision.decision_id.as_str()),
        "payload.decision_id 必须与本次 decision_id 一致(跨表 join 锚点)"
    );
    assert_eq!(
        payload.get("fail_closed_decision").and_then(|v| v.as_str()),
        Some("fall_back_hard_only"),
        "退化策略稳定码 fall_back_hard_only"
    );
}

/// 反向守门:scanner 走 default `scan_with_status`(返 Unsupported)→ **不**应落
/// engine.degraded 事件 + reasons **不**应含 engine.status= 串。
/// 这测试 Codex § 2 改进版 A 的关键不变量:Unsupported 不被当 Ok / 不引入幽灵审计。
#[test]
fn preflight_unsupported_status_does_not_emit_audit_or_reason() {
    use std::sync::Arc;

    /// scanner 不 override scan_with_status → 走 trait default 返 Unsupported
    struct DefaultStatusScanner;
    impl vigil_firewall::PiiScanner for DefaultStatusScanner {
        fn scan(
            &self,
            _text: &str,
        ) -> Result<vigil_redaction::RedactionResult, vigil_redaction::ScanError> {
            Ok(empty_redaction_result())
        }
        // 故意不 override scan_with_status
    }

    let l = Arc::new(vigil_audit::Ledger::open_in_memory().unwrap());
    let sid = l
        .start_session("a2-test", Some("preflight_unsupported"))
        .unwrap();
    let scanner: Arc<dyn vigil_firewall::PiiScanner> = Arc::new(DefaultStatusScanner);
    let fw = Firewall::with_scanner(
        l.clone(),
        allow_all_policy(),
        FirewallConfig {
            project_roots: vec!["/proj".into()],
            ..Default::default()
        },
        scanner,
    );
    let call = mk_call(&sid, "noop", json!({ "prompt": "x".repeat(200) }));
    let out = fw
        .evaluate(
            &call,
            &StaticDescriptorOracle(DescriptorStatus::ApprovedStable),
            OAuthScopeContext::NonOauth,
        )
        .unwrap();
    let decision = decision_of(&out);

    // reasons 不应含 engine.status= 串(Unsupported / Ok 都不写)
    assert!(
        !decision
            .reasons
            .iter()
            .any(|r| r.starts_with("engine.status=")),
        "Unsupported 状态不应在 reasons 留任何 engine.status= 串;reasons={:?}",
        decision.reasons
    );

    // ledger 不应有 engine.degraded 事件
    let events = l.replay_session(&sid).unwrap();
    let degraded_count = events
        .iter()
        .filter(|e| e.event_type == "engine.degraded")
        .count();
    assert_eq!(
        degraded_count, 0,
        "Unsupported 状态不应触发 engine.degraded 审计事件;实际 {degraded_count}"
    );
}
