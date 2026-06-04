//! v0.5 P1 ADR 0014 α2 — `Hub::resolve_approval` thin-wrapper 守门测试。
//!
//! 三条断言(approve / deny / cancel),每条都用真 `Ledger::open_in_memory`
//! 建一条 Pending approval,再调 `Hub::resolve_approval` 验证终态:
//! - approve(scope=Once)→ ApprovalStatus::Approved + scope 透传
//! - deny(reason)→ ApprovalStatus::Denied
//! - cancel → ApprovalStatus::Cancelled
//!
//! **不**依赖任何 mock —— 全链路走 Ledger.approve/deny/cancel,确认 wrapper
//! 没引入第二个状态机、没改 ApprovalBroker 路径。
//!
//! 第四条断言守门 `Approve` 缺 `scope` → `HubError::Invalid`(α2 唯一新增 variant)。

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::sync::Arc;
use std::time::Duration;

use vigil_audit::{ApprovalTargetContext, Ledger};
use vigil_firewall::scorer::{DescriptorOracle, DescriptorStatus, StaticDescriptorOracle};
use vigil_firewall::{Firewall, FirewallConfig};
use vigil_mcp::{Hub, HubConfig, HubError};
use vigil_policy::{defaults::default_ruleset, PolicyEngine};
use vigil_types::{ApprovalScope, ApprovalStatus, DecisionKind, DecisionRecord, EffectVector};
use vigil_ui_protocol::{ApprovalAction, ResolveApprovalReq};

/// 组装一个最小 Hub(in-memory ledger + default policy + StaticDescriptorOracle)。
/// 与 `tests/hub_acceptance.rs::setup_hub` 同模式,但本文件不需要 firewall 评估,
/// approval_wait 设短没意义(本测试只走 resolve 同步路径,不 wait)。
fn setup_hub() -> (Arc<Ledger>, Hub) {
    let ledger = Arc::new(Ledger::open_in_memory().unwrap());
    let policy = PolicyEngine::new(default_ruleset());
    let firewall = Arc::new(Firewall::new(
        ledger.clone(),
        policy,
        FirewallConfig::default(),
    ));
    let oracle: Arc<dyn DescriptorOracle> =
        Arc::new(StaticDescriptorOracle(DescriptorStatus::ApprovedStable));
    let hub = Hub::new(
        ledger.clone(),
        firewall,
        oracle,
        HubConfig {
            // 本测试不走 wait 路径;保留默认即可,这里短设以防未来误用
            approval_wait: Duration::from_millis(50),
            ..Default::default()
        },
        vigil_mcp::SecretAliasMap::default(),
    );
    (ledger, hub)
}

/// 在 in-memory ledger 上建一条 Pending approval,返回 approval_id。
fn create_pending_approval(ledger: &Ledger) -> String {
    let session_id = ledger
        .start_session("test", Some("vigil-mcp-resolve-approval-test"))
        .unwrap();
    let decision = DecisionRecord {
        decision_id: "dec-α2-test".to_string(),
        invocation_id: "inv-α2-test".to_string(),
        decision: DecisionKind::Approve,
        risk_score: 50,
        reasons: vec!["α2 test fixture".into()],
        policy_ids: vec!["test-policy".into()],
        created_at: 0,
    };
    let effects = EffectVector::default();
    let req = ledger
        .create_approval(
            &session_id,
            &decision,
            &effects,
            "α2 test approval",
            "fixture for resolve_approval thin-wrapper",
            300,
            ApprovalTargetContext::default(),
        )
        .unwrap();
    req.approval_id
}

#[test]
fn hub_resolve_approval_approve_returns_approved() {
    let (ledger, hub) = setup_hub();
    let approval_id = create_pending_approval(&ledger);

    let dto = hub
        .resolve_approval(ResolveApprovalReq {
            approval_id: approval_id.clone(),
            action: ApprovalAction::Approve,
            scope: Some(ApprovalScope::Once),
            resolved_by: "tester".into(),
            reason: None,
        })
        .expect("approve thin-wrapper should succeed");

    assert_eq!(dto.approval_id, approval_id);
    assert_eq!(dto.status, ApprovalStatus::Approved);
    assert_eq!(
        dto.scope,
        Some(ApprovalScope::Once),
        "approve 必须把 scope 透传到 DTO(audit 层 resolve 已写 DB 列)"
    );
    assert_eq!(dto.resolved_by.as_deref(), Some("tester"));
}

#[test]
fn hub_resolve_approval_deny_returns_denied() {
    let (ledger, hub) = setup_hub();
    let approval_id = create_pending_approval(&ledger);

    let dto = hub
        .resolve_approval(ResolveApprovalReq {
            approval_id: approval_id.clone(),
            action: ApprovalAction::Deny,
            scope: None,
            resolved_by: "tester".into(),
            reason: Some("not now".into()),
        })
        .expect("deny thin-wrapper should succeed");

    assert_eq!(dto.approval_id, approval_id);
    assert_eq!(dto.status, ApprovalStatus::Denied);
    // deny 不写 scope(audit 层 resolve 仅在 Approved 路径写 scope_str)
    assert_eq!(dto.scope, None);
    assert_eq!(dto.resolved_by.as_deref(), Some("tester"));
}

#[test]
fn hub_resolve_approval_cancel_returns_cancelled() {
    let (ledger, hub) = setup_hub();
    let approval_id = create_pending_approval(&ledger);

    let dto = hub
        .resolve_approval(ResolveApprovalReq {
            approval_id: approval_id.clone(),
            action: ApprovalAction::Cancel,
            scope: None,
            resolved_by: "tester".into(),
            reason: None,
        })
        .expect("cancel thin-wrapper should succeed");

    assert_eq!(dto.approval_id, approval_id);
    assert_eq!(dto.status, ApprovalStatus::Cancelled);
    assert_eq!(dto.scope, None);
    assert_eq!(dto.resolved_by.as_deref(), Some("tester"));
}

#[test]
fn hub_resolve_approval_approve_without_scope_returns_invalid() {
    let (ledger, hub) = setup_hub();
    let approval_id = create_pending_approval(&ledger);

    let err = hub
        .resolve_approval(ResolveApprovalReq {
            approval_id,
            action: ApprovalAction::Approve,
            scope: None, // ← 缺 scope
            resolved_by: "tester".into(),
            reason: None,
        })
        .expect_err("approve without scope must fail");

    match err {
        HubError::Invalid(msg) => assert!(
            msg.contains("scope"),
            "Invalid error message 应说明缺 scope:got `{msg}`"
        ),
        other => panic!("期望 HubError::Invalid,得到 {other:?}"),
    }
}
