//! v0.5 P1 ADR 0014 α2 — embed-path Hub.resolve_approval 集成守门测试。
//!
//! 4 子测试:
//! - (a) approve 路径 DTO 投影正确
//! - (b) deny 路径 DTO 投影正确
//! - (c) cancel 路径 DTO 投影正确
//! - (d) **Condvar 唤醒延迟 < 100ms** —— 排除 ISS-019 500ms fallback 路径,
//!   证明 in-process broker.publish 直接生效
//!
//! 真 in-memory Ledger + 真 wait_for_resolution + Instant 测量 —— 不 mock。
//!
//! # 与 `crates/vigil-mcp/tests/resolve_approval.rs` 的边界
//!
//! 那 4 单测验证 `Hub::resolve_approval` 自身的语义(approve/deny/cancel 三态 +
//! 缺 scope `HubError::Invalid`),不涉及 GUI bin 的 Hub 组装路径。本文件走
//! `vigil_desktop::embed::gui_build_hub`(α1 7 步组装),覆盖 GUI 进程内
//! "Hub.resolve_approval → Ledger.{approve,deny,cancel} → ApprovalBroker.publish
//! → 同进程 wait_for_resolution Condvar 唤醒"完整链路 —— 这是 ADR 0014 §3.4
//! "GUI bin embed Hub" 的核心收益:in-process Condvar 唤醒延迟 ≈ 0,而非
//! ISS-019 cross-proc 路径下 ≤500ms 的短轮询兜底。
//!
//! # 阈值 100ms 的选择
//!
//! `WAIT_POLL_INTERVAL = 500ms`(crates/vigil-audit/src/approvals.rs:541)。
//! 若 in-process broker.publish 被绕过(例如未来回归到 cross-proc 写 DB 不调
//! `publish` 的实现),wait_for_resolution 必须等到下一片轮询才检出 ——
//! 测得延迟会落在 [0, 500ms] 区间且偏向高端。100ms 阈值留出 5× 安全裕度,
//! 远低于 500ms 单片;一旦超 100ms,几乎可肯定走的是 fallback。

#![cfg(feature = "gui")]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::sync::mpsc;
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

use vigil_audit::{ApprovalTargetContext, Ledger};
use vigil_desktop::embed::gui_build_hub;
use vigil_mcp::Hub;
use vigil_types::{ApprovalScope, ApprovalStatus, DecisionKind, DecisionRecord, EffectVector};
use vigil_ui_protocol::{ApprovalAction, ResolveApprovalReq};

/// 组装一个走 α1 `gui_build_hub` 的 Hub + 在 ledger 上预置一条 Pending approval。
///
/// 与 `crates/vigil-mcp/tests/resolve_approval.rs::create_pending_approval` 复用同一
/// `Ledger::create_approval` 入口(那是 ledger 公开的唯一 approval 创建路径);
/// 区别只在 Hub 通过 `gui_build_hub` 组装,确保走 GUI bin 真实路径。
///
/// 注意 `gui_build_hub` 内部已调 `ledger.start_session("vigil-desktop-gui", ...)`,
/// 所以这里再开一条独立的测试 session 不会冲突 —— ledger 支持多 session。
fn build_hub_with_pending_approval() -> (Arc<Hub>, Arc<Ledger>, String) {
    let ledger = Arc::new(Ledger::open_in_memory().expect("open in-memory ledger"));
    let hub = gui_build_hub(Arc::clone(&ledger)).expect("gui_build_hub should succeed");

    // 测试 fixture session(与 gui_build_hub 内部的 "vigil-desktop-gui" session 平行;
    // ledger 不要求 1-session)
    let session_id = ledger
        .start_session("test-α2", Some("embed_hub_resolve_approval"))
        .expect("start fixture session");

    let decision = DecisionRecord {
        decision_id: "dec-α2-embed".to_string(),
        invocation_id: "inv-α2-embed".to_string(),
        decision: DecisionKind::Approve,
        risk_score: 50,
        reasons: vec!["α2 embed-path test fixture".into()],
        policy_ids: vec!["test-policy".into()],
        created_at: 0,
    };
    let effects = EffectVector::default();
    let req = ledger
        .create_approval(
            &session_id,
            &decision,
            &effects,
            "α2 embed test approval",
            "fixture for embed-path resolve_approval",
            300,
            ApprovalTargetContext::default(),
        )
        .expect("create pending approval");

    (hub, ledger, req.approval_id)
}

/// (a) approve 路径 —— DTO `status = Approved`,`scope` 透传,`resolved_by` 落位。
#[test]
fn hub_resolve_approval_approve_returns_approved_dto() {
    let (hub, _ledger, approval_id) = build_hub_with_pending_approval();

    let dto = hub
        .resolve_approval(ResolveApprovalReq {
            approval_id: approval_id.clone(),
            action: ApprovalAction::Approve,
            scope: Some(ApprovalScope::Once),
            resolved_by: "test-user".into(),
            reason: None,
        })
        .expect("approve via embed Hub should succeed");

    assert_eq!(dto.approval_id, approval_id);
    assert_eq!(dto.status, ApprovalStatus::Approved);
    assert_eq!(
        dto.scope,
        Some(ApprovalScope::Once),
        "approve 必须把 scope 透传到 DTO(audit 层 resolve 已写 scope_str DB 列)"
    );
    assert_eq!(dto.resolved_by.as_deref(), Some("test-user"));
}

/// (b) deny 路径 —— DTO `status = Denied`,scope 不写(audit 层 resolve 仅 Approved 写 scope)。
#[test]
fn hub_resolve_approval_deny_returns_denied_dto() {
    let (hub, _ledger, approval_id) = build_hub_with_pending_approval();

    let dto = hub
        .resolve_approval(ResolveApprovalReq {
            approval_id: approval_id.clone(),
            action: ApprovalAction::Deny,
            scope: None,
            resolved_by: "test-user".into(),
            reason: Some("not authorized".into()),
        })
        .expect("deny via embed Hub should succeed");

    assert_eq!(dto.approval_id, approval_id);
    assert_eq!(dto.status, ApprovalStatus::Denied);
    assert_eq!(dto.scope, None);
    assert_eq!(dto.resolved_by.as_deref(), Some("test-user"));
}

/// (c) cancel 路径 —— DTO `status = Cancelled`。
#[test]
fn hub_resolve_approval_cancel_returns_cancelled_dto() {
    let (hub, _ledger, approval_id) = build_hub_with_pending_approval();

    let dto = hub
        .resolve_approval(ResolveApprovalReq {
            approval_id: approval_id.clone(),
            action: ApprovalAction::Cancel,
            scope: None,
            resolved_by: "test-user".into(),
            reason: None,
        })
        .expect("cancel via embed Hub should succeed");

    assert_eq!(dto.approval_id, approval_id);
    assert_eq!(dto.status, ApprovalStatus::Cancelled);
    assert_eq!(dto.scope, None);
    assert_eq!(dto.resolved_by.as_deref(), Some("test-user"));
}

/// (d) **关键守门** —— `wait_for_resolution` 在同进程 `Hub::resolve_approval` 触发
/// `ApprovalBroker::publish` 后必须 < 100ms 返回。
///
/// 阈值 100ms 排除 ISS-019 500ms 短轮询 fallback 路径(WAIT_POLL_INTERVAL,
/// crates/vigil-audit/src/approvals.rs:541)。若该断言失败,说明 GUI bin embed
/// Hub 没有真正走 in-process 路径 —— ADR 0014 α2 的核心收益(避免 cross-proc
/// 短轮询)即被破坏。
#[test]
fn hub_resolve_approval_wakes_waiter_under_100ms() {
    let (hub, ledger, approval_id) = build_hub_with_pending_approval();

    // waiter 线程:阻塞在 ledger.wait_for_resolution,timeout 设 10s 远大于阈值,
    // 确保不靠 timeout 提前返;wait 返回时通过 channel 把"返回时刻"传回主线程。
    let (tx, rx) = mpsc::channel();
    let ledger_for_wait = Arc::clone(&ledger);
    let approval_id_for_wait = approval_id.clone();
    let waiter = thread::spawn(move || {
        let result =
            ledger_for_wait.wait_for_resolution(&approval_id_for_wait, Duration::from_secs(10));
        // recv_at 测在拿到 result 之后、send 之前 —— 最贴近 wait_timeout 真实唤醒时刻
        let recv_at = Instant::now();
        tx.send(recv_at).expect("send recv_at to main thread");
        result
    });

    // 让 waiter 进入 Condvar wait_timeout(避免 fast-path:create_approval 后状态仍是
    // Pending,fast-path `current_resolution` 会返 None,直接进 slow-path 阻塞)。
    // 50ms sleep 给 waiter 充足启动时间但不浪费测试预算。
    thread::sleep(Duration::from_millis(50));

    // 主线程 publish:Hub.resolve_approval → Ledger.approve → ApprovalBroker.publish
    let publish_at = Instant::now();
    hub.resolve_approval(ResolveApprovalReq {
        approval_id: approval_id.clone(),
        action: ApprovalAction::Approve,
        scope: Some(ApprovalScope::Once),
        resolved_by: "test-user".into(),
        reason: None,
    })
    .expect("approve via embed Hub should succeed");

    // 接收 waiter 返回时刻;recv_timeout 给 2s 包络,若超 2s 说明 wait 完全没醒。
    let recv_at = rx
        .recv_timeout(Duration::from_secs(2))
        .expect("waiter must report recv_at within 2s of publish");
    let wakeup_latency = recv_at.saturating_duration_since(publish_at);
    // α4 机器可读样本(stdout):e2e runner `scripts/test-local/e2e-embed-approval/run.mjs`
    // 用 `^WAKEUP_LATENCY_NS=(\d+)$` 抽样 N=10 次。eprintln 人类可读样本保留(line 222)。
    println!("WAKEUP_LATENCY_NS={}", wakeup_latency.as_nanos());

    // 验 wait 真拿到了 resolution(防 timeout / err 静默通过断言)
    let result = waiter
        .join()
        .expect("waiter thread should not panic")
        .expect("wait_for_resolution should not Err");
    let resolution = result.expect("wait must return Some(resolution), not None (timeout)");
    assert_eq!(resolution.approval_id, approval_id);
    assert_eq!(resolution.status, ApprovalStatus::Approved);

    assert!(
        wakeup_latency < Duration::from_millis(100),
        "Condvar wakeup latency {wakeup_latency:?} >= 100ms — \
         this means we hit ISS-019 500ms short-poll fallback rather than \
         in-process broker.publish; α2 single-process Hub embed not effective. \
         See ADR 0014 Revised α2 + crates/vigil-audit/src/approvals.rs:700-704 \
         (atomic publish-after-write) and approvals.rs:541 (WAIT_POLL_INTERVAL=500ms)."
    );

    // 输出实测延迟样本(运行 `cargo test -- --nocapture` 可见,便于回归监控)
    eprintln!("wakeup_latency sample: {wakeup_latency:?}");
}
