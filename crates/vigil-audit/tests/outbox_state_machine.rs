//! I04 Outbox 八态状态机的转换回归测试(Codex M4)。
//!
//! 覆盖:
//! - Drafted → PendingApproval(submit)
//! - PendingApproval → Approved(mark_outbox_approved)
//! - PendingApproval → Denied / Expired
//! - Approved → Executed / Failed
//! - Cancelled from Drafted / Cancelled from PendingApproval
//! - 非法跨态转换返回 InvalidInput
//! - preview_json 含 UTF-8 特殊字符 + 硬指纹时 fail-closed

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::err_expect,
    clippy::panic
)]

use serde_json::json;
use vigil_audit::{AuditError, Ledger, OutboxKind, OutboxStatus};

fn setup() -> (Ledger, String) {
    let l = Ledger::open_in_memory().unwrap();
    let sid = l.start_session("outbox_test", None).unwrap();
    (l, sid)
}

#[test]
fn drafted_to_pending_to_approved_to_executed() {
    let (l, sid) = setup();
    let oi = l
        .draft_outbox(
            "inv-1",
            &sid,
            OutboxKind::HttpPost,
            &json!({"url": "https://api.example.com/x"}),
        )
        .unwrap();
    assert_eq!(oi.status, OutboxStatus::Drafted);
    l.submit_outbox_for_approval(&oi.outbox_id, "appr-1")
        .unwrap();
    assert_eq!(
        l.get_outbox(&oi.outbox_id).unwrap().unwrap().status,
        OutboxStatus::PendingApproval
    );
    l.mark_outbox_approved(&oi.outbox_id).unwrap();
    assert_eq!(
        l.get_outbox(&oi.outbox_id).unwrap().unwrap().status,
        OutboxStatus::Approved
    );
    l.mark_outbox_executed(&oi.outbox_id).unwrap();
    let after = l.get_outbox(&oi.outbox_id).unwrap().unwrap();
    assert_eq!(after.status, OutboxStatus::Executed);
    assert!(after.executed_at.is_some());
    assert!(after.approved_at.is_some());
}

#[test]
fn denied_path_blocks_execution() {
    let (l, sid) = setup();
    let oi = l
        .draft_outbox(
            "inv-2",
            &sid,
            OutboxKind::HttpPost,
            &json!({"url": "https://x"}),
        )
        .unwrap();
    l.submit_outbox_for_approval(&oi.outbox_id, "appr-2")
        .unwrap();
    l.mark_outbox_denied(&oi.outbox_id).unwrap();
    // Denied 后不能再 approved / executed
    assert!(matches!(
        l.mark_outbox_approved(&oi.outbox_id),
        Err(AuditError::InvalidInput { .. })
    ));
    assert!(matches!(
        l.mark_outbox_executed(&oi.outbox_id),
        Err(AuditError::InvalidInput { .. })
    ));
}

#[test]
fn expired_path_blocks_execution() {
    let (l, sid) = setup();
    let oi = l
        .draft_outbox(
            "inv-3",
            &sid,
            OutboxKind::HttpPost,
            &json!({"url": "https://x"}),
        )
        .unwrap();
    l.submit_outbox_for_approval(&oi.outbox_id, "appr-3")
        .unwrap();
    l.mark_outbox_expired(&oi.outbox_id).unwrap();
    assert!(matches!(
        l.mark_outbox_executed(&oi.outbox_id),
        Err(AuditError::InvalidInput { .. })
    ));
}

#[test]
fn failed_path_from_approved() {
    let (l, sid) = setup();
    let oi = l
        .draft_outbox(
            "inv-4",
            &sid,
            OutboxKind::HttpPost,
            &json!({"url": "https://x"}),
        )
        .unwrap();
    l.submit_outbox_for_approval(&oi.outbox_id, "appr-4")
        .unwrap();
    l.mark_outbox_approved(&oi.outbox_id).unwrap();
    l.mark_outbox_failed(&oi.outbox_id).unwrap();
    assert_eq!(
        l.get_outbox(&oi.outbox_id).unwrap().unwrap().status,
        OutboxStatus::Failed
    );
}

#[test]
fn cancel_from_drafted() {
    let (l, sid) = setup();
    let oi = l
        .draft_outbox(
            "inv-5",
            &sid,
            OutboxKind::HttpPost,
            &json!({"url": "https://x"}),
        )
        .unwrap();
    l.cancel_outbox(&oi.outbox_id).unwrap();
    assert_eq!(
        l.get_outbox(&oi.outbox_id).unwrap().unwrap().status,
        OutboxStatus::Cancelled
    );
}

#[test]
fn cancel_from_pending_approval() {
    let (l, sid) = setup();
    let oi = l
        .draft_outbox(
            "inv-6",
            &sid,
            OutboxKind::HttpPost,
            &json!({"url": "https://x"}),
        )
        .unwrap();
    l.submit_outbox_for_approval(&oi.outbox_id, "appr-6")
        .unwrap();
    l.cancel_outbox(&oi.outbox_id).unwrap();
    assert_eq!(
        l.get_outbox(&oi.outbox_id).unwrap().unwrap().status,
        OutboxStatus::Cancelled
    );
}

#[test]
fn cannot_cancel_executed_or_denied() {
    let (l, sid) = setup();
    let oi = l
        .draft_outbox(
            "inv-7",
            &sid,
            OutboxKind::HttpPost,
            &json!({"url": "https://x"}),
        )
        .unwrap();
    l.submit_outbox_for_approval(&oi.outbox_id, "appr-7")
        .unwrap();
    l.mark_outbox_approved(&oi.outbox_id).unwrap();
    l.mark_outbox_executed(&oi.outbox_id).unwrap();
    assert!(matches!(
        l.cancel_outbox(&oi.outbox_id),
        Err(AuditError::InvalidInput { .. })
    ));
}

#[test]
fn submit_rejected_if_not_drafted() {
    let (l, sid) = setup();
    let oi = l
        .draft_outbox(
            "inv-8",
            &sid,
            OutboxKind::HttpPost,
            &json!({"url": "https://x"}),
        )
        .unwrap();
    l.submit_outbox_for_approval(&oi.outbox_id, "appr-8")
        .unwrap();
    assert!(matches!(
        l.submit_outbox_for_approval(&oi.outbox_id, "appr-other"),
        Err(AuditError::InvalidInput { .. })
    ));
}

#[test]
fn draft_fails_closed_on_utf8_hard_secret() {
    let (l, sid) = setup();
    // 非 ASCII 前缀 + GitHub token:JCS 会保留 Unicode,detect_hard_secret 应命中
    let preview = json!({
        "note": "中文前缀 ghp_abcdefghijklmnopqrstuvwxyzABCDEFGHIJ 混合",
        "meta": {"lang": "zh-CN"},
    });
    let err = l
        .draft_outbox("inv-9", &sid, OutboxKind::HttpPost, &preview)
        .err()
        .expect("preview 含硬指纹必须被 fail-closed 拒绝");
    assert!(matches!(err, AuditError::HardSecretDetected { .. }));
}
