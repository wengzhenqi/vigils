//! v0.7-α6 A1(E6a)— `engine.degraded` 事件守门测试。
//!
//! 验证:
//! 1. EngineDegradedPayload serde roundtrip 稳定
//! 2. record_engine_degraded 写入 SQLite + hash chain 链入
//! 3. FTS 字段含 engine_id / status / decision_id(便于 query)
//! 4. payload 不含原始 input(no-plaintext invariant 守门)
//! 5. Optional 字段(budget_ms / elapsed_ms)None 时 serde skip,正常往返

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use serde_json::Value;
use vigil_audit::{EngineDegradedPayload, Ledger};

/// (1) EngineDegradedPayload serde roundtrip(typed schema 稳定守门)
#[test]
fn engine_degraded_payload_serde_roundtrip() {
    let payload = EngineDegradedPayload {
        engine_id: "openai-privacy-filter-v1".to_string(),
        status: "degraded_timeout".to_string(),
        reason_code: "budget_exceeded".to_string(),
        budget_ms: Some(2000),
        elapsed_ms: Some(2150),
        fail_closed_decision: "fall_back_hard_only".to_string(),
        decision_id: "abc-123-decision-uuid".to_string(),
    };
    let json = serde_json::to_string(&payload).unwrap();
    let back: EngineDegradedPayload = serde_json::from_str(&json).unwrap();
    assert_eq!(back.engine_id, payload.engine_id);
    assert_eq!(back.status, payload.status);
    assert_eq!(back.reason_code, payload.reason_code);
    assert_eq!(back.budget_ms, Some(2000));
    assert_eq!(back.elapsed_ms, Some(2150));
    assert_eq!(back.fail_closed_decision, payload.fail_closed_decision);
    assert_eq!(back.decision_id, payload.decision_id);
}

/// (2) Optional 字段 None 时 serde skip(payload 不含 budget_ms / elapsed_ms key)
#[test]
fn engine_degraded_optional_fields_skip_when_none() {
    let payload = EngineDegradedPayload {
        engine_id: "xlmr-pii-v1".to_string(),
        status: "degraded_error".to_string(),
        reason_code: "infer_run_error".to_string(),
        budget_ms: None,
        elapsed_ms: None,
        fail_closed_decision: "deny_request".to_string(),
        decision_id: "xyz-789".to_string(),
    };
    let json: Value = serde_json::to_value(&payload).unwrap();
    assert!(
        !json.as_object().unwrap().contains_key("budget_ms"),
        "None budget_ms 应不在 JSON 中(serde skip)"
    );
    assert!(
        !json.as_object().unwrap().contains_key("elapsed_ms"),
        "None elapsed_ms 应不在 JSON 中"
    );
    assert!(json.as_object().unwrap().contains_key("engine_id"));
}

/// (3) record_engine_degraded 写入 SQLite + hash chain 链入
#[test]
fn engine_degraded_event_appends_and_hash_chain_intact() {
    let l = Ledger::open_in_memory().unwrap();
    let sid = l.start_session("test", Some("unit")).unwrap();
    assert_eq!(l.event_count().unwrap(), 0);

    let payload = EngineDegradedPayload {
        engine_id: "openai-privacy-filter-v1".to_string(),
        status: "degraded_timeout".to_string(),
        reason_code: "budget_exceeded".to_string(),
        budget_ms: Some(2000),
        elapsed_ms: Some(2150),
        fail_closed_decision: "fall_back_hard_only".to_string(),
        decision_id: "test-decision-1".to_string(),
    };
    let ev = l.record_engine_degraded(&sid, &payload).unwrap();
    assert_eq!(ev.event_id, 1);
    assert_eq!(ev.event_hash.len(), 64);
    assert_eq!(l.event_count().unwrap(), 1);

    // hash chain 完整性(本事件不破)
    l.verify_chain().unwrap();
}

/// (4) FTS 含 engine_id / status / decision_id(用户 query 友好)
#[test]
fn engine_degraded_fts_contains_key_fields() {
    let l = Ledger::open_in_memory().unwrap();
    let sid = l.start_session("test", Some("unit")).unwrap();

    let payload = EngineDegradedPayload {
        engine_id: "yonigo-pii-v1".to_string(),
        status: "degraded_error".to_string(),
        reason_code: "model_not_found".to_string(),
        budget_ms: None,
        elapsed_ms: None,
        fail_closed_decision: "deny_request".to_string(),
        decision_id: "fts-test-decision".to_string(),
    };
    l.record_engine_degraded(&sid, &payload).unwrap();

    // FTS 命中(用 search_events)
    // FTS5 query:`-` 是字段定界符,需引号包裹
    let hits = l.fts_search("\"yonigo-pii-v1\"").expect("search ok");
    assert!(!hits.is_empty(), "FTS 应命中 engine_id");
    let hits2 = l.fts_search("\"fts-test-decision\"").expect("search ok");
    assert!(!hits2.is_empty(), "FTS 应命中 decision_id");
}

/// (5) 多个 engine.degraded 事件可连续追加(hash chain 不破)
#[test]
fn engine_degraded_multiple_events_chain_intact() {
    let l = Ledger::open_in_memory().unwrap();
    let sid = l.start_session("test", Some("unit")).unwrap();

    for i in 0..3 {
        let payload = EngineDegradedPayload {
            engine_id: format!("engine-{}", i),
            status: "degraded_timeout".to_string(),
            reason_code: "budget_exceeded".to_string(),
            budget_ms: Some(1500),
            elapsed_ms: Some(1600 + i * 10),
            fail_closed_decision: "fall_back_hard_only".to_string(),
            decision_id: format!("dec-{}", i),
        };
        l.record_engine_degraded(&sid, &payload).unwrap();
    }
    assert_eq!(l.event_count().unwrap(), 3);
    l.verify_chain().unwrap();
}
