//! ISS-008 Phase 1 — engine.rs 默认 feature 集成测试。
//!
//! 4 类不变量:
//! 1. `MockEngine::default()` 等价 `scan_text`(NoopEngine delegating 不漂)
//! 2. `MockEngine::from_findings` non-overlap 进 merged + overlap Hard 赢(ADR 0013 D3)
//! 3. fail-closed:本地 `LocalFailingEngine` 触发 `ScanError::InferenceFailed`,reason 不漏 input
//! 4. `Send + Sync` 静态守门(编译期)

// 集成测试整体 = test 代码,workspace clippy 把 panic/unwrap/expect 设为 warn
// 是为生产路径守门;按 workspace Cargo.toml 注释口径"测试代码可用",这里
// 整文件 allow,与 lib.rs:28 既有处理一致。
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use vigil_redaction::{
    scan_text, scan_text_with_engine, EngineError, Finding, FindingSource, MockEngine, NoopEngine,
    RedactionEngine, ScanError,
};

// ──────────────────────────── 测试 1:默认 Mock 等价 scan_text ────────────────────────────

#[test]
fn mock_engine_default_equals_scan_text() {
    let input = "Email me at noreply@example.com on 192.168.1.1";
    let r1 = scan_text(input).expect("scan_text 非空必成功");
    let r2 = scan_text_with_engine(input, &MockEngine::default()).expect("MockEngine 默认空");

    assert_eq!(r1.redacted_text, r2.redacted_text, "redacted_text 必须等价");
    assert_eq!(r1.findings, r2.findings, "findings 列表必须等价");
    assert_eq!(r1.risk_signals, r2.risk_signals, "risk_signals 必须等价");
}

// ──────────────────────────── 测试 2a:non-overlap 进 merged ────────────────────────────

#[test]
fn mock_engine_from_findings_non_overlap_enters_merged() {
    // 用纯字面量字符串保证字节边界对齐(无 multi-byte char)
    let input = "Alice met Bob at the cafe";
    // input.len() = 25;mock 占 (0..5) "Alice"
    let mock = Finding::model("private_person", (0, 5), 0.9, 0);
    let baseline = scan_text(input).expect("baseline 非空");
    let r = scan_text_with_engine(input, &MockEngine::from_findings(vec![mock.clone()]))
        .expect("with mock 必成功");

    // baseline 上无任何硬指纹命中,findings 空;mock 应进入 merged
    assert_eq!(
        r.findings.len(),
        baseline.findings.len() + 1,
        "non-overlap mock 必须进 merged(baseline={}, with mock={})",
        baseline.findings.len(),
        r.findings.len()
    );
    assert!(
        r.findings
            .iter()
            .any(|f| matches!(f.source, FindingSource::Model) && f.kind == "private_person"),
        "merged 必须含 mock private_person finding"
    );
    // risk_delta 由 caller 注入:Person → 5(scan.rs::risk_of)
    let person = r
        .findings
        .iter()
        .find(|f| f.kind == "private_person")
        .expect("有 person");
    assert_eq!(person.risk_delta, 5, "risk_of(private_person) 应 = 5");
}

// ──────────────────────────── 测试 2b:overlap Hard 赢(ADR 0013 D3) ────────────────────────────

#[test]
fn mock_engine_overlap_hard_wins() {
    // 构造硬指纹 stripe key(必中 stripe_secret_key);mock 故意覆盖同一 span
    let secret = "sk_test_abcdefghijklmnopqrstuvwxyz12";
    let input = format!("payment key {secret}");
    let secret_start = 12; // "payment key " 长度
    let secret_end = secret_start + secret.len();

    // mock model finding 覆盖完全同一 span,模拟模型也认出来了
    let overlapping_mock = Finding::model("private_person", (secret_start, secret_end), 0.95, 0);
    let r = scan_text_with_engine(
        &input,
        &MockEngine::from_findings(vec![overlapping_mock.clone()]),
    )
    .expect("scan with mock");

    // 覆盖 span 应只保留 Hard,不留 Model(D3)
    let model_in_span = r
        .findings
        .iter()
        .any(|f| matches!(f.source, FindingSource::Model) && f.span == (secret_start, secret_end));
    assert!(!model_in_span, "ADR 0013 D3:overlap 时 Model 必须被丢弃");

    let hard_in_span = r
        .findings
        .iter()
        .any(|f| matches!(f.source, FindingSource::Hard) && f.kind == "stripe_secret_key");
    assert!(hard_in_span, "Hard stripe_secret_key 必须保留");
}

// ──────────────────────────── 测试 3:fail-closed,reason 不漏 input ────────────────────────────

/// 本地测试专用 engine:总是返 InferRun,验证 fail-closed 路径。
struct LocalFailingEngine;

impl RedactionEngine for LocalFailingEngine {
    fn infer(&self, _text: &str) -> Result<Vec<Finding>, EngineError> {
        Err(EngineError::InferRun("simulated failure for test".into()))
    }
}

#[test]
fn failing_engine_fail_closed_returns_inference_failed() {
    // 关键安全不变量:reason 必须不含 input 内容,避免 audit log 把 secret 写出去
    let secret_input = "my-super-secret-token-XYZ-789-abc";
    let result = scan_text_with_engine(secret_input, &LocalFailingEngine);

    let reason = match result {
        Err(ScanError::InferenceFailed { reason }) => reason,
        Ok(r) => panic!("应 fail-closed,实际 Ok: {:?}", r),
        Err(other) => panic!("应 InferenceFailed,实际 {:?}", other),
    };

    assert!(!reason.is_empty(), "reason 不能为空");
    // C-2 不变量:From<EngineError> 只取 e.to_string(),不拼 input
    assert!(
        !reason.contains("super-secret-token-XYZ-789-abc"),
        "reason MUST NOT leak input content: got {reason}"
    );
    assert!(
        !reason.contains(secret_input),
        "reason MUST NOT leak full input"
    );
    // 但 reason 应含 InferRun 的错误描述,便于诊断
    assert!(
        reason.contains("simulated failure") || reason.contains("inference run failed"),
        "reason 应来自 EngineError Display: got {reason}"
    );
}

// ──────────────────────────── 测试 4:Send + Sync 编译期守门 ────────────────────────────

#[test]
fn engine_send_sync_static_assertion() {
    fn _assert_send_sync<T: Send + Sync>() {}
    _assert_send_sync::<Box<dyn RedactionEngine>>();
    _assert_send_sync::<MockEngine>();
    _assert_send_sync::<NoopEngine>();
    _assert_send_sync::<LocalFailingEngine>();
    // 通过 = 编译过 = 绑定的类型集合都是 Send + Sync
}
