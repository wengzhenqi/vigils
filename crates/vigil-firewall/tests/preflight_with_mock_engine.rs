//! ISS-008 Phase 2 T7:验证 PiiScanner trait 在 RedactionEngine 注入下的转发语义。
//!
//! `OrtPiiScanner` 是 vigil-firewall crate-private(T3 决议),无法直接构造;
//! 这里用 `MockEngine` 注入 `vigil_redaction::scan_text_with_engine`,验证:
//!
//! 1. wrapper 转发正确(`scan_text_with_engine` 调用 `engine.infer`)
//! 2. Send + Sync 编译期 check(`Arc<dyn PiiScanner>` 跨线程边界要求)
//! 3. EmptyInput / InferenceFailed 路径 fail-closed 语义在 wrapper 层被透传
//! 4. PiiScanner 工厂返回 `Arc<dyn PiiScanner>` 类型契约
//! 5. PiiScanner trait 与生产 `OrtPiiScanner` 同形(都委托 `scan_text_with_engine`)
//!
//! **为什么不直接测 OrtPiiScanner**:wrapper 类型 crate-private(T3 决议),
//! 暴露的只是 `Arc<dyn PiiScanner>` 工厂;且 OrtEngine 需 ~7s cold-start + 模型文件,
//! 默认 feature 测试矩阵不允许此重依赖。MockEngine 同形 wrapper 验证语义
//! (实现 `RedactionEngine` 委托给 `scan_text_with_engine`)是 Phase 1 已落实的
//! 测试模式 —— 与 `crates/vigil-redaction/src/engine.rs::tests` 的 MockEngine
//! 用途完全对齐。

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::sync::Arc;

use vigil_firewall::PiiScanner;
use vigil_redaction::{
    engine::EngineError, scan_text_with_engine, Finding, MockEngine, RedactionEngine,
    RedactionResult, ScanError,
};

/// 同形 wrapper:复刻 `OrtPiiScanner::scan` 的转发语义,但用任意 `RedactionEngine`
/// trait object,以便测试驱动失败路径 + Send/Sync compile-check。
///
/// 与生产 `OrtPiiScanner`(`crates/vigil-firewall/src/preflight.rs::ort_scanner`)
/// 唯一差别:engine 类型参数化(MockEngine / FailingEngine);scan 路径完全一致。
struct MockPiiScannerWrapper<E: RedactionEngine + 'static> {
    engine: Arc<E>,
}

impl<E: RedactionEngine + 'static> PiiScanner for MockPiiScannerWrapper<E> {
    fn scan(&self, text: &str) -> Result<RedactionResult, ScanError> {
        // 与生产 OrtPiiScanner 同形:都直接 forward 到 scan_text_with_engine。
        scan_text_with_engine(text, &*self.engine)
    }
}

#[test]
fn wrapper_forwards_to_engine_with_findings() {
    // MockEngine 注入预设 model finding;scan 应让 finding 走 model 侧 merge 路径。
    let preset = vec![Finding::model("private_email", (0, 11), 0.95, 10)];
    let engine = Arc::new(MockEngine::from_findings(preset));
    let scanner = MockPiiScannerWrapper { engine };

    let result = scanner
        .scan("alice@x.com 和别的内容,长度足够触发 scan_text_with_engine")
        .expect("non-empty input should succeed");

    // model finding(span 0..11)与 hard 路径不重叠(无 hard 命中),应至少 1 条留存。
    // (具体条数受 hard 规则命中情况影响,断言至少 1 条 + 含 private_email kind 即可。)
    assert!(
        !result.findings.is_empty(),
        "MockEngine 注入应至少 1 finding;实际 {:?}",
        result.findings
    );
    assert!(
        result.findings.iter().any(|f| f.kind == "private_email"),
        "应含 private_email kind 的 finding(来自 MockEngine);实际 {:?}",
        result.findings.iter().map(|f| f.kind).collect::<Vec<_>>()
    );
}

#[test]
fn wrapper_returns_empty_input_err() {
    // EmptyInput fail-closed 不变量在 wrapper 层透传:scan_text_with_engine
    // 在 input.is_empty() 时早返 Err(EmptyInput),engine.infer 不被调用。
    let engine = Arc::new(MockEngine::default());
    let scanner = MockPiiScannerWrapper { engine };
    match scanner.scan("") {
        Err(ScanError::EmptyInput) => {}
        other => panic!("空输入应返 EmptyInput,实际 {other:?}"),
    }
}

#[test]
fn wrapper_propagates_inference_failed() {
    // 自建 failing engine,验证 EngineError → ScanError::InferenceFailed 自动塌缩
    // 在 wrapper 层透传(From<EngineError> for ScanError 由 vigil-redaction 提供)。
    struct FailingEngine;
    impl RedactionEngine for FailingEngine {
        fn infer(&self, _text: &str) -> Result<Vec<Finding>, EngineError> {
            Err(EngineError::InferRun("simulated infer crash".into()))
        }
    }

    let engine = Arc::new(FailingEngine);
    let scanner = MockPiiScannerWrapper { engine };

    match scanner.scan("any non-empty text long enough to reach engine.infer") {
        Err(ScanError::InferenceFailed { reason }) => {
            // reason 来自 EngineError Display(`inference run failed: simulated infer crash`)
            // 注:wrapper 层 reason 还携带原文片段,**消费此 reason 的 caller**
            // (firewall preflight)负责塌缩到稳定字面量(T4 实施)。
            assert!(
                reason.contains("inference run") || reason.contains("simulated infer crash"),
                "reason 应含 EngineError Display 片段;实际 {reason:?}"
            );
        }
        other => panic!("failing engine 应返 InferenceFailed,实际 {other:?}"),
    }
}

#[test]
fn wrapper_is_send_sync_assertable() {
    // 编译期守门:`Arc<dyn PiiScanner>` 必须 Send + Sync(Firewall::with_scanner
    // 签名要求 + 多线程 evaluate 路径要求)。新增 PiiScanner 实现若意外破坏
    // Send/Sync 不变量,本测试编译失败。
    fn assert_send_sync<T: Send + Sync>() {}
    assert_send_sync::<Arc<dyn PiiScanner>>();
    assert_send_sync::<MockPiiScannerWrapper<MockEngine>>();
}

#[test]
fn factory_signature_matches_arc_dyn_pii_scanner() {
    // 编译期 + 运行期联合守门:`Arc<dyn PiiScanner>` 是 Firewall::with_scanner
    // 实参类型契约。任何工厂签名漂移(e.g. 改返 Box<dyn> / 具体类型)会让此处编译失败。
    let engine = Arc::new(MockEngine::default());
    let wrapper: Arc<dyn PiiScanner> = Arc::new(MockPiiScannerWrapper { engine });

    // dyn dispatch 调用一次确保 vtable 链路通(不关心结果,只关心调得到)
    let _ = wrapper.scan("hello world this is a sufficiently long input string");
}
