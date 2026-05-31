//! ISS-008 Phase 1 — OrtEngine smoke test(真模型推理三层 gate)。
//!
//! # 三层 gate(默认环境 0 开销)
//!
//! 1. `#![cfg(feature = "ort")]` — 默认 feature 完全不编译此文件
//! 2. `#[ignore]` — 即使 `--features ort` 跑 cargo test,默认仍跳过
//! 3. 运行时 `VIGIL_RUN_ORT_SMOKE=1` env 检查 — 显式 opt-in;否则即使 `--ignored` 也 graceful skip
//!
//! # 运行命令(本地 dev)
//!
//! ```bash
//! # 前置:
//! # 1) onnxruntime.dll/.so on PATH(load-dynamic 运行时加载)
//! # 2) VIGIL_PRIVACY_FILTER_MODEL_DIR=<absolute path>(目录含 tokenizer.json / config.json / model_q4f16.onnx)
//! # 3) VIGIL_RUN_ORT_SMOKE=1
//!
//! VIGIL_RUN_ORT_SMOKE=1 cargo test -p vigil-redaction --features ort --test engine_ort_smoke -- --ignored
//! ```
//!
//! # 断言
//!
//! - (a) `OrtEngine::from_env()` 成功(模型文件全齐)
//! - (b) 中样本推理产 ≥ 1 个 finding,且至少一个是 model 来源(`PrivacyLabel` 映射后的 kind)
//! - (c) warm 推理(第二次调用)< 2s(ISS-022 spike 实测 358-630ms,2s 留 3-5× 余量)

#![cfg(feature = "ort")]
// 集成测试整体 = test 代码,workspace clippy 把 panic/unwrap/expect 设为 warn
// 是为生产路径守门;按 workspace Cargo.toml 注释口径"测试代码可用",这里
// 整文件 allow,与 lib.rs:28 既有处理一致。
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::time::Instant;
use vigil_redaction::{scan_text_with_engine, FindingSource, OrtEngine, PrivacyLabel};

// v0.5 P2 ISS-008 Phase 3:fixture(labeled_samples.json)反序列化结构。
// label 字面量必须与 PrivacyLabel::as_str() 返回值严格一致;由 ort_smoke_per_label_coverage 守门。
#[derive(serde::Deserialize, Debug)]
struct Sample {
    id: String,
    text: String,
    truth: Vec<TruthSpan>,
    category: String,
}

#[derive(serde::Deserialize, Debug)]
struct TruthSpan {
    label: String,
    // smoke 测试只断言"该 label 至少 1 命中",不卡 span 边界(精确 IoU 留给 bench)。
    // 字段保留供未来扩展 + fixture schema 一致性校验,因此 allow(dead_code)。
    #[allow(dead_code)]
    start: usize,
    #[allow(dead_code)]
    end: usize,
}

/// 加载 v0.5 P2 fixture(crates/vigil-redaction/tests/fixtures/labeled_samples.json)。
/// 用 concat!(env!("CARGO_MANIFEST_DIR"), ...) 取绝对路径,避免 cargo 不同 cwd 下漂移。
fn load_labeled_samples() -> Vec<Sample> {
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/fixtures/labeled_samples.json"
    );
    let raw = std::fs::read_to_string(path).unwrap_or_else(|e| panic!("read fixture {path}: {e}"));
    serde_json::from_str::<Vec<Sample>>(&raw)
        .unwrap_or_else(|e| panic!("parse fixture {path}: {e}"))
}

#[test]
#[ignore = "requires VIGIL_RUN_ORT_SMOKE=1 + VIGIL_PRIVACY_FILTER_MODEL_DIR + onnxruntime.dll on path"]
fn ort_smoke_from_env_and_infer() {
    // 第三层 gate:运行时 env 检查
    if std::env::var("VIGIL_RUN_ORT_SMOKE").as_deref() != Ok("1") {
        eprintln!("skip: VIGIL_RUN_ORT_SMOKE != 1");
        return;
    }

    // (a) from_env 成功
    let engine = OrtEngine::from_env().unwrap_or_else(|e| {
        panic!(
            "OrtEngine::from_env failed (check VIGIL_PRIVACY_FILTER_MODEL_DIR + model files): {e:?}"
        )
    });

    // (b) 中样本(spike main.rs:96-100 已验证此样本产 8/8 类标签命中)
    let input = "Alice Johnson was born on 1990-01-02. \
                 Contact alice.johnson@acme-corp.example.com or call +1 (555) 123-4567. \
                 Her home address is 742 Evergreen Terrace, Springfield, IL 62704.";
    let result = scan_text_with_engine(input, &engine)
        .expect("scan_text_with_engine should not fail on medium sample");
    assert!(
        !result.findings.is_empty(),
        "expected ≥ 1 finding for medium sample, got 0"
    );
    let model_findings: Vec<_> = result
        .findings
        .iter()
        .filter(|f| matches!(f.source, FindingSource::Model))
        .collect();
    assert!(
        !model_findings.is_empty(),
        "expected ≥ 1 model finding (Privacy Filter Source::Model), got only Hard. \
         findings={:?}",
        result.findings
    );

    // (c) warm 推理 < 2s(第二次调用避开 cold start)
    let start = Instant::now();
    let _ = scan_text_with_engine(input, &engine).expect("warm inference must succeed");
    let elapsed = start.elapsed();
    assert!(
        elapsed.as_millis() < 2000,
        "warm inference must be < 2s, got {}ms (ISS-022 spike: 358-630ms)",
        elapsed.as_millis()
    );
}

/// v0.5 P2 ISS-008 Phase 3:8 类 PrivacyLabel 断言矩阵(逐桶覆盖)。
///
/// # 设计
///
/// - **加载 fixture**(20 样本):7 类软标签 ≥ 2 + secret 1 + clean 1
/// - **逐样本调用** `scan_text_with_engine(text, &OrtEngine)`(走完整 Hard + Model + merge 链路)
/// - **逐 truth.label 断言**:findings 中至少 1 项的 kind 经 PrivacyLabel::from_kind 路由后
///   等于该 label;否则 panic 并 dump 样本 id + label + 实际 findings
/// - secret 类样本依赖 HARD_RULES 命中(github_token kind),merge 后仍是 Secret 桶(D1 Hard 优先)
/// - soft 类样本依赖 OrtEngine BIOES 解码后产 model finding,经 from_kind 路由到对应桶
/// - clean baseline 样本不断言"产 0 finding"(模型可能误报,这是 bench 而非 smoke 关注点)
///
/// # 沿用三层 gate
///
/// 与 [`ort_smoke_from_env_and_infer`] 同模板:
/// 1. `#![cfg(feature = "ort")]`(文件级)
/// 2. `#[ignore = "..."]`(默认 cargo test 跳过)
/// 3. 运行时 `VIGIL_RUN_ORT_SMOKE=1` 短路(显式 opt-in)
///
/// 测试结束在 stderr 打印每类命中样本计数,便于 ad-hoc 看回归。
/// **不**写硬阈值断言(精确 IoU/precision/recall 留给 benches/precision_recall.rs)。
#[test]
#[ignore = "requires VIGIL_RUN_ORT_SMOKE=1 + VIGIL_PRIVACY_FILTER_MODEL_DIR + onnxruntime.dll on path"]
fn ort_smoke_per_label_coverage() {
    // 第三层 gate:运行时 env 检查
    if std::env::var("VIGIL_RUN_ORT_SMOKE").as_deref() != Ok("1") {
        eprintln!("skip: VIGIL_RUN_ORT_SMOKE != 1");
        return;
    }

    // 模型加载失败视为"模型未分发"→ graceful skip,不 panic
    let engine = match OrtEngine::from_env() {
        Ok(e) => e,
        Err(e) => {
            eprintln!("skip: OrtEngine::from_env failed (model not distributed?): {e:?}");
            return;
        }
    };

    let samples = load_labeled_samples();
    // v0.6 P2:fixture 从 20 扩展到 26(加 6 个 zh/ja/ko multilang-soft 样本);
    // assert 改为下界守门"不退化"而非精确数,允许后续追加
    assert!(
        samples.len() >= 20,
        "fixture 必须 ≥ 20 样本(防退化护栏);当前 {}",
        samples.len()
    );

    // per-label 命中计数(只看 truth 出现过的 label)
    let mut hit_counts: std::collections::BTreeMap<&'static str, u32> =
        std::collections::BTreeMap::new();
    for label in PrivacyLabel::ALL {
        hit_counts.insert(label.as_str(), 0);
    }

    for sample in &samples {
        // 全链路扫描(Hard + Model + merge);engine.infer 失败 → InferenceFailed,直接 panic 暴露
        let result = scan_text_with_engine(&sample.text, &engine).unwrap_or_else(|e| {
            panic!("sample {} scan failed: {e:?}", sample.id);
        });

        // 对每条 truth label,要求 findings 中至少 1 项映射到该 PrivacyLabel
        for truth in &sample.truth {
            let expected_label = match truth.label.as_str() {
                "person" => PrivacyLabel::Person,
                "email" => PrivacyLabel::Email,
                "phone" => PrivacyLabel::Phone,
                "address" => PrivacyLabel::Address,
                "date" => PrivacyLabel::Date,
                "url" => PrivacyLabel::Url,
                "account_number" => PrivacyLabel::AccountNumber,
                "secret" => PrivacyLabel::Secret,
                other => panic!("fixture {} 含未知 label {other:?}", sample.id),
            };

            let any_hit = result
                .findings
                .iter()
                .any(|f| PrivacyLabel::from_kind(f.kind) == Some(expected_label));

            assert!(
                any_hit,
                "sample {} (category={}) 期望 label {} 至少 1 命中,实际 findings={:#?}",
                sample.id, sample.category, truth.label, result.findings
            );

            *hit_counts.entry(expected_label.as_str()).or_insert(0) += 1;
        }
    }

    // 每类至少 1 命中(7 软 + secret;clean baseline 无 truth 不计入)
    for (label, count) in &hit_counts {
        eprintln!("[ort_smoke_per_label_coverage] {label} hit count = {count}");
    }
    for (label, count) in &hit_counts {
        // FindingSource 仅供 stderr 报告时区分 Hard/Model 路径,不卡 source 来源(merge 已编排)
        let _ = FindingSource::Hard;
        assert!(
            *count >= 1,
            "PrivacyLabel {label} 在 fixture 中无任何样本命中(覆盖率 0/{n}); \
             期望每类 ≥ 1。请检查 fixture 是否含该类样本,或 OrtEngine BIOES 解码是否退化",
            n = samples.len()
        );
    }
}
