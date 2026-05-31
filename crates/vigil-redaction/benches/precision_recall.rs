//! v0.5 P2 ISS-008 Phase 3 — Privacy Filter precision / recall benchmark。
//!
//! # 用途
//!
//! 对 [`crates/vigil-redaction/tests/fixtures/labeled_samples.json`] 20 条 ground-truth 样本,
//! 跑三组对比并产出 per-label precision/recall/F1 + 8x8(+1 none 行)confusion matrix +
//! 各组累计耗时 JSON 报告(给 ADR 0013 Revised 段引用)。
//!
//! ## 三组对比
//!
//! | 组 | 引擎 | 路径 |
//! |----|------|------|
//! | `hard_only`  | [`NoopEngine`] | `scan_text_with_engine`(NoopEngine.infer 返空 → merge 退化为 Hard 全保留)|
//! | `model_only` | [`OrtEngine`]  | 直接 `engine.infer`(跳过 merge,看模型原始输出)|
//! | `merge`      | [`OrtEngine`]  | `scan_text_with_engine`(完整 Hard + Model + ADR 0013 D1/D3/D4/D5)|
//!
//! ## 三层 gate(沿用 [`tests/engine_ort_smoke.rs`] 模板)
//!
//! 1. `[[bench]] required-features = ["ort"]`(Cargo.toml):默认 cargo build/test --workspace 0 ort 编译
//! 2. 文件级 `#![cfg(feature = "ort")]`(下方):防御性,即便误启用 bench 也只在 ort 时编译
//! 3. 运行时 `VIGIL_RUN_ORT_BENCH=1` 短路:显式 opt-in,否则 graceful skip
//!
//! ## 运行
//!
//! ```bash
//! # 前置:onnxruntime.dll on PATH + VIGIL_PRIVACY_FILTER_MODEL_DIR
//! VIGIL_RUN_ORT_BENCH=1 cargo run --bench precision_recall --features ort
//!
//! # 输出到文件(VIGIL_BENCH_OUT 设)
//! VIGIL_BENCH_OUT=dist/redaction-bench.json \
//!   VIGIL_RUN_ORT_BENCH=1 cargo run --bench precision_recall --features ort
//! ```
//!
//! ## 评估口径
//!
//! - **TP**(true positive):finding 与某 truth 满足 `IoU ≥ IOU_THRESHOLD` 且 label 一致(经 PrivacyLabel::from_kind 路由)
//! - **FP**(false positive):finding 无任何 truth 匹配
//! - **FN**(false negative):truth 无任何 finding 匹配
//! - precision = TP / (TP + FP);recall = TP / (TP + FN);F1 = 2PR / (P+R)(分母为 0 时 0)
//!
//! IoU 阈值 [`IOU_THRESHOLD`] = 0.5(NER 标准做法);如跨平台浮点 ULP 漂导致 span 边界 ±1 字节,
//! 可上调到 0.6 减边界敏感(由 ADR 0013 Revised fallback 条款覆盖)。
//!
//! **本 bench 不写硬阈值断言** —— 输出仅作观测报告,供 ADR Revised 解读 + v0.6 校准基线。

#![cfg(feature = "ort")]
// bench 整体 = 工具型 bin,workspace clippy 把 panic/unwrap/expect 设为 warn
// 是为生产路径守门;本 bench 是 ad-hoc 报告工具,与 tests/engine_ort_smoke.rs:30 同口径
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::collections::BTreeMap;
use std::time::Instant;

use serde::{Deserialize, Serialize};
use vigil_redaction::{
    scan_text_with_engine, EngineError, Finding, NoopEngine, OrtEngine, PrivacyLabel,
    RedactionEngine,
};

/// IoU 阈值(NER 标准 0.5);span 重叠面积 / 并集面积 ≥ 此值算 TP 候选。
const IOU_THRESHOLD: f64 = 0.5;

// ─────────────────────────── fixture 反序列化(与 tests/engine_ort_smoke.rs 同 schema)

#[derive(Deserialize, Debug)]
struct Sample {
    id: String,
    text: String,
    truth: Vec<TruthSpan>,
    /// fixture category — `soft` / `hard` / `clean` / `multilang-soft`(v0.6 P2 加);
    /// 用于 per-category 分组 bench(en-soft vs multilang-soft 跨语言对比)
    category: String,
}

#[derive(Deserialize, Debug)]
struct TruthSpan {
    label: String,
    start: usize,
    end: usize,
}

fn load_samples() -> Vec<Sample> {
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/fixtures/labeled_samples.json"
    );
    let raw = std::fs::read_to_string(path).unwrap_or_else(|e| panic!("read fixture {path}: {e}"));
    serde_json::from_str::<Vec<Sample>>(&raw)
        .unwrap_or_else(|e| panic!("parse fixture {path}: {e}"))
}

// ─────────────────────────── JSON 输出 schema

#[derive(Serialize)]
struct LabelMetrics {
    precision: f64,
    recall: f64,
    f1: f64,
    tp: u32,
    fp: u32,
    #[serde(rename = "fn")]
    fn_: u32,
}

#[derive(Serialize)]
struct GroupStats {
    /// per-label 指标;key 是 PrivacyLabel::as_str()(8 类)
    per_label: BTreeMap<String, LabelMetrics>,
    /// 全组累计(含 none 兜底统计)
    totals: LabelMetrics,
    /// 单组所有样本扫描累计耗时(毫秒)
    latency_ms: f64,
}

#[derive(Serialize)]
struct BenchReport {
    /// Unix 秒时间戳
    ts: u64,
    /// 样本数(下界 ≥ 20,fixture 可扩;v0.6 P2 已扩到 32)
    sample_count: usize,
    /// IoU 阈值(本 phase 0.5)
    iou_threshold: f64,
    /// 三组对比(hard_only / model_only / merge)
    per_group: BTreeMap<String, GroupStats>,
    /// merge 组按 fixture category 分组的 metrics(v0.6 P2 加);
    /// key = category 名(e.g., "soft" / "multilang-soft" / "hard" / "clean");
    /// 用于跨语言对比 — 比较 en-soft vs multilang-soft 的 recall 差距
    per_category_merge: BTreeMap<String, GroupStats>,
    /// 各 category 的样本数计数(便于解读 per_category_merge 是否有足够支撑)
    category_sample_counts: BTreeMap<String, usize>,
    /// 8x8(+1 none 行)merge 组 confusion matrix;
    /// 行 = truth label idx(0..7) + idx 8 = "no truth";
    /// 列 = predicted label idx(0..7) + idx 8 = "no prediction"
    confusion_matrix: Vec<Vec<u32>>,
    /// PrivacyLabel index → label 名称(便于 confusion_matrix 解读)
    label_index: Vec<String>,
}

// ─────────────────────────── 评估核心

/// span 1-D IoU(byte-level interval [start, end))。
fn iou(a: (usize, usize), b: (usize, usize)) -> f64 {
    let inter_start = a.0.max(b.0);
    let inter_end = a.1.min(b.1);
    if inter_start >= inter_end {
        return 0.0;
    }
    let inter = (inter_end - inter_start) as f64;
    let union_start = a.0.min(b.0);
    let union_end = a.1.max(b.1);
    let union = (union_end - union_start) as f64;
    if union <= 0.0 {
        0.0
    } else {
        inter / union
    }
}

/// truth.label 字符串 → PrivacyLabel;fixture 已守门 schema,不识别即 panic 修 fixture。
fn parse_truth_label(s: &str) -> PrivacyLabel {
    match s {
        "secret" => PrivacyLabel::Secret,
        "account_number" => PrivacyLabel::AccountNumber,
        "email" => PrivacyLabel::Email,
        "phone" => PrivacyLabel::Phone,
        "person" => PrivacyLabel::Person,
        "address" => PrivacyLabel::Address,
        "date" => PrivacyLabel::Date,
        "url" => PrivacyLabel::Url,
        other => panic!("fixture 含未知 truth.label {other:?};请同步 PrivacyLabel"),
    }
}

/// 把 (kind, span, ...) 列表收敛到 (PrivacyLabel, span);未识别 kind 丢弃(eprintln 提示)。
fn predictions_from_findings(findings: &[Finding]) -> Vec<(PrivacyLabel, (usize, usize))> {
    findings
        .iter()
        .filter_map(|f| PrivacyLabel::from_kind(f.kind).map(|l| (l, f.span)))
        .collect()
}

/// 单组对全部样本评估,产 per-label TP/FP/FN + latency_ms,可选填 confusion matrix。
/// 每个样本只跑一次 `predict`(OrtEngine 推理 ~400ms × 20 = 8s,避免重复触发)。
fn evaluate_group(
    name: &str,
    samples: &[Sample],
    mut predict: impl FnMut(&Sample) -> Vec<(PrivacyLabel, (usize, usize))>,
    mut confusion: Option<&mut Vec<Vec<u32>>>,
) -> GroupStats {
    let mut per_label: BTreeMap<PrivacyLabel, (u32, u32, u32)> = BTreeMap::new(); // (tp, fp, fn)
    for label in PrivacyLabel::ALL {
        per_label.insert(label, (0, 0, 0));
    }

    let label_count = PrivacyLabel::ALL.len();
    let none_idx = label_count;
    let label_idx = |l: PrivacyLabel| -> usize {
        PrivacyLabel::ALL
            .iter()
            .position(|x| *x == l)
            .unwrap_or(none_idx)
    };

    let t0 = Instant::now();

    for sample in samples {
        let preds = predict(sample); // 单次推理(若是 OrtEngine 即 ~400ms)
        let truths: Vec<(PrivacyLabel, (usize, usize))> = sample
            .truth
            .iter()
            .map(|t| (parse_truth_label(&t.label), (t.start, t.end)))
            .collect();

        // 贪心匹配:每个 truth 只能被 1 个 pred 消耗(防 1 truth 被多 pred 同时算 TP 双倍)
        let mut pred_used = vec![false; preds.len()];
        let mut truth_matched = vec![false; truths.len()];

        for (ti, &(t_label, t_span)) in truths.iter().enumerate() {
            let found = preds.iter().enumerate().find(|(pi, &(p_label, p_span))| {
                !pred_used[*pi] && p_label == t_label && iou(p_span, t_span) >= IOU_THRESHOLD
            });
            if let Some((pi, &(p_label, _))) = found {
                pred_used[pi] = true;
                truth_matched[ti] = true;
                if let Some(slot) = per_label.get_mut(&t_label) {
                    slot.0 += 1; // TP
                }
                if let Some(cm) = confusion.as_deref_mut() {
                    cm[label_idx(t_label)][label_idx(p_label)] += 1;
                }
            }
        }
        // 未匹配 truth → FN(confusion 列 = none idx 8)
        for (ti, &(t_label, _)) in truths.iter().enumerate() {
            if !truth_matched[ti] {
                if let Some(slot) = per_label.get_mut(&t_label) {
                    slot.2 += 1; // FN
                }
                if let Some(cm) = confusion.as_deref_mut() {
                    cm[label_idx(t_label)][none_idx] += 1;
                }
            }
        }
        // 未使用 pred → FP(confusion 行 = none idx 8)
        for (pi, &(p_label, _)) in preds.iter().enumerate() {
            if !pred_used[pi] {
                if let Some(slot) = per_label.get_mut(&p_label) {
                    slot.1 += 1; // FP
                }
                if let Some(cm) = confusion.as_deref_mut() {
                    cm[none_idx][label_idx(p_label)] += 1;
                }
            }
        }
    }

    let latency_ms = t0.elapsed().as_secs_f64() * 1000.0;

    // 聚合 per-label 指标
    let mut metrics: BTreeMap<String, LabelMetrics> = BTreeMap::new();
    let mut total_tp = 0u32;
    let mut total_fp = 0u32;
    let mut total_fn = 0u32;
    for (label, (tp, fp, fn_)) in &per_label {
        let p = if tp + fp == 0 {
            0.0
        } else {
            *tp as f64 / (*tp + *fp) as f64
        };
        let r = if tp + fn_ == 0 {
            0.0
        } else {
            *tp as f64 / (*tp + *fn_) as f64
        };
        let f1 = if p + r == 0.0 {
            0.0
        } else {
            2.0 * p * r / (p + r)
        };
        metrics.insert(
            label.as_str().to_string(),
            LabelMetrics {
                precision: p,
                recall: r,
                f1,
                tp: *tp,
                fp: *fp,
                fn_: *fn_,
            },
        );
        total_tp += tp;
        total_fp += fp;
        total_fn += fn_;
    }

    let p = if total_tp + total_fp == 0 {
        0.0
    } else {
        total_tp as f64 / (total_tp + total_fp) as f64
    };
    let r = if total_tp + total_fn == 0 {
        0.0
    } else {
        total_tp as f64 / (total_tp + total_fn) as f64
    };
    let f1 = if p + r == 0.0 {
        0.0
    } else {
        2.0 * p * r / (p + r)
    };
    let totals = LabelMetrics {
        precision: p,
        recall: r,
        f1,
        tp: total_tp,
        fp: total_fp,
        fn_: total_fn,
    };

    eprintln!(
        "[{name}] precision={:.3} recall={:.3} f1={:.3} (TP={} FP={} FN={}) latency={:.1}ms",
        totals.precision, totals.recall, totals.f1, totals.tp, totals.fp, totals.fn_, latency_ms
    );

    GroupStats {
        per_label: metrics,
        totals,
        latency_ms,
    }
}

// ─────────────────────────── main(三层 gate + 三组运行 + 输出)

fn main() {
    // 第三层 gate:运行时 env opt-in(默认不跑,避免无模型环境 cold-start 7s 浪费)
    if std::env::var("VIGIL_RUN_ORT_BENCH").as_deref() != Ok("1") {
        eprintln!("skip: VIGIL_RUN_ORT_BENCH != 1; export VIGIL_RUN_ORT_BENCH=1 to run");
        return;
    }

    // OrtEngine 加载失败 → graceful skip(模型未分发场景常见,符合 ADR 0012 side-car 设计)
    let engine = match OrtEngine::from_env() {
        Ok(e) => e,
        Err(e) => {
            eprintln!("skip: OrtEngine::from_env failed (model not distributed?): {e:?}");
            return;
        }
    };

    let samples = load_samples();
    eprintln!(
        "=== Privacy Filter precision/recall bench (N={}) ===",
        samples.len()
    );
    eprintln!("IOU_THRESHOLD = {IOU_THRESHOLD}\n");

    // 8 类 + 1 none 行 = 9x9 confusion matrix
    let label_index: Vec<String> = PrivacyLabel::ALL
        .iter()
        .map(|l| l.as_str().to_string())
        .chain(std::iter::once("(none)".to_string()))
        .collect();
    let mut confusion = vec![vec![0u32; label_index.len()]; label_index.len()];

    let mut per_group: BTreeMap<String, GroupStats> = BTreeMap::new();

    // 组 1: hard_only —— scan_text_with_engine + NoopEngine
    let stats_hard = evaluate_group(
        "hard_only",
        &samples,
        |sample| {
            let r = scan_text_with_engine(&sample.text, &NoopEngine)
                .unwrap_or_else(|e| panic!("hard_only sample {} scan failed: {e:?}", sample.id));
            predictions_from_findings(&r.findings)
        },
        None,
    );
    per_group.insert("hard_only".to_string(), stats_hard);

    // 组 2: model_only —— OrtEngine.infer 直拿(跳过 merge,看模型原始输出)
    let stats_model = evaluate_group(
        "model_only",
        &samples,
        |sample| {
            let findings: Vec<Finding> = match engine.infer(&sample.text) {
                Ok(v) => v,
                Err(EngineError::ModelNotFound { dir }) => {
                    panic!("model_only sample {}: ModelNotFound dir={dir}", sample.id)
                }
                Err(e) => panic!("model_only sample {} infer failed: {e:?}", sample.id),
            };
            predictions_from_findings(&findings)
        },
        None,
    );
    per_group.insert("model_only".to_string(), stats_model);

    // 组 3: merge —— scan_text_with_engine + OrtEngine(完整 D1/D3/D4/D5);填 confusion matrix
    let stats_merge = evaluate_group(
        "merge",
        &samples,
        |sample| {
            let r = scan_text_with_engine(&sample.text, &engine)
                .unwrap_or_else(|e| panic!("merge sample {} scan failed: {e:?}", sample.id));
            predictions_from_findings(&r.findings)
        },
        Some(&mut confusion),
    );
    per_group.insert("merge".to_string(), stats_merge);

    // ─── v0.6 P2:per-category merge bench(跨语言对比)───
    // 对 fixture 按 category 分组(en-soft / multilang-soft / hard / clean);
    // 每 category 单独跑 merge 引擎评估,产 per-category GroupStats。
    // 价值:能直接读 multilang-soft category 的 precision/recall,与 en-soft 同口径对比,
    // 让 v0.7 多语言模型评估 sprint 有量化基线。
    //
    // 注意:OrtEngine.infer 在每 category 重新跑(总耗时 ≈ 单组 N × ~400ms × M categories;
    // 32 sample / 4 category = 大约多 8s × 4 = 32s 额外开销,可接受)。
    let mut per_category_merge: BTreeMap<String, GroupStats> = BTreeMap::new();
    let mut category_sample_counts: BTreeMap<String, usize> = BTreeMap::new();
    let mut by_cat: BTreeMap<String, Vec<Sample>> = BTreeMap::new();
    for sample in &samples {
        // 重建 Sample(Sample 无 Clone derive,手动构造小副本)
        by_cat
            .entry(sample.category.clone())
            .or_default()
            .push(Sample {
                id: sample.id.clone(),
                text: sample.text.clone(),
                truth: sample
                    .truth
                    .iter()
                    .map(|t| TruthSpan {
                        label: t.label.clone(),
                        start: t.start,
                        end: t.end,
                    })
                    .collect(),
                category: sample.category.clone(),
            });
    }
    for (cat, sub_samples) in by_cat {
        category_sample_counts.insert(cat.clone(), sub_samples.len());
        let group_name = format!("merge[{cat}]");
        let stats = evaluate_group(
            &group_name,
            &sub_samples,
            |sample| {
                let r = scan_text_with_engine(&sample.text, &engine).unwrap_or_else(|e| {
                    panic!("merge[{cat}] sample {} scan failed: {e:?}", sample.id)
                });
                predictions_from_findings(&r.findings)
            },
            None, // confusion matrix 已在全局 merge 组填,不重复
        );
        per_category_merge.insert(cat, stats);
    }

    // 组装 JSON 报告
    let ts = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let report = BenchReport {
        ts,
        sample_count: samples.len(),
        iou_threshold: IOU_THRESHOLD,
        per_group,
        per_category_merge,
        category_sample_counts,
        confusion_matrix: confusion,
        label_index,
    };
    let json = serde_json::to_string_pretty(&report)
        .unwrap_or_else(|e| panic!("serialize bench report: {e}"));

    // 输出路径选择:VIGIL_BENCH_OUT 设 → 写文件,未设 → stdout
    if let Ok(out_path) = std::env::var("VIGIL_BENCH_OUT") {
        // 创建父目录(dist/)
        if let Some(parent) = std::path::Path::new(&out_path).parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        std::fs::write(&out_path, &json)
            .unwrap_or_else(|e| panic!("write bench report to {out_path}: {e}"));
        eprintln!("\nbench report written to {out_path}");
    } else {
        // stdout JSON 便于 `| jq .`
        println!("{json}");
    }
}
