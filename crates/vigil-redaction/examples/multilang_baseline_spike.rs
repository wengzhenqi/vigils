//! v0.10 Sprint 5 Phase 4 spike — multilang baseline runner(沿 r1_ensemble_e2e.rs 范式)。
//!
//! **目的**:Day 3 跑当前 3-engine ensemble 在 multilang_baseline_v1 fixture 上的真实
//! recall/precision/F1/latency,**数据驱动**决定 Phase 4 commit/pivot/park。
//!
//! **运行**(远程 box,沿 v0.9 P1.3 范式):
//! ```bash
//! export ORT_DYLIB_PATH=$HOME/ort/onnxruntime-linux-x64-1.24.4/lib/libonnxruntime.so.1.24.4
//! export LD_LIBRARY_PATH=$HOME/ort/onnxruntime-linux-x64-1.24.4/lib:$LD_LIBRARY_PATH
//! export VIGIL_ML_OPENAI_DIR=/var/vigil/models/openai-pf/v1
//! export VIGIL_ML_XLMR_DIR=$HOME/vigil-spike-p3/model
//! export VIGIL_ML_YONIGO_DIR=$HOME/vigil-spike-p3/model-yonigo
//! export VIGIL_ML_FIXTURE_ROOT=$VIGIL_ROOT/crates/vigil-redaction/fixtures/multilang_baseline_v1
//! export VIGIL_ML_BENCH_OUT=$VIGIL_ROOT/docs/operations/v0.10-sprint5-spike/baseline-day3-results.json
//! cargo run --example multilang_baseline_spike --features ort --release
//! ```
//!
//! **skip-if-empty fallback**:fixture root 不存或 0 sample 即 graceful skip 退出 0
//! (Day 2 Phase B 完成前避免 CI 误报);0 engine env 设置则 panic(显式失败,提醒
//! 设置 VIGIL_ML_*_DIR)。
//!
//! **schema**:输出 `baseline-day3-results.json` 矩阵 by (engine_id × lang × label)
//! schema_version `v0.10.sprint5.spike.day3.1`。

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Instant;

use serde::Deserialize;
use serde_json::json;
use vigil_redaction::{
    model_descriptor::{
        ModelDescriptor, OpenAIPrivacyFilterDescriptor, XlmrPiiDescriptor, YonigoPiiDescriptor,
    },
    scan_text_with_engine_with_lang, EnsembleEngine, FindingSource, OrtEngine, PrivacyLabel,
    RedactionEngine,
};

/// v0.10 Sprint 5 multilang fixture v1 sample schema(对齐 fixture-schema.md § 2)。
/// `#[allow(dead_code)]`:source/metadata 仅 deserialize 校验,不进 metric 计算。
#[derive(Deserialize, Debug)]
#[allow(dead_code)]
struct MultilangSample {
    id: String,
    text: String,
    lang: String, // zh / ja / ru / mixed
    #[serde(default)]
    lang_review_status: String, // human_curated | heuristic_draft | pending_review
    #[serde(default = "default_eval_role")]
    eval_role: String, // spike_baseline | heldout_human_eval
    expected_findings: Vec<ExpectedFinding>,
    #[serde(default)]
    source: String,
    #[serde(default)]
    metadata: serde_json::Value,
}

fn default_eval_role() -> String {
    "spike_baseline".to_string()
}

/// `#[allow(dead_code)]`:extracted_text/redact_action 仅 deserialize 守门(loader test
/// 已断言 text[start..end] 与 extracted_text 一致),example 主路径只用 label/start/end/risk_tier。
#[derive(Deserialize, Debug)]
#[allow(dead_code)]
struct ExpectedFinding {
    label: String,
    start: usize,
    end: usize,
    #[serde(default)]
    extracted_text: String,
    #[serde(default)]
    risk_tier: String, // high | med | low
    #[serde(default)]
    redact_action: String,
}

fn parse_label(s: &str) -> Option<PrivacyLabel> {
    match s {
        "secret" => Some(PrivacyLabel::Secret),
        "account_number" => Some(PrivacyLabel::AccountNumber),
        "email" => Some(PrivacyLabel::Email),
        "phone" => Some(PrivacyLabel::Phone),
        "person" => Some(PrivacyLabel::Person),
        "address" => Some(PrivacyLabel::Address),
        "date" => Some(PrivacyLabel::Date),
        "url" => Some(PrivacyLabel::Url),
        _ => None,
    }
}

fn iou(a: (usize, usize), b: (usize, usize)) -> f64 {
    let s = a.0.max(b.0);
    let e = a.1.min(b.1);
    if s >= e {
        return 0.0;
    }
    let inter = (e - s) as f64;
    let union = (a.1.max(b.1) - a.0.min(b.0)) as f64;
    if union <= 0.0 {
        0.0
    } else {
        inter / union
    }
}

fn risk_weight(tier: &str) -> u32 {
    match tier {
        "high" => 3,
        "med" => 2,
        "low" => 1,
        _ => 1,
    }
}

/// 复用 r1_ensemble_e2e.rs 的 build_engine_or_skip 模式 — engine 与 model_id 1:1。
fn build_engine_or_skip(
    env_var: &str,
    descriptor: Box<dyn ModelDescriptor>,
) -> Option<(Arc<dyn RedactionEngine>, String)> {
    let dir = match std::env::var(env_var) {
        Ok(d) => PathBuf::from(d),
        Err(_) => {
            eprintln!("[skip] {env_var} 未设;engine 不进 ensemble");
            return None;
        }
    };
    if !dir.exists() {
        eprintln!("[skip] {env_var}={} 不存在", dir.display());
        return None;
    }
    let model_id = descriptor.model_id().to_string();
    eprintln!("[load] {model_id} ({})", dir.display());
    let t0 = Instant::now();
    match OrtEngine::from_dir_with_descriptor(&dir, descriptor) {
        Ok(e) => {
            eprintln!("  load wall: {:.0}ms", t0.elapsed().as_secs_f64() * 1000.0);
            Some((Arc::new(e), model_id))
        }
        Err(err) => {
            eprintln!("[skip] load 失败: {err:?}");
            None
        }
    }
}

/// 递归遍历 fixture root,读所有 *.json 转 MultilangSample(skip-if-empty fallback)。
fn load_multilang_fixtures(root: &std::path::Path) -> Vec<MultilangSample> {
    if !root.exists() {
        eprintln!(
            "[skip-if-empty] fixture root 不存:{} (Day 2 Phase B 未完成?graceful exit)",
            root.display()
        );
        return Vec::new();
    }
    let mut samples = Vec::new();
    let buckets = ["zh", "ja", "ru", "mixed_script", "negative_control"];
    for bucket in buckets {
        let bucket_dir = root.join(bucket);
        if !bucket_dir.exists() {
            eprintln!("[skip] bucket {} 不存(Day 2 未填充?)", bucket_dir.display());
            continue;
        }
        let entries = match std::fs::read_dir(&bucket_dir) {
            Ok(e) => e,
            Err(e) => {
                eprintln!("[skip] read_dir {} 失败: {e:?}", bucket_dir.display());
                continue;
            }
        };
        let mut bucket_count = 0;
        for entry in entries.flatten() {
            let path = entry.path();
            if path.extension().and_then(|s| s.to_str()) != Some("json") {
                continue;
            }
            match std::fs::read_to_string(&path).map(|raw| serde_json::from_str(&raw)) {
                Ok(Ok(s)) => {
                    samples.push(s);
                    bucket_count += 1;
                }
                Ok(Err(e)) => eprintln!("[warn] parse {} failed: {e:?}", path.display()),
                Err(e) => eprintln!("[warn] read {} failed: {e:?}", path.display()),
            }
        }
        eprintln!("[fixture] bucket {bucket}: {bucket_count} samples");
    }
    samples
}

fn main() {
    eprintln!("=== v0.10 Sprint 5 Phase 4 multilang baseline spike ===\n");

    // ─────────────────────────── 1. Load fixture ───────────────────────────
    let root_str = std::env::var("VIGIL_ML_FIXTURE_ROOT")
        .expect("VIGIL_ML_FIXTURE_ROOT 必设(指向 multilang_baseline_v1/ 目录)");
    let fixture_root = PathBuf::from(&root_str);
    let all_samples = load_multilang_fixtures(&fixture_root);
    if all_samples.is_empty() {
        eprintln!("[skip-if-empty] 0 samples loaded — Day 2 Phase B 未完成?graceful exit 0");
        std::process::exit(0);
    }

    // 按 eval_role 过滤:Day 3 baseline 仅测 spike_baseline,heldout 留 Day 7 verdict
    let samples: Vec<&MultilangSample> = all_samples
        .iter()
        .filter(|s| s.eval_role == "spike_baseline")
        .collect();
    eprintln!(
        "[fixture] total={} spike_baseline={} heldout={}",
        all_samples.len(),
        samples.len(),
        all_samples
            .iter()
            .filter(|s| s.eval_role == "heldout_human_eval")
            .count()
    );

    // ─── Mode A/B detection(Codex R2 ACCEPT 后 R1-CONDITIONAL fix)─────
    // Mode A(Verdict-Bearing):全 800 sample lang_review_status='human_curated';
    //   eligible_for_day7_verdict=true;若 VIGIL_ML_REQUIRE_MODE_A=1 → fail-fast on 任一 ≠
    // Mode B(Non-Verdict):任一 sample ≠ 'human_curated';eligible_for_day7_verdict=false;
    //   output 自动 mark non_verdict + loud-mark caveat 字段(避免手工 JSON edit,Codex § 2)
    let non_human_curated = samples
        .iter()
        .filter(|s| s.lang_review_status != "human_curated")
        .count();
    let mut lang_review_status_distribution: BTreeMap<String, u32> = BTreeMap::new();
    for s in &samples {
        *lang_review_status_distribution
            .entry(s.lang_review_status.clone())
            .or_insert(0) += 1;
    }
    let require_mode_a = std::env::var("VIGIL_ML_REQUIRE_MODE_A").as_deref() == Ok("1");
    let mode_a = non_human_curated == 0;

    if require_mode_a && !mode_a {
        eprintln!(
            "[FATAL] VIGIL_ML_REQUIRE_MODE_A=1 但 {} samples lang_review_status ≠ 'human_curated'.\n\
             Mode A(Verdict-Bearing)要求 fixture human sign-off 完成。\n\
             解决:human flip 'heuristic_draft' → 'human_curated' 后重跑;\n\
             或去 VIGIL_ML_REQUIRE_MODE_A 走 Mode B(non-verdict reference run)。\n\
             详见 docs/operations/v0.10-sprint5-spike/pre-day3-gate.md",
            non_human_curated
        );
        std::process::exit(1);
    }

    if mode_a {
        eprintln!(
            "[mode] Mode A — Verdict-Bearing(全 800 sample human_curated;eligible Day 7 verdict)"
        );
    } else {
        eprintln!(
            "[mode] Mode B — Non-Verdict(loud-mark)— {} samples ≠ 'human_curated';\
             output 标 verdict_mode='non_verdict' + eligible_for_day7_verdict=false;\
             不进 Day 7 verdict 量化判定",
            non_human_curated
        );
    }

    // ─────────────────────────── 2. Build ensemble ─────────────────────────
    let mut engines: Vec<Arc<dyn RedactionEngine>> = Vec::new();
    let mut model_ids: Vec<String> = Vec::new();
    for (env_var, descriptor) in [
        (
            "VIGIL_ML_OPENAI_DIR",
            Box::new(OpenAIPrivacyFilterDescriptor) as Box<dyn ModelDescriptor>,
        ),
        (
            "VIGIL_ML_XLMR_DIR",
            Box::new(XlmrPiiDescriptor::default()) as Box<dyn ModelDescriptor>,
        ),
        (
            "VIGIL_ML_YONIGO_DIR",
            Box::new(YonigoPiiDescriptor) as Box<dyn ModelDescriptor>,
        ),
    ] {
        if let Some((engine, model_id)) = build_engine_or_skip(env_var, descriptor) {
            engines.push(engine);
            model_ids.push(model_id);
        }
    }
    if engines.is_empty() {
        panic!("0 engines loaded — set at least one VIGIL_ML_*_DIR env var");
    }
    eprintln!("[ensemble] {} engines loaded\n", engines.len());

    let ensemble = EnsembleEngine::new(engines).with_model_ids(model_ids.clone());

    // warmup
    eprintln!("[warmup] 3x dummy infer...");
    let warmup_start = Instant::now();
    for _ in 0..3 {
        let _ = ensemble.infer("a");
    }
    let warmup_ms = warmup_start.elapsed().as_secs_f64() * 1000.0;

    // ─────────────────────────── 3. Run baseline ───────────────────────────
    // 矩阵 by (lang, label):TP / FP / FN + risk-weighted FN(high × 3 / med × 2 / low × 1)
    type LabelStats = BTreeMap<PrivacyLabel, (u32, u32, u32, u32)>; // tp, fp, fn, risk_weighted_fn
    let mut per_lang: BTreeMap<String, LabelStats> = BTreeMap::new();
    let mut latencies_ms = Vec::with_capacity(samples.len());
    let mut total_tp = 0u32;
    let mut total_fp = 0u32;
    let mut total_fn = 0u32;
    let mut total_high_risk_fn = 0u32;

    eprintln!(
        "[bench] running {} samples through ensemble (lang-aware)...",
        samples.len()
    );
    let bench_start = Instant::now();

    for sample in &samples {
        let lang = if sample.lang.is_empty() {
            None
        } else {
            Some(sample.lang.as_str())
        };

        let t0 = Instant::now();
        let result = scan_text_with_engine_with_lang(&sample.text, &ensemble, lang)
            .unwrap_or_else(|e| panic!("sample {}: scan failed {e:?}", sample.id));
        let dt_ms = t0.elapsed().as_secs_f64() * 1000.0;
        latencies_ms.push(dt_ms);

        // Predictions(filter to canonical 8-label)
        let preds: Vec<(PrivacyLabel, (usize, usize), &str)> = result
            .findings
            .iter()
            .filter_map(|f| {
                PrivacyLabel::from_kind(f.kind).map(|l| {
                    let src = match f.source {
                        FindingSource::Hard => "hard",
                        FindingSource::Model => "model",
                        // P0 元指令软信号不流经本 spike 路径,仅兜底标注。
                        FindingSource::MetaInstruction => "meta-instruction",
                    };
                    (l, f.span, src)
                })
            })
            .collect();

        // Truths
        let truths: Vec<(PrivacyLabel, (usize, usize), &str)> = sample
            .expected_findings
            .iter()
            .filter_map(|t| {
                parse_label(&t.label).map(|l| (l, (t.start, t.end), t.risk_tier.as_str()))
            })
            .collect();

        // Greedy match IoU >= 0.5
        let mut pred_used = vec![false; preds.len()];
        let mut truth_matched = vec![false; truths.len()];
        for (ti, &(t_label, t_span, _)) in truths.iter().enumerate() {
            for (pi, &(p_label, p_span, _)) in preds.iter().enumerate() {
                if pred_used[pi] {
                    continue;
                }
                if p_label == t_label && iou(p_span, t_span) >= 0.5 {
                    pred_used[pi] = true;
                    truth_matched[ti] = true;
                    let bucket = per_lang.entry(sample.lang.clone()).or_default();
                    let stats = bucket.entry(p_label).or_insert((0, 0, 0, 0));
                    stats.0 += 1;
                    total_tp += 1;
                    break;
                }
            }
        }
        for (ti, matched) in truth_matched.iter().enumerate() {
            if !matched {
                let (t_label, _, t_risk) = truths[ti];
                let bucket = per_lang.entry(sample.lang.clone()).or_default();
                let stats = bucket.entry(t_label).or_insert((0, 0, 0, 0));
                stats.2 += 1;
                stats.3 += risk_weight(t_risk);
                total_fn += 1;
                if t_risk == "high" {
                    total_high_risk_fn += 1;
                }
            }
        }
        for (pi, used) in pred_used.iter().enumerate() {
            if !used {
                let (p_label, _, _) = preds[pi];
                let bucket = per_lang.entry(sample.lang.clone()).or_default();
                let stats = bucket.entry(p_label).or_insert((0, 0, 0, 0));
                stats.1 += 1;
                total_fp += 1;
            }
        }
    }

    let bench_total_ms = bench_start.elapsed().as_secs_f64() * 1000.0;
    let total_recall = if total_tp + total_fn > 0 {
        total_tp as f64 / (total_tp + total_fn) as f64
    } else {
        0.0
    };
    let total_precision = if total_tp + total_fp > 0 {
        total_tp as f64 / (total_tp + total_fp) as f64
    } else {
        0.0
    };
    let f1 = if total_recall + total_precision > 0.0 {
        2.0 * total_recall * total_precision / (total_recall + total_precision)
    } else {
        0.0
    };
    latencies_ms.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
    let p50 = latencies_ms[latencies_ms.len() / 2];
    let p95 =
        latencies_ms[((latencies_ms.len() as f64 * 0.95) as usize).min(latencies_ms.len() - 1)];
    let p99 =
        latencies_ms[((latencies_ms.len() as f64 * 0.99) as usize).min(latencies_ms.len() - 1)];

    // ─────────────────────────── 4. Console summary ────────────────────────
    eprintln!("\n=== baseline summary ===");
    eprintln!(
        "samples: {}  bench wall: {:.0}ms  warmup: {:.0}ms",
        samples.len(),
        bench_total_ms,
        warmup_ms
    );
    eprintln!(
        "TP={} FP={} FN={} (high-risk FN={}) recall={:.3} precision={:.3} F1={:.3}",
        total_tp, total_fp, total_fn, total_high_risk_fn, total_recall, total_precision, f1
    );
    eprintln!("latency p50={:.1}ms p95={:.1}ms p99={:.1}ms", p50, p95, p99);
    for (lang, stats) in &per_lang {
        let lang_tp: u32 = stats.values().map(|s| s.0).sum();
        let lang_fp: u32 = stats.values().map(|s| s.1).sum();
        let lang_fn: u32 = stats.values().map(|s| s.2).sum();
        let r = if lang_tp + lang_fn > 0 {
            lang_tp as f64 / (lang_tp + lang_fn) as f64
        } else {
            0.0
        };
        eprintln!(
            "  [{}] TP={} FP={} FN={} recall={:.3}",
            lang, lang_tp, lang_fp, lang_fn, r
        );
    }

    // ─────────────────────────── 5. JSON output ────────────────────────────
    if let Ok(out_path) = std::env::var("VIGIL_ML_BENCH_OUT") {
        let mut per_lang_json = serde_json::Map::new();
        for (lang, stats) in &per_lang {
            let mut label_map = serde_json::Map::new();
            for (label, (tp, fp, fn_, weighted_fn)) in stats {
                label_map.insert(
                    label.as_str().to_string(),
                    json!({
                        "tp": tp,
                        "fp": fp,
                        "fn": fn_,
                        "risk_weighted_fn": weighted_fn,
                    }),
                );
            }
            per_lang_json.insert(lang.clone(), serde_json::Value::Object(label_map));
        }

        // Mode A/B fields(Codex R1-CONDITIONAL fix:loud-mark + 自动 emit,避免手工 JSON edit)
        let verdict_mode = if mode_a {
            "verdict_bearing"
        } else {
            "non_verdict"
        };
        let eligible_for_day7_verdict = mode_a;
        let human_gate_status = if mode_a { "passed" } else { "pending" };
        let baseline_caveat = if mode_a {
            String::new()
        } else {
            format!(
                "Pre-human-review reference run; not eligible for Day 7 verdict gate. \
                 {} samples lang_review_status ≠ 'human_curated'.",
                non_human_curated
            )
        };
        // env-driven commit hashes(caller 在 cargo run 前 export VIGIL_ML_FIXTURE_COMMIT/RUNNER_COMMIT;
        // 避免 example.rs 跑 git command 引依赖)
        let fixture_commit =
            std::env::var("VIGIL_ML_FIXTURE_COMMIT").unwrap_or_else(|_| "unset".to_string());
        let runner_commit =
            std::env::var("VIGIL_ML_RUNNER_COMMIT").unwrap_or_else(|_| "unset".to_string());
        // eval_role distribution(audit 用)
        let mut eval_role_dist: BTreeMap<String, u32> = BTreeMap::new();
        for s in &all_samples {
            *eval_role_dist.entry(s.eval_role.clone()).or_insert(0) += 1;
        }

        let report = json!({
            "schema_version": "v0.10.sprint5.spike.day3.1",
            "verdict_mode": verdict_mode,
            "eligible_for_day7_verdict": eligible_for_day7_verdict,
            "human_gate_status": human_gate_status,
            "baseline_caveat": baseline_caveat,
            "fixture_commit": fixture_commit,
            "runner_commit": runner_commit,
            "lang_review_status_distribution": lang_review_status_distribution,
            "eval_role_distribution": eval_role_dist,
            "ensemble": format!("{} engines + Hard rules", ensemble.engine_count()),
            "model_ids": &model_ids,
            "fixture_root": &root_str,
            "fixture_count_total": all_samples.len(),
            "fixture_count_spike_baseline": samples.len(),
            "fixture_count_heldout": all_samples.len() - samples.len(),
            "non_human_curated_count": non_human_curated,
            "totals": {
                "tp": total_tp,
                "fp": total_fp,
                "fn": total_fn,
                "high_risk_fn": total_high_risk_fn,
                "recall": total_recall,
                "precision": total_precision,
                "f1": f1,
            },
            "latency_ms": {
                "p50": p50,
                "p95": p95,
                "p99": p99,
                "warmup": warmup_ms,
                "bench_wall": bench_total_ms,
            },
            "per_lang": per_lang_json,
            "verdict_gate_reference": {
                "commit_phase4_if": "candidate -30% high-risk FN OR target-lang recall >= 0.97 AND <= +10% FP AND warm p95 <= ADR 0016 SLO",
                "park_phase4_if": "xlmr-pii-v1 high-risk recall >= 0.95 / 与 EN diff <= 5pp"
            }
        });

        std::fs::write(&out_path, serde_json::to_string_pretty(&report).unwrap())
            .unwrap_or_else(|e| panic!("write {out_path}: {e}"));
        eprintln!("[bench-out] wrote {out_path}");
    } else {
        eprintln!("[bench-out] VIGIL_ML_BENCH_OUT 未设;不写 JSON,仅 console");
    }
}
