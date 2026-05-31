//! v0.7-α3 R1(E6a)— 远程三引擎 ensemble e2e bench(对齐 Python spike-3)。
//!
//! **运行**(远程 vigils.ai):
//! ```bash
//! export ORT_DYLIB_PATH=$HOME/ort/onnxruntime-linux-x64-1.24.4/lib/libonnxruntime.so.1.24.4
//! export LD_LIBRARY_PATH=$HOME/ort/onnxruntime-linux-x64-1.24.4/lib:$LD_LIBRARY_PATH
//! export VIGIL_R1_OPENAI_DIR=/var/vigil/models/openai-pf/v1   # 现 v0.6 模型(可选)
//! export VIGIL_R1_XLMR_DIR=$HOME/vigil-spike-p3/model         # spike-1 下载
//! export VIGIL_R1_YONIGO_DIR=$HOME/vigil-spike-p3/model-yonigo # spike-2 下载
//! export VIGIL_R1_FIXTURE=$HOME/vigil-spike-p3/labeled_samples.json
//! cargo run --example r1_ensemble_e2e --features ort --release
//! ```
//!
//! **验收**:Rust ensemble 输出与 Python spike-3 同 fixture 同算法,EU recall
//! 应在 ±0.05 内对齐 0.895(算法已在 mock-engine 单测验证;真模型推理对齐
//! 验证 ORT 1.24.4 + canonical_mapping 路径)。

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Instant;

use serde::Deserialize;
use serde_json::json;
use vigil_redaction::{
    model_descriptor::{
        ModelDescriptor, OpenAIPrivacyFilterDescriptor, XlmrPiiDescriptor, YonigoPiiDescriptor,
    },
    scan_text_with_engine, scan_text_with_engine_with_lang, EnsembleEngine, Finding, FindingSource,
    OrtEngine, PrivacyLabel, RedactionEngine,
};

#[derive(Deserialize, Debug)]
struct Sample {
    id: String,
    text: String,
    truth: Vec<TruthSpan>,
    category: String,
    /// v0.8 Sprint 2 P1.0+ 起 fixture 必含;backward-compat 默认空串(预 P1.0+ fixture)。
    #[serde(default)]
    lang: String,
}

#[derive(Deserialize, Debug)]
struct TruthSpan {
    label: String,
    start: usize,
    end: usize,
}

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
        other => panic!("unknown truth label: {other}"),
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

fn is_european_lang(text: &str) -> bool {
    for ch in text.chars() {
        let cp = ch as u32;
        if (0x4E00..=0x9FFF).contains(&cp)
            || (0x3040..=0x309F).contains(&cp)
            || (0x30A0..=0x30FF).contains(&cp)
            || (0xAC00..=0xD7AF).contains(&cp)
            || (0x0400..=0x04FF).contains(&cp)
            || (0x0600..=0x06FF).contains(&cp)
        {
            return false;
        }
    }
    true
}

/// **R1 MUST-FIX(Codex 019deb45)**:返 `(engine, model_id)` 对,确保 load 成功
/// 才记 model_id;model_id 与 engines vec 严格 1:1 对齐。否则 path 存在但
/// `OrtEngine::from_dir_with_descriptor` 失败时,model_ids 旧实现会全 fallback
/// `unknown-N`,丢真 attribution。
fn build_engine_or_skip(
    env_var: &str,
    descriptor: Box<dyn ModelDescriptor>,
) -> Option<(Arc<dyn RedactionEngine>, String)> {
    let dir = match std::env::var(env_var) {
        Ok(d) => PathBuf::from(d),
        Err(_) => {
            eprintln!("[skip] {env_var} not set; engine omitted from ensemble");
            return None;
        }
    };
    if !dir.exists() {
        eprintln!("[skip] {env_var}={} does not exist", dir.display());
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
            eprintln!("[skip] failed to load: {err:?}");
            None
        }
    }
}

fn main() {
    eprintln!("=== R1 ensemble e2e bench(Rust 端对齐 Python spike-3)===\n");

    let fixture_path = std::env::var("VIGIL_R1_FIXTURE")
        .expect("VIGIL_R1_FIXTURE 必设(指向 labeled_samples.json)");
    let raw = std::fs::read_to_string(&fixture_path)
        .unwrap_or_else(|e| panic!("read {fixture_path}: {e}"));
    let samples: Vec<Sample> =
        serde_json::from_str(&raw).unwrap_or_else(|e| panic!("parse fixture: {e}"));
    eprintln!("[fixture] N={} samples", samples.len());

    // 三引擎构造(env 缺失即 skip,组建实际可用 ensemble)。
    // **R1 MUST-FIX(Codex 019deb45)**:engines 与 model_ids 严格 1:1 对齐,
    // 由 build_engine_or_skip 返 (engine, model_id) 对统一 push。
    // 旧实现 model_ids 是从 env 路径存在重建的 — 若 path 存在但 from_dir_with_descriptor
    // 失败(如 ONNX 文件损坏),会丢真 attribution。
    let mut engines: Vec<Arc<dyn RedactionEngine>> = Vec::new();
    let mut model_ids: Vec<String> = Vec::new();
    for (env_var, descriptor) in [
        (
            "VIGIL_R1_OPENAI_DIR",
            Box::new(OpenAIPrivacyFilterDescriptor) as Box<dyn ModelDescriptor>,
        ),
        (
            "VIGIL_R1_XLMR_DIR",
            Box::new(XlmrPiiDescriptor::default()) as Box<dyn ModelDescriptor>,
        ),
        (
            "VIGIL_R1_YONIGO_DIR",
            Box::new(YonigoPiiDescriptor) as Box<dyn ModelDescriptor>,
        ),
    ] {
        if let Some((engine, model_id)) = build_engine_or_skip(env_var, descriptor) {
            engines.push(engine);
            model_ids.push(model_id);
        }
    }
    if engines.is_empty() {
        panic!("0 engines loaded — set at least one VIGIL_R1_*_DIR env var");
    }
    debug_assert_eq!(
        engines.len(),
        model_ids.len(),
        "engines / model_ids 必须 1:1 对齐"
    );
    eprintln!("[ensemble] {} engines loaded\n", engines.len());

    let ensemble = EnsembleEngine::new(engines).with_model_ids(model_ids.clone());
    // v0.7-α5 A step:env-driven dual_confirm(comma-separated canonical labels)
    // 示例:VIGIL_R1_DUAL_CONFIRM=address,date,account_number
    let ensemble = if let Ok(s) = std::env::var("VIGIL_R1_DUAL_CONFIRM") {
        let labels: Vec<PrivacyLabel> = s
            .split(',')
            .filter_map(|t| PrivacyLabel::from_kind(t.trim()))
            .collect();
        if !labels.is_empty() {
            eprintln!("[dual_confirm] enabled for: {:?}", labels);
            ensemble.with_dual_confirm(labels)
        } else {
            ensemble
        }
    } else {
        ensemble
    };

    // warmup(eager preload all engines)
    eprintln!("[warmup] running 3x dummy infer...");
    for _ in 0..3 {
        let _ = ensemble.infer("a");
    }

    // 跑 fixture(走 scan_text_with_engine 完整路径,Hard + Model union 都生效)
    eprintln!("[bench] running fixture through scan_text_with_engine + EnsembleEngine...");
    let mut total_tp = 0u32;
    let mut total_fp = 0u32;
    let mut total_fn_ = 0u32;
    let mut eu_tp = 0u32;
    let mut eu_fp = 0u32;
    let mut eu_fn = 0u32;
    let mut latencies_ms = Vec::with_capacity(samples.len());

    // v0.8 NICE — VIGIL_R1_BENCH_OUT 透出 per_sample_diff JSON(供 diagnose_per_label.py 消费)。
    // schema 对齐 v0.7-spike-ensemble.json:per_sample_diff[].preds[].src 字段标
    // FindingSource(hard / model 二态)。per-engine 细分(openai/xlmr/yonigo)需扩
    // EnsembleEngine API,推 Sprint 3 P2.0(dual_confirm 真要时再做)。
    let bench_out_path = std::env::var("VIGIL_R1_BENCH_OUT").ok();
    let collect_per_sample = bench_out_path.is_some();
    let mut per_sample_diff: Vec<serde_json::Value> = Vec::with_capacity(samples.len());

    // **v0.9 Sprint 1 P1.3** — VIGIL_R1_LANG_AWARE=1 启用 lang-aware 路径。
    // 走 scan_text_with_engine_with_lang(text, &ensemble, sample.lang) — engine 内部
    // threshold 应用走 lang-conditional(top 5 候选 1.1 屏蔽)。default(env unset)
    // 等价 v0.8 baseline path(scan_text_with_engine);两路径同一 example 共存,
    // 便于 baseline / lang-aware 同 fixture 同 build 直接对比 EU recall + FP delta。
    let lang_aware = std::env::var("VIGIL_R1_LANG_AWARE").as_deref() == Ok("1");
    if lang_aware {
        eprintln!(
            "[lang-aware] VIGIL_R1_LANG_AWARE=1 启用 — sample.lang 透传 OrtEngine.infer_with_lang"
        );
    }

    for sample in &samples {
        let is_eu = is_european_lang(&sample.text);
        let t0 = Instant::now();
        let result = if lang_aware {
            // P1.3:lang 来自 fixture lang 字段(权威);空串 None(预 P1.0+ 的 sample)
            let lang = if sample.lang.is_empty() {
                None
            } else {
                Some(sample.lang.as_str())
            };
            scan_text_with_engine_with_lang(&sample.text, &ensemble, lang)
                .unwrap_or_else(|e| panic!("sample {}: scan_with_lang failed {e:?}", sample.id))
        } else {
            scan_text_with_engine(&sample.text, &ensemble)
                .unwrap_or_else(|e| panic!("sample {}: scan failed {e:?}", sample.id))
        };
        let dt_ms = t0.elapsed().as_secs_f64() * 1000.0;
        latencies_ms.push(dt_ms);

        // v0.8 Sprint 3 P2.0 — 额外跑 ensemble.infer_with_attribution 拿 model 路径 attribution。
        // BENCH_OUT 模式下需要细分 contributing_engines;legacy 路径(`infer`)沿用 result。
        // 注意:此调用增加 1 次 model inference cost(仅 BENCH_OUT 启用时跑;
        // verdict gate / latency 测量仍以 scan_text_with_engine 为准 — t0 已收 dt_ms)。
        //
        // **v0.10 Sprint 3 — P1.3 R1 NICE 兑付**:attribution 路径接 lang。
        // 当 lang_aware=true,走 infer_with_attribution_with_lang(text, sample.lang)
        // 让 attribution 与主 result 矩阵口径一致(同 lang-conditional threshold);
        // legacy / lang_aware=false 走 infer_with_attribution(等价 lang None)。
        let attribution_map: Vec<(Finding, Vec<String>)> = if collect_per_sample {
            let (model_findings, attrs) = if lang_aware {
                let lang = if sample.lang.is_empty() {
                    None
                } else {
                    Some(sample.lang.as_str())
                };
                ensemble
                    .infer_with_attribution_with_lang(&sample.text, lang)
                    .unwrap_or_else(|e| {
                        panic!("sample {}: attribution_with_lang failed {e:?}", sample.id)
                    })
            } else {
                ensemble
                    .infer_with_attribution(&sample.text)
                    .unwrap_or_else(|e| panic!("sample {}: attribution failed {e:?}", sample.id))
            };
            model_findings
                .into_iter()
                .zip(attrs)
                .map(|(f, a)| (f, a.contributing_engines))
                .collect()
        } else {
            Vec::new()
        };

        // v0.8 NICE — pred src attribution + raw kind
        // FindingSource::Hard → src="hard"
        // FindingSource::Model → 查 attribution_map 同 (kind, span IoU>=0.5),拿 contributing_engines list
        #[allow(clippy::type_complexity)]
        let preds_with_src: Vec<(PrivacyLabel, (usize, usize), Vec<String>, &str)> = result
            .findings
            .iter()
            .filter_map(|f| {
                PrivacyLabel::from_kind(f.kind).map(|l| {
                    let src: Vec<String> = match f.source {
                        FindingSource::Hard => vec!["hard".to_string()],
                        FindingSource::Model => {
                            // 查 attribution_map 中同 kind + IoU >= 0.5 的 finding
                            attribution_map
                                .iter()
                                .find(|(mf, _)| mf.kind == f.kind && iou(mf.span, f.span) >= 0.5)
                                .map(|(_, engines)| engines.clone())
                                .unwrap_or_else(|| vec!["model-unattributed".to_string()])
                        }
                    };
                    (l, f.span, src, f.kind)
                })
            })
            .collect();

        // 转 (canonical_label, span) for IoU 比较(沿用现有 TP/FP/FN 路径,不改 metric 计算)
        let preds: Vec<(PrivacyLabel, (usize, usize))> =
            preds_with_src.iter().map(|(l, s, _, _)| (*l, *s)).collect();
        let truths: Vec<(PrivacyLabel, (usize, usize))> = sample
            .truth
            .iter()
            .map(|t| (parse_truth_label(&t.label), (t.start, t.end)))
            .collect();

        // 贪心匹配 IoU >= 0.5
        let mut pred_used = vec![false; preds.len()];
        let mut truth_matched = vec![false; truths.len()];
        for (ti, &(t_label, t_span)) in truths.iter().enumerate() {
            for (pi, &(p_label, p_span)) in preds.iter().enumerate() {
                if pred_used[pi] {
                    continue;
                }
                if p_label == t_label && iou(p_span, t_span) >= 0.5 {
                    pred_used[pi] = true;
                    truth_matched[ti] = true;
                    total_tp += 1;
                    if is_eu {
                        eu_tp += 1;
                    }
                    break;
                }
            }
        }
        for matched in truth_matched.iter() {
            if !matched {
                total_fn_ += 1;
                if is_eu {
                    eu_fn += 1;
                }
            }
        }
        for used in pred_used.iter() {
            if !used {
                total_fp += 1;
                if is_eu {
                    eu_fp += 1;
                }
            }
        }

        // v0.8 NICE — 收 per_sample_diff JSON(对齐 v0.7-spike-ensemble.json schema)
        if collect_per_sample {
            let preds_json: Vec<serde_json::Value> = preds_with_src
                .iter()
                .map(|(label, span, src, raw_kind)| {
                    json!({
                        "label": label.as_str(),
                        "raw_kind": raw_kind,
                        "start": span.0,
                        "end": span.1,
                        "src": src, // v0.8 Sprint 3 P2.0:Vec<String> contributing engines("hard" / "model-unattributed" / model_id list)
                    })
                })
                .collect();
            let truths_json: Vec<serde_json::Value> = sample
                .truth
                .iter()
                .map(|t| {
                    json!({
                        "label": t.label,
                        "start": t.start,
                        "end": t.end,
                    })
                })
                .collect();
            per_sample_diff.push(json!({
                "id": sample.id,
                "category": sample.category,
                "lang": sample.lang,
                "is_european_lang": is_eu,
                "preds": preds_json,
                "truths": truths_json,
                "latency_ms": dt_ms,
            }));
        }
    }

    let total_recall = if total_tp + total_fn_ > 0 {
        total_tp as f64 / (total_tp + total_fn_) as f64
    } else {
        0.0
    };
    let eu_recall = if eu_tp + eu_fn > 0 {
        eu_tp as f64 / (eu_tp + eu_fn) as f64
    } else {
        0.0
    };

    latencies_ms.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
    let p95_idx = ((latencies_ms.len() as f64 * 0.95) as usize).min(latencies_ms.len() - 1);
    let warm_p95 = latencies_ms[p95_idx];
    let warm_mean: f64 = latencies_ms.iter().sum::<f64>() / latencies_ms.len() as f64;

    // v0.8 NICE — VIGIL_R1_BENCH_OUT 写 per_sample_diff JSON(供 diagnose_per_label.py 消费)。
    if let Some(out_path) = bench_out_path.as_deref() {
        let report = json!({
            "schema_version": "v0.9.sprint1.p1_3.1",
            "ensemble": format!("{} engines + Hard rules", ensemble.engine_count()),
            "model_ids": &model_ids,
            "lang_aware": lang_aware,  // v0.9 Sprint 1 P1.3 — 标记本次跑是否走 lang-conditional
            "fixture_path": &fixture_path,
            "sample_count": samples.len(),
            "iou_threshold": 0.5,
            "warm_p95_ms": warm_p95,
            "warm_mean_ms": warm_mean,
            "metrics_full": {
                "tp": total_tp, "fp": total_fp, "fn": total_fn_,
                "recall": total_recall,
            },
            "metrics_eu_subset": {
                "tp": eu_tp, "fp": eu_fp, "fn": eu_fn,
                "recall": eu_recall,
            },
            "per_sample_diff": per_sample_diff,
            "notes": [
                "preds[].src 是 Vec<String>:[\"hard\"] / [\"model-unattributed\"] / 真 model_id 列表(P2.0)",
                "preds[].src 真 model_id list 来自 EnsembleEngine.infer_with_attribution cluster 共识",
                "preds[].raw_kind 是 RedactionEngine 原始 native label(供 BIO debug)",
                "lang 字段从 fixture 透传(P1.0+ 后所有 sample 必含;预 P1.0+ 默认空串)",
                "schema_version v0.8.sprint3.p2_0.1:src Vec<String> + model_ids 顶级字段(对齐 EnsembleEngine.with_model_ids)"
            ]
        });
        std::fs::write(out_path, serde_json::to_string_pretty(&report).unwrap())
            .unwrap_or_else(|e| panic!("write VIGIL_R1_BENCH_OUT={out_path}: {e}"));
        eprintln!(
            "[bench_out] wrote {} ({} samples)",
            out_path,
            per_sample_diff.len()
        );
    }

    println!("\n=== R1 RESULTS ===");
    println!("Engines:               {}", ensemble.engine_count());
    println!("Sample count:          {}", samples.len());
    println!("Warm p95 latency:      {warm_p95:.1}ms");
    println!("Warm mean latency:     {warm_mean:.1}ms");
    println!(
        "Full(N={}) recall:    {total_recall:.3} (TP={total_tp} FP={total_fp} FN={total_fn_})",
        samples.len()
    );
    println!("EU subset recall:      {eu_recall:.3} (TP={eu_tp} FP={eu_fp} FN={eu_fn})");
    println!(
        "EU subset count:       {}",
        samples.iter().filter(|s| is_european_lang(&s.text)).count()
    );
    println!("\n=== Verdict vs Python spike-3 baseline ===");
    println!("Python spike-3 EU recall: 0.895");
    println!("Rust R1 EU recall:        {eu_recall:.3}");
    let delta = eu_recall - 0.895;
    println!("Delta:                    {delta:+.3}");
    if delta.abs() < 0.05 {
        println!("  [PASS] within ±0.05 alignment threshold");
    } else {
        println!("  [INVESTIGATE] outside ±0.05 — possible algorithmic divergence");
    }

    // v0.7-α4 Sprint 1 — verdict gate skeleton(R1g release runner 消费):
    // 当 VIGIL_R1_VERDICT_GATE=1 时,严格阈值 fail → exit non-zero
    // (供 R1h FP regression 实测 + R1g github actions release runner 调用)
    //
    // **v0.7-α5 C step 调整**:80-sample 实测 EU recall 0.886(50-sample 0.919
    // 是乐观估计 — fixture 太小放大边缘 case 影响)。新阈值 0.85 = 0.886 - 0.036
    // 缓冲(留统计噪声余量)。VIGIL_R1_RECALL_THRESHOLD env 可覆盖(用户调试)。
    if std::env::var("VIGIL_R1_VERDICT_GATE").as_deref() == Ok("1") {
        let recall_threshold: f64 = std::env::var("VIGIL_R1_RECALL_THRESHOLD")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(0.85); // C step 调整:80-sample 0.886 baseline + buffer
        let warm_p95_threshold_ms = 1500.0; // ADR 0016 ensemble path SLO

        let mut violations: Vec<String> = Vec::new();
        if eu_recall < recall_threshold {
            violations.push(format!(
                "EU recall {eu_recall:.3} < {recall_threshold} threshold"
            ));
        }
        if warm_p95 > warm_p95_threshold_ms {
            violations.push(format!(
                "warm p95 {warm_p95:.1}ms > {warm_p95_threshold_ms}ms threshold(ADR 0016 ensemble SLO)"
            ));
        }

        println!("\n=== R1 Verdict Gate(VIGIL_R1_VERDICT_GATE=1)===");
        println!("  Recall threshold: ≥ {recall_threshold} (实测 {eu_recall:.3})");
        println!("  Warm p95 threshold: ≤ {warm_p95_threshold_ms}ms (实测 {warm_p95:.1}ms)");
        if violations.is_empty() {
            println!("  [VERDICT GATE PASS] ✅");
        } else {
            eprintln!("\n[VERDICT GATE FAIL] ❌");
            for v in &violations {
                eprintln!("  - {v}");
            }
            std::process::exit(1);
        }
    }
}
