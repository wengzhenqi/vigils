//! v0.10 Sprint 5 Phase 4 spike — multilang_baseline_v1 fixture loader 守门(skip-if-empty)。
//!
//! **目的**:Day 2 Phase B 完成后,守门 800-sample multilang fixture 的结构正确性。
//! 与 [`fixture_invariants.rs`](./fixture_invariants.rs) 的关键区别:
//!
//! - `fixture_invariants.rs` 守 `tests/fixtures/labeled_samples.json`(EU 多语言 fixture);
//!   `lang ∈ {en, de, it, fr, zh, ja, ko, ru}` allowed enum 严格守门。
//! - 本 file 守 `crates/vigil-redaction/fixtures/multilang_baseline_v1/`(Phase 4 spike 独立
//!   fixture root)。`lang ∈ {zh, ja, ru, mixed}` — 与 EU enum 解耦(选 README A/B 之 **B**:
//!   独立 fixture loader,不污染既有 EU+ASIA enum 语义)。
//!
//! **拍板:lang='mixed' enum 决策 = B**(独立 loader,本 file 内部 ALLOWED_MULTILANG_LANGS;
//! 不扩 fixture_invariants.rs allowed_lang;multilang_baseline_v1 是 spike 数据,不进 EU
//! 主 fixture 路径)。
//!
//! **Skip-if-empty fallback**:fixture root 不存或 0 sample 时,所有 test 提早返回 `Ok`。
//! Day 2 Phase B 未完成时 CI 不破;Phase B 完成 + 800 sample 落地后,
//! [`multilang_v1_total_meets_lower_bound`] 等 lower bound 守门激活。
//!
//! **Phase B 完成后必扩**:
//! - [`MULTILANG_V1_TOTAL_LOWER_BOUND`] 从 1 升到 600(spike_baseline 600 + heldout 200 = 800,
//!   守 spike_baseline 子集 ≥ 600)
//! - 每桶 lower bound:zh ≥ 150 / ja ≥ 150 / ru ≥ 150 / mixed ≥ 75 / negative ≥ 75
//! - lang_review_status 守门:全部 'human_curated'(目前 'heuristic_draft' 仍允许)
//!
//! Codex Phase B preliminary review ACCEPT 后再扩 lower bound。

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::collections::BTreeMap;
use std::path::PathBuf;

use serde::Deserialize;

use vigil_redaction::PrivacyLabel;

/// fixture root(相对 vigil-redaction crate)。
fn fixture_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("fixtures/multilang_baseline_v1")
}

/// 5 桶目录名。
const BUCKETS: &[&str] = &["zh", "ja", "ru", "mixed_script", "negative_control"];

/// **拍板 B**:multilang_baseline_v1 独立 lang enum,不与 fixture_invariants.rs allowed_lang
/// 共用。spike 数据隔离于 EU 主 fixture 路径,避免污染既有 enum 语义。
const ALLOWED_MULTILANG_LANGS: &[&str] = &["zh", "ja", "ru", "mixed"];

/// allowed `lang_review_status` enum(对齐 fixture-schema.md § 2)。
/// Phase B 完成后必硬约束为 `human_curated`(目前 `heuristic_draft` 是 synth.py 默认)。
const ALLOWED_LANG_REVIEW_STATUS: &[&str] = &["human_curated", "heuristic_draft", "pending_review"];

/// allowed `eval_role` enum。
const ALLOWED_EVAL_ROLE: &[&str] = &["spike_baseline", "heldout_human_eval"];

/// Phase A 阶段 lower bound = 1(skip-if-empty);Phase A.2 (synth.py 生成 800) 完成后
/// 升到 600(spike_baseline 600 / heldout 200 = 800);Phase B human review 完成后保持。
///
/// **当前状态(2026-05-10 commit `d107c28` 后)**:Phase A.2 完成 — 800 sample 已落地,
/// 标 lang_review_status='heuristic_draft';Phase B (human review + sign-off + Codex)
/// 仍待 spike-team。
const MULTILANG_V1_TOTAL_LOWER_BOUND: usize = 600;

/// Phase A.2 完成后,各桶 lower bound(spike_baseline 子集占 ~75%):
/// zh/ja/ru 各 ~150 / mixed ~75 / negative ~75 = 600;若 user 调整 idx % 4 比例
/// 可能 ±5% 漂移,守门取严格值(150/75)。
const ZH_LOWER_BOUND: usize = 150;
const JA_LOWER_BOUND: usize = 150;
const RU_LOWER_BOUND: usize = 150;
const MIXED_LOWER_BOUND: usize = 70; // 100 sample × 75% = 75,留 5 buffer
const NEGATIVE_LOWER_BOUND: usize = 70;

/// `#[allow(dead_code)]`:test-only struct;不同 test 读不同字段子集,
/// 整体 struct 视图保留所有 deserialize 字段以做 schema-level sanity。
#[derive(Deserialize, Debug)]
#[allow(dead_code)]
struct Sample {
    id: String,
    text: String,
    lang: String,
    #[serde(default)]
    lang_review_status: String,
    #[serde(default)]
    eval_role: String,
    expected_findings: Vec<ExpectedFinding>,
    #[serde(default)]
    source: String,
}

#[derive(Deserialize, Debug)]
#[allow(dead_code)]
struct ExpectedFinding {
    label: String,
    start: usize,
    end: usize,
    extracted_text: String,
    #[serde(default)]
    risk_tier: String,
    #[serde(default)]
    redact_action: String,
}

/// 加载 fixture 全部 sample(skip-if-empty:root 不存即返空)。
fn load_all() -> Vec<Sample> {
    let root = fixture_root();
    if !root.exists() {
        return Vec::new();
    }
    let mut out = Vec::new();
    for bucket in BUCKETS {
        let dir = root.join(bucket);
        if !dir.exists() {
            continue;
        }
        let entries = match std::fs::read_dir(&dir) {
            Ok(e) => e,
            Err(_) => continue,
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if path.extension().and_then(|s| s.to_str()) != Some("json") {
                continue;
            }
            let raw = std::fs::read_to_string(&path)
                .unwrap_or_else(|e| panic!("read {}: {e}", path.display()));
            let s: Sample = serde_json::from_str(&raw)
                .unwrap_or_else(|e| panic!("parse {}: {e}", path.display()));
            out.push(s);
        }
    }
    out
}

#[test]
fn multilang_v1_skip_if_empty_or_meets_lower_bound() {
    // Phase A.2 完成后(synth.py 生成 800):全 sample 数 ≥ MULTILANG_V1_TOTAL_LOWER_BOUND。
    // 仍容忍 Phase A skip(若 fixture 被清空)。
    let samples = load_all();
    if samples.is_empty() {
        eprintln!(
            "[skip-if-empty] multilang_baseline_v1 fixture root 0 sample;Day 2 Phase A.2 未跑?\
             Phase A.2 完成后 MULTILANG_V1_TOTAL_LOWER_BOUND={} 应满足",
            MULTILANG_V1_TOTAL_LOWER_BOUND
        );
        return;
    }
    assert!(
        samples.len() >= MULTILANG_V1_TOTAL_LOWER_BOUND,
        "multilang_baseline_v1 sample 数 {} < 下界 {}",
        samples.len(),
        MULTILANG_V1_TOTAL_LOWER_BOUND
    );
}

/// Phase A.2 完成后,5 桶 per-bucket lower bound(zh/ja/ru ≥ 150 / mixed ≥ 70 / negative ≥ 70)。
/// skip-if-empty 兼容(fixture 清空时不报)。
#[test]
fn multilang_v1_per_bucket_lower_bound() {
    let root = fixture_root();
    if !root.exists() {
        return;
    }
    let mut counts: BTreeMap<&str, usize> = BTreeMap::new();
    for bucket in BUCKETS {
        let dir = root.join(bucket);
        if !dir.exists() {
            counts.insert(bucket, 0);
            continue;
        }
        let n = std::fs::read_dir(&dir)
            .ok()
            .map(|entries| {
                entries
                    .filter_map(|e| e.ok())
                    .filter(|e| e.path().extension().and_then(|s| s.to_str()) == Some("json"))
                    .count()
            })
            .unwrap_or(0);
        counts.insert(bucket, n);
    }
    // skip-if-empty:全 0 时跳(Phase A 阶段)
    if counts.values().all(|&n| n == 0) {
        return;
    }
    let bounds = [
        ("zh", ZH_LOWER_BOUND),
        ("ja", JA_LOWER_BOUND),
        ("ru", RU_LOWER_BOUND),
        ("mixed_script", MIXED_LOWER_BOUND),
        ("negative_control", NEGATIVE_LOWER_BOUND),
    ];
    for (bucket, lower) in bounds {
        let n = counts.get(bucket).copied().unwrap_or(0);
        assert!(
            n >= lower,
            "bucket {} 当前 {} sample < 下界 {}(Phase A.2 应至少满足;若刻意收缩请同步改 lower bound const)",
            bucket,
            n,
            lower
        );
    }
}

/// `lang` ∈ ALLOWED_MULTILANG_LANGS(zh/ja/ru/mixed)。**与 fixture_invariants.rs 解耦**。
#[test]
fn multilang_v1_lang_in_allowed_enum() {
    let samples = load_all();
    if samples.is_empty() {
        return;
    }
    for s in &samples {
        assert!(
            ALLOWED_MULTILANG_LANGS.contains(&s.lang.as_str()),
            "{}: lang {:?} 不在 multilang allowed {:?};拍板 B(独立 enum)— 加新 lang \
             桶请扩 ALLOWED_MULTILANG_LANGS,**不**碰 fixture_invariants.rs allowed_lang",
            s.id,
            s.lang,
            ALLOWED_MULTILANG_LANGS
        );
    }
}

/// `lang_review_status` ∈ allowed enum;Phase B 完成后必全为 `human_curated`(暂作 warn)。
#[test]
fn multilang_v1_lang_review_status_in_allowed_enum() {
    let samples = load_all();
    if samples.is_empty() {
        return;
    }
    let mut non_curated_count = 0;
    for s in &samples {
        // 缺字段当作 pending_review(synth.py 默认 'heuristic_draft',总有值)
        let status = if s.lang_review_status.is_empty() {
            "pending_review"
        } else {
            s.lang_review_status.as_str()
        };
        assert!(
            ALLOWED_LANG_REVIEW_STATUS.contains(&status),
            "{}: lang_review_status {:?} 不在 allowed {:?}",
            s.id,
            status,
            ALLOWED_LANG_REVIEW_STATUS
        );
        if status != "human_curated" {
            non_curated_count += 1;
        }
    }
    if non_curated_count > 0 {
        eprintln!(
            "[WARN] {} samples 非 human_curated(Day 2 Phase B 未签收?);Day 7 verdict 阶段必清零",
            non_curated_count
        );
    }
}

/// `eval_role` ∈ allowed;且 `heldout_human_eval` 占比 ~25%(synth.py idx % 4 == 0)。
/// 跨桶分布大致均衡(zh/ja/ru/mixed/negative 各贡献 heldout)。
#[test]
fn multilang_v1_eval_role_distribution() {
    let samples = load_all();
    if samples.is_empty() {
        return;
    }
    let mut heldout = 0;
    let mut baseline = 0;
    for s in &samples {
        let role = if s.eval_role.is_empty() {
            "spike_baseline"
        } else {
            s.eval_role.as_str()
        };
        assert!(
            ALLOWED_EVAL_ROLE.contains(&role),
            "{}: eval_role {:?} 不在 allowed {:?}",
            s.id,
            role,
            ALLOWED_EVAL_ROLE
        );
        if role == "heldout_human_eval" {
            heldout += 1;
        } else {
            baseline += 1;
        }
    }
    // synth.py idx % 4 == 0 → 25% heldout;allow ±5pp drift(若 user 手动调整)
    if samples.len() >= 100 {
        let heldout_pct = heldout as f64 / samples.len() as f64;
        assert!(
            (0.20..=0.30).contains(&heldout_pct),
            "heldout 占比 {:.2}% 超出 [20%, 30%](baseline {}, heldout {})",
            heldout_pct * 100.0,
            baseline,
            heldout
        );
    }
}

/// 8 canonical label 守门(对齐 PrivacyLabel::ALL,与 fixture_invariants.rs 同口径)。
#[test]
fn multilang_v1_label_in_canonical_8() {
    let samples = load_all();
    if samples.is_empty() {
        return;
    }
    let known: Vec<&str> = PrivacyLabel::ALL.iter().map(|l| l.as_str()).collect();
    for s in &samples {
        for (idx, f) in s.expected_findings.iter().enumerate() {
            assert!(
                known.contains(&f.label.as_str()),
                "{} expected_findings[{}] label {:?} 不在 PrivacyLabel::ALL = {:?};\
                 Phase 4 新模型 PII 类必须 mapping 到 8 canonical(SDK ABI 硬约束)",
                s.id,
                idx,
                f.label,
                known
            );
        }
    }
}

/// UTF-8 char boundary + extracted_text 与 text[start..end] sanity(Codex R2 ACCEPT 硬要求)。
#[test]
fn multilang_v1_span_char_boundary_and_extracted_text_match() {
    let samples = load_all();
    if samples.is_empty() {
        return;
    }
    for s in &samples {
        let text_bytes = s.text.as_bytes();
        let text_len = text_bytes.len();
        for (idx, f) in s.expected_findings.iter().enumerate() {
            assert!(f.start < f.end, "{} f[{}] empty span", s.id, idx);
            assert!(
                f.end <= text_len,
                "{} f[{}] end={} > len={}",
                s.id,
                idx,
                f.end,
                text_len
            );
            assert!(
                s.text.is_char_boundary(f.start) && s.text.is_char_boundary(f.end),
                "{} f[{}] start={} end={} not UTF-8 char boundary",
                s.id,
                idx,
                f.start,
                f.end
            );
            // extracted_text === text[start..end](Codex R2 ACCEPT 硬要求)
            let actual = &s.text[f.start..f.end];
            assert_eq!(
                actual, f.extracted_text,
                "{} f[{}] extracted_text {:?} != text slice {:?}(fixture corruption)",
                s.id, idx, f.extracted_text, actual
            );
        }
    }
}

/// `risk_tier` ∈ {high, med, low};**high** 对应 secret/account_number(对齐 fixture-schema.md § 3)。
#[test]
fn multilang_v1_risk_tier_aligns_with_label() {
    let samples = load_all();
    if samples.is_empty() {
        return;
    }
    let allowed = ["high", "med", "low"];
    for s in &samples {
        for (idx, f) in s.expected_findings.iter().enumerate() {
            if f.risk_tier.is_empty() {
                continue;
            }
            assert!(
                allowed.contains(&f.risk_tier.as_str()),
                "{} f[{}] risk_tier {:?} 不在 {:?}",
                s.id,
                idx,
                f.risk_tier,
                allowed
            );
            // ADR 0013 + fixture-schema.md § 3:secret + account_number 必 high
            // person/address/phone/email 默认 med(email 可被 'high' 覆盖)
            // date/url 必 low
            match f.label.as_str() {
                "secret" | "account_number" => assert_eq!(
                    f.risk_tier, "high",
                    "{} f[{}] {:?} 默认 risk_tier 必 high",
                    s.id, idx, f.label
                ),
                "date" | "url" => assert_eq!(
                    f.risk_tier, "low",
                    "{} f[{}] {:?} risk_tier 必 low",
                    s.id, idx, f.label
                ),
                _ => {} // person/address/phone 默认 med;email 可 med/high
            }
        }
    }
}

/// negative_control 桶 sample 必空 expected_findings(测 FP)。
#[test]
fn multilang_v1_negative_control_has_no_findings() {
    let dir = fixture_root().join("negative_control");
    if !dir.exists() {
        return;
    }
    let entries = match std::fs::read_dir(&dir) {
        Ok(e) => e,
        Err(_) => return,
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.extension().and_then(|s| s.to_str()) != Some("json") {
            continue;
        }
        let raw = std::fs::read_to_string(&path)
            .unwrap_or_else(|e| panic!("read {}: {e}", path.display()));
        let s: Sample =
            serde_json::from_str(&raw).unwrap_or_else(|e| panic!("parse {}: {e}", path.display()));
        assert!(
            s.expected_findings.is_empty(),
            "negative_control sample {} 含 {} expected_findings;按 fixture-schema.md § 2 必空",
            s.id,
            s.expected_findings.len()
        );
    }
}

/// `source` 字段标 enum(synthetic/public_ner/internal)。
#[test]
fn multilang_v1_source_field_in_allowed_enum() {
    let samples = load_all();
    if samples.is_empty() {
        return;
    }
    let allowed = ["synthetic", "public_ner", "internal"];
    for s in &samples {
        if s.source.is_empty() {
            continue; // backward compat:Phase A synth.py 默认 'synthetic',不应空,但容错
        }
        assert!(
            allowed.contains(&s.source.as_str()),
            "{} source {:?} 不在 {:?}",
            s.id,
            s.source,
            allowed
        );
    }
}

/// id 唯一性:跨 bucket 不重(`ml-{lang}-{NNN}` 命名 + bucket 隔离)。
#[test]
fn multilang_v1_id_unique_across_buckets() {
    let samples = load_all();
    if samples.is_empty() {
        return;
    }
    let mut seen: BTreeMap<&str, &str> = BTreeMap::new();
    for s in &samples {
        assert!(
            !seen.contains_key(s.id.as_str()),
            "duplicate id {:?}(已见于另一 sample);id 必跨 bucket 唯一",
            s.id
        );
        seen.insert(&s.id, &s.lang);
    }
}
