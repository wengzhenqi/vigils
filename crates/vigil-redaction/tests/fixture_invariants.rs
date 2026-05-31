//! v0.6 P2 — fixture 不变量守门(default test 跑,无需 ort feature)。
//!
//! 守门 [`tests/fixtures/labeled_samples.json`] 的结构与 truth span 正确性:
//!
//! 1. **fixture 不退化**:samples ≥ 20(LOWER_BOUND);随后续 multilang 扩展可加,但不能减
//! 2. **truth span 是 UTF-8 char boundary**:start / end 都必须落在字符边界,
//!    否则模型 BIOES 解码做 `text[start..end]` 直接 panic(ja/ko 非 ASCII 平均 3 byte)
//! 3. **truth span 范围合法**:start ≤ end ≤ text.len(),非空 span(end > start)
//! 4. **truth label 在 PrivacyLabel ALL 内**:防 fixture 引入未知 label
//!
//! ## 为什么独立 file 而非加到 engine_mock.rs
//!
//! - `engine_mock.rs` 是引擎逻辑测试,本测试是 fixture 数据测试,关注点不同
//! - 默认 cargo test --workspace 跑,无 ort feature 依赖,fixture 加新样本即时守门
//! - 与 `engine_ort_smoke.rs`(`#[ignore]` + ORT_SMOKE=1)互补:smoke 测真模型对每
//!   PrivacyLabel ≥ 1 命中,本 test 守 fixture **数据本身**结构不破

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use serde::Deserialize;

use vigil_redaction::PrivacyLabel;

/// fixture 样本不退化下界(允许加,不许减;与 `engine_ort_smoke.rs:158` 守门同口径)
const FIXTURE_LOWER_BOUND: usize = 20;

/// v0.8 Sprint 2 P1.1 — fixture 总数 / EU 多语言 / per-label 覆盖下界。
/// 当前数据(2026-05-02 commit P1.1):92 samples,EN 35 / DE 15 / IT 15 / FR 15。
const FIXTURE_TOTAL_LOWER_BOUND: usize = 92;
const EU_PER_LANG_LOWER_BOUND: usize = 15;
const EU_LANGS: &[&str] = &["en", "de", "it", "fr"];

/// v0.10 Sprint 5 Phase 4 spike 准备 — 亚洲/新语言桶守门。
/// **不**对 labeled_samples.json 强制下界(spike 阶段 zh/ja/ko 各 ~4 sample,ru 0);
/// 目的:让 allowed_lang enum 与 ASIA_LANGS const 同步,**任一漏列**即编译/测试失败。
/// Day 2 800-sample fixture 会落到独立 `multilang_baseline_v1/` 目录,
/// 由独立 fixture loader test 负责按 200/lang 守门(本 file 不动)。
const ASIA_LANGS: &[&str] = &["zh", "ja", "ko", "ru"];

#[derive(Deserialize, Debug)]
struct Sample {
    id: String,
    #[allow(dead_code)]
    category: String,
    /// v0.8 Sprint 2 P1.0+:lang 字段(P1.0+ 后所有 sample 必含)。
    /// allowed enum: en / de / it / fr / zh / ja / ko。
    lang: String,
    text: String,
    truth: Vec<TruthSpan>,
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

#[test]
fn fixture_count_above_lower_bound() {
    let samples = load_samples();
    assert!(
        samples.len() >= FIXTURE_LOWER_BOUND,
        "fixture 样本数 {} < 下界 {}(防退化护栏);若需收缩请同步改 LOWER_BOUND 与 \
         engine_ort_smoke.rs L158 的 >= 20 断言",
        samples.len(),
        FIXTURE_LOWER_BOUND
    );
}

#[test]
fn fixture_truth_spans_are_char_boundaries() {
    let samples = load_samples();

    for sample in &samples {
        let text = sample.text.as_str();
        let text_len = text.len(); // byte len

        for (idx, truth) in sample.truth.iter().enumerate() {
            // 范围合法
            assert!(
                truth.start <= truth.end,
                "{} truth[{}] start={} > end={}",
                sample.id,
                idx,
                truth.start,
                truth.end
            );
            assert!(
                truth.end <= text_len,
                "{} truth[{}] end={} > text.len()={}(byte 越界)",
                sample.id,
                idx,
                truth.end,
                text_len
            );
            assert!(
                truth.end > truth.start,
                "{} truth[{}] 空 span(start==end={})",
                sample.id,
                idx,
                truth.start
            );

            // UTF-8 char boundary 守门 —— text[start..end] 切片不 panic 的前置条件;
            // 中日韩 fixture 平均 3 byte / 字,手算 offset 偏 1/2 立即被这两条断言抓
            assert!(
                text.is_char_boundary(truth.start),
                "{} truth[{}] start={} 不是 UTF-8 char boundary; \
                 文本 byte head: {:?}",
                sample.id,
                idx,
                truth.start,
                &text.as_bytes()[..text_len.min(truth.start + 4)],
            );
            assert!(
                text.is_char_boundary(truth.end),
                "{} truth[{}] end={} 不是 UTF-8 char boundary; \
                 文本 byte tail: {:?}",
                sample.id,
                idx,
                truth.end,
                &text.as_bytes()[truth.end.saturating_sub(4)..text_len.min(truth.end + 4)],
            );

            // 切片不 panic(以上 char boundary 已保证,这里是终态 sanity)
            let _slice = &text[truth.start..truth.end];
        }
    }
}

#[test]
fn fixture_truth_labels_are_recognized() {
    let samples = load_samples();
    let known: Vec<&str> = PrivacyLabel::ALL.iter().map(|l| l.as_str()).collect();

    for sample in &samples {
        for (idx, truth) in sample.truth.iter().enumerate() {
            assert!(
                known.contains(&truth.label.as_str()),
                "{} truth[{}] label {:?} 不在 PrivacyLabel::ALL = {:?}; \
                 添加新 label 必须先扩 PrivacyLabel enum + rule_sync 守门",
                sample.id,
                idx,
                truth.label,
                known
            );
        }
    }
}

#[test]
fn fixture_truth_slice_non_empty_text() {
    // span 切出来的子串不应是空白(catch fixture 里 start/end 写到了空格区域的 bug)
    let samples = load_samples();
    for sample in &samples {
        for (idx, truth) in sample.truth.iter().enumerate() {
            let slice = &sample.text[truth.start..truth.end];
            assert!(
                !slice.trim().is_empty(),
                "{} truth[{}] slice = {:?} 是空白;span 标到了 whitespace 而非实体内容",
                sample.id,
                idx,
                slice
            );
        }
    }
}

// ────────────────────────────────────────────────────────────────────
// v0.8 Sprint 2 P1.1 — fixture 总数 + EU 多语言桶 + per-label 覆盖守门
// ────────────────────────────────────────────────────────────────────

/// 总数 ≥ FIXTURE_TOTAL_LOWER_BOUND(92,P1.1 后)。
/// 区别于上面 `fixture_count_above_lower_bound`(20,v0.6 历史值,留作后向兼容护栏):
/// 本 test 守 v0.8+ 总量,前者守 v0.6+ 最低底线。
#[test]
fn fixture_total_meets_v0_8_lower_bound() {
    let samples = load_samples();
    assert!(
        samples.len() >= FIXTURE_TOTAL_LOWER_BOUND,
        "fixture 总数 {} < v0.8 Sprint 2 下界 {}(P1.1 已补到 92);若新加 sample \
         请同步上调 FIXTURE_TOTAL_LOWER_BOUND",
        samples.len(),
        FIXTURE_TOTAL_LOWER_BOUND
    );
}

/// 每个 sample 必含 lang 字段(P1.0+ 强制),且值在允许 enum 内。
/// 反映 P1.0+ schema 演化:fixture 不能再添加无 lang 字段的 sample。
///
/// **v0.10 Sprint 5 Phase 4 spike**:扩 'ru' 准备 Day 2 800-sample multilang fixture;
/// 与 ASIA_LANGS const 必须保持同步(由 [`asia_langs_subset_of_allowed_lang_enum`] 守门)。
#[test]
fn fixture_lang_field_in_allowed_enum() {
    let samples = load_samples();
    let allowed: &[&str] = &["en", "de", "it", "fr", "zh", "ja", "ko", "ru"];
    for sample in &samples {
        assert!(
            allowed.contains(&sample.lang.as_str()),
            "{}: lang {:?} 不在允许 enum {:?};若加新语言桶请先扩 EU_LANGS / ASIA_LANGS / allowed",
            sample.id,
            sample.lang,
            allowed
        );
    }
}

/// v0.10 Sprint 5 Phase 4 spike 准备 — `ASIA_LANGS` 必须是 `fixture_lang_field_in_allowed_enum`
/// 内 allowed 子集。守目标:任何在 ASIA_LANGS 加新桶(如 'th' / 'vi')必须同步扩
/// allowed,否则 fixture sample 落地即报错。
///
/// 这是 SSOT drift guard(`feedback_ssot_drift_guard`),**精确集合双向 diff** 的
/// 子集形式 — ASIA_LANGS ⊆ allowed。
#[test]
fn asia_langs_subset_of_allowed_lang_enum() {
    let allowed: &[&str] = &["en", "de", "it", "fr", "zh", "ja", "ko", "ru"];
    for lang in ASIA_LANGS {
        assert!(
            allowed.contains(lang),
            "ASIA_LANGS 含 {:?} 但 allowed enum 不含;\
             加新桶时必须同步扩 fixture_lang_field_in_allowed_enum 的 allowed 数组",
            lang
        );
    }
}

/// EU 各 lang(EN/DE/IT/FR)各 ≥ 15(B 折中方案目标)。
#[test]
fn fixture_eu_per_lang_meets_floor() {
    use std::collections::BTreeMap;
    let samples = load_samples();
    let mut counts: BTreeMap<&str, usize> = BTreeMap::new();
    for s in &samples {
        *counts.entry(s.lang.as_str()).or_insert(0) += 1;
    }

    for &lang in EU_LANGS {
        let n = counts.get(lang).copied().unwrap_or(0);
        assert!(
            n >= EU_PER_LANG_LOWER_BOUND,
            "EU lang {:?} 当前 {} 样本 < 下界 {}(B 折中方案);所有 EU lang 必须 ≥ 15 \
             才能进 Sprint 3 dual_confirm 校准",
            lang,
            n,
            EU_PER_LANG_LOWER_BOUND
        );
    }
}

/// 每 EU lang × 8 canonical labels 全部 ≥ 1 truth(P1.1 secret 优先补到位)。
/// 这是 Sprint 3 dual_confirm cross-engine per-label 校准的最低必要 — 任一桶 0
/// 则该 label 在该 lang 下无法做 N-engine 共识比较。
#[test]
fn fixture_eu_per_lang_per_label_coverage() {
    use std::collections::{BTreeMap, BTreeSet};
    let samples = load_samples();
    let canonical: BTreeSet<&str> = PrivacyLabel::ALL.iter().map(|l| l.as_str()).collect();

    let mut matrix: BTreeMap<&str, BTreeMap<&str, usize>> = BTreeMap::new();
    for s in &samples {
        if !EU_LANGS.contains(&s.lang.as_str()) {
            continue;
        }
        let bucket = matrix.entry(s.lang.as_str()).or_default();
        for t in &s.truth {
            if canonical.contains(t.label.as_str()) {
                *bucket.entry(t.label.as_str()).or_insert(0) += 1;
            }
        }
    }

    for &lang in EU_LANGS {
        let bucket = matrix.get(lang).cloned().unwrap_or_default();
        for label in &canonical {
            let n = bucket.get(*label).copied().unwrap_or(0);
            assert!(
                n >= 1,
                "EU lang {:?} 在 label {:?} 上 truth 数 {} < 1;Sprint 3 dual_confirm \
                 要求每 EU lang × 8 canonical labels 全部 ≥ 1。\
                 当前 {:?} 桶: {:?}",
                lang,
                label,
                n,
                lang,
                bucket
            );
        }
    }
}
