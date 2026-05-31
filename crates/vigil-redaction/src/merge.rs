//! ADR 0013 — T0 模型 × 硬指纹 findings 合并决策层(纯函数)。
//!
//! 语义(详见 `docs/adr/0013-hardfp-model-merge.md`):
//!
//! - **D1** Hard 优先(fast-path):调用方先跑 Hard 再跑 Model,两者结果送本 merge
//! - **D3** Span 重叠 → Hard 赢(丢 Model)
//! - **D4** 不重复加权:同 span 冲突时 Model 的 `risk_delta` 随 finding 一起被 drop
//! - **D5** 非重叠 → 两者都保留(互补覆盖)
//! - **不变量**:输出按 `span.start` 升序;纯函数不改动输入
//!
//! 本模块**只负责 merge 决策**;Hard detect / Model 推理 / risk_delta 累加策略由 caller
//! 决定(ISS-005 scaffold + ISS-010 firewall preflight 消费者)。
//!
//! 类型是 minimal + 保守:`kind` 用 `&'static str` 字面量,避免提前锁死 FindingKind 枚举
//! 形态(ISS-005 真正扩 API 时可平滑升级;现有字符串字面量规则集见 `crates/vigil-redaction/src/lib.rs`
//! HARD_RULES)。

#![allow(missing_docs)] // 本模块是 ISS-005 scaffold 前置;完整 rustdoc 由 ISS-005 补

/// Finding 来源分类。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FindingSource {
    /// 正则 / 结构化硬指纹(v0.3 HARD_RULES 14 项)—— 高 precision,<1ms
    Hard,
    /// OpenAI Privacy Filter 模型输出(8 类标签)—— 高 recall,400-630 ms CPU
    Model,
}

/// 统一 finding 结构;Hard 和 Model 使用同一类型,merge 后 caller 按 `source` 区分
/// 需要时的差异化处理(如审计展现 / risk 加权)。
#[derive(Debug, Clone, PartialEq)]
pub struct Finding {
    /// label 字面量(Hard 侧:见 HARD_RULES `name`;Model 侧:`private_*` / `secret` / `account_number`)
    pub kind: &'static str,
    /// 来源层
    pub source: FindingSource,
    /// byte 区间 `[start, end)`(UTF-8 offset,与 tokenizer offsets 对齐)
    pub span: (usize, usize),
    /// 置信度 [0.0, 1.0];Hard 总为 1.0(正则命中即确定);Model 为 softmax
    pub confidence: f32,
    /// 风险加权基础值(ADR 0012 §1.3 风险分级);merge 后 caller 累加
    pub risk_delta: u32,
}

impl Finding {
    /// 硬指纹 finding 构造辅助(confidence 固定 1.0)
    pub fn hard(kind: &'static str, span: (usize, usize), risk_delta: u32) -> Self {
        Self {
            kind,
            source: FindingSource::Hard,
            span,
            confidence: 1.0,
            risk_delta,
        }
    }

    /// Model finding 构造辅助
    pub fn model(
        kind: &'static str,
        span: (usize, usize),
        confidence: f32,
        risk_delta: u32,
    ) -> Self {
        Self {
            kind,
            source: FindingSource::Model,
            span,
            confidence,
            risk_delta,
        }
    }
}

/// 两 span 严格重叠判定(strict-less):`[a_start, a_end) ∩ [b_start, b_end) != ∅`。
/// 相邻(`a_end == b_start`)**不** 视为重叠 —— 允许相邻 findings 都保留。
#[inline]
fn spans_overlap(a: (usize, usize), b: (usize, usize)) -> bool {
    a.0 < b.1 && b.0 < a.1
}

/// ADR 0013 核心 merge 函数。
///
/// **契约**:
/// - Hard findings 全保留(D1)
/// - Model findings 与**任何** Hard finding 重叠即丢弃(D3 + D4)
/// - 非重叠 Model findings 保留(D5)
/// - 结果按 `span.0` 升序;同 start 保持"Hard 先于 Model"(稳定排序)
/// - 纯函数,不改动输入
///
/// caller(ISS-005 scan_text / ISS-010 preflight)可按 `source` 做差异化审计展现
/// 或按 `risk_delta` 累加得总 risk score。
pub fn merge_findings(hard: &[Finding], model: &[Finding]) -> Vec<Finding> {
    let mut out: Vec<Finding> = Vec::with_capacity(hard.len() + model.len());
    // Hard 全收(D1)
    out.extend(hard.iter().cloned());
    // Model 逐条检查 overlap(D3)
    for m in model {
        let overlapped = hard.iter().any(|h| spans_overlap(h.span, m.span));
        if !overlapped {
            out.push(m.clone());
        }
    }
    // 稳定按 span.start 升序(D5 表现要求);sort_by 稳定,同 start 保 Hard 在前
    out.sort_by_key(|f| f.span.0);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    // 辅助 —— 简化构造
    fn h(kind: &'static str, start: usize, end: usize, risk: u32) -> Finding {
        Finding::hard(kind, (start, end), risk)
    }
    fn m(kind: &'static str, start: usize, end: usize, conf: f32, risk: u32) -> Finding {
        Finding::model(kind, (start, end), conf, risk)
    }

    // ──────────────────────────── 1. 空输入 ────────────────────────────
    #[test]
    fn merge_empty_both() {
        assert_eq!(merge_findings(&[], &[]), vec![]);
    }

    // ──────────────────────────── 2. 仅 Hard ────────────────────────────
    #[test]
    fn merge_hard_only() {
        let hard = vec![h("email", 10, 30, 10), h("aws_access_key_id", 50, 70, 25)];
        let merged = merge_findings(&hard, &[]);
        assert_eq!(merged, hard, "Hard findings 应按 span.start 升序保留");
    }

    // ──────────────────────────── 3. 仅 Model ────────────────────────────
    #[test]
    fn merge_model_only() {
        let model = vec![
            m("private_person", 0, 13, 0.99, 5),
            m("private_date", 20, 30, 0.98, 5),
        ];
        let merged = merge_findings(&[], &model);
        assert_eq!(merged, model);
    }

    // ──────────────────────────── 4. 非重叠:两侧共存 ────────────────────────────
    #[test]
    fn merge_non_overlapping_both_kept() {
        // Hard 命中 email [73..109];Model 命中 person [0..13] / date [26..36]
        let hard = vec![h("email", 73, 109, 10)];
        let model = vec![
            m("private_person", 0, 13, 0.99, 5),
            m("private_date", 26, 36, 0.98, 5),
        ];
        let merged = merge_findings(&hard, &model);
        assert_eq!(merged.len(), 3, "3 条不重叠 finding 应全保留");
        // 按 span.start 升序:person(0)→ date(26)→ email(73)
        assert_eq!(merged[0].kind, "private_person");
        assert_eq!(merged[1].kind, "private_date");
        assert_eq!(merged[2].kind, "email");
    }

    // ──────────────────────────── 5. 完全重叠:Hard 赢(D3)────────────────────────────
    #[test]
    fn merge_fully_overlapping_hard_wins() {
        // Hard `email` vs Model `private_email` 同 span
        let hard = vec![h("email", 73, 109, 10)];
        let model = vec![m("private_email", 73, 109, 1.0, 10)];
        let merged = merge_findings(&hard, &model);
        assert_eq!(merged.len(), 1, "重叠应只留 Hard");
        assert_eq!(merged[0].kind, "email");
        assert_eq!(merged[0].source, FindingSource::Hard);
    }

    // ──────────────────────────── 6. 部分重叠:Model drop ────────────────────────────
    #[test]
    fn merge_partially_overlapping_hard_wins() {
        // Hard [73..109];Model [70..85] 部分重叠前缀
        let hard = vec![h("email", 73, 109, 10)];
        let model = vec![m("private_email", 70, 85, 0.9, 10)];
        let merged = merge_findings(&hard, &model);
        assert_eq!(merged.len(), 1);
        assert_eq!(merged[0].source, FindingSource::Hard);

        // 反向:Model [100..120] 部分重叠后缀
        let model2 = vec![m("private_email", 100, 120, 0.9, 10)];
        let merged2 = merge_findings(&hard, &model2);
        assert_eq!(merged2.len(), 1);
        assert_eq!(merged2[0].source, FindingSource::Hard);

        // 反向:Model [70..120] 完全包含 Hard
        let model3 = vec![m("private_email", 70, 120, 0.9, 10)];
        let merged3 = merge_findings(&hard, &model3);
        assert_eq!(merged3.len(), 1);
        assert_eq!(merged3[0].source, FindingSource::Hard);
    }

    // ──────────────────────────── 7. 相邻不重叠:两侧保留 ────────────────────────────
    #[test]
    fn merge_adjacent_not_overlap() {
        // Hard [10..20];Model [20..30](端点相邻)
        let hard = vec![h("email", 10, 20, 10)];
        let model = vec![m("private_person", 20, 30, 0.9, 5)];
        let merged = merge_findings(&hard, &model);
        assert_eq!(
            merged.len(),
            2,
            "相邻 span 两者都保留(spans_overlap 严格 strict-less)"
        );
        assert_eq!(merged[0].kind, "email");
        assert_eq!(merged[1].kind, "private_person");
    }

    // ──────────────────────────── 8. risk_delta 不双倍(D4)────────────────────────────
    #[test]
    fn merge_no_double_weighting_on_overlap() {
        // 同 span 重叠:只计 Hard.risk,不加 Model.risk
        let hard = vec![h("email", 73, 109, 10)];
        let model = vec![m("private_email", 73, 109, 1.0, 10)];
        let merged = merge_findings(&hard, &model);
        let total: u32 = merged.iter().map(|f| f.risk_delta).sum();
        assert_eq!(
            total, 10,
            "重叠时 risk 只计 Hard 一次,不应 Hard+Model 双加为 20"
        );

        // 对照:非重叠时两者都计
        let model2 = vec![m("private_email", 200, 220, 1.0, 10)];
        let merged2 = merge_findings(&hard, &model2);
        let total2: u32 = merged2.iter().map(|f| f.risk_delta).sum();
        assert_eq!(total2, 20, "非重叠时 Hard + Model 正常累加");
    }

    // ──────────────────────────── 9. 综合场景(ISS-022 medium 实际样本)────────────────────────────
    #[test]
    fn merge_iss_022_medium_sample_scenario() {
        // 模拟 ISS-022 medium 样本(文档 §1.3)的 merge 结果:
        //   Hard:  email [73..109]
        //   Model: private_person [0..13], private_date [26..36],
        //          private_person [45..70],
        //          private_email [73..109]  ← 与 Hard 冲突,应丢
        //          private_phone [117..135],
        //          private_address [157..201]
        let hard = vec![h("email", 73, 109, 10)];
        let model = vec![
            m("private_person", 0, 13, 0.99, 5),
            m("private_date", 26, 36, 0.98, 5),
            m("private_person", 45, 70, 0.97, 5),
            m("private_email", 73, 109, 1.0, 10),
            m("private_phone", 117, 135, 1.0, 10),
            m("private_address", 157, 201, 0.99, 5),
        ];
        let merged = merge_findings(&hard, &model);
        assert_eq!(
            merged.len(),
            6,
            "合并后 6 条(Hard 1 + Model 5,private_email drop)"
        );
        // 校验 private_email 被丢
        assert!(!merged.iter().any(|f| f.kind == "private_email"));
        // 校验 email(Hard)保留
        assert!(merged
            .iter()
            .any(|f| f.kind == "email" && f.source == FindingSource::Hard));
        // 校验排序
        let starts: Vec<usize> = merged.iter().map(|f| f.span.0).collect();
        assert_eq!(starts, vec![0, 26, 45, 73, 117, 157]);

        // risk_delta 合计(按 ADR 0012 §1.3 分级)
        let total: u32 = merged.iter().map(|f| f.risk_delta).sum();
        // 5(person) + 5(date) + 5(person) + 10(email,Hard 赢) + 10(phone) + 5(address) = 40
        assert_eq!(total, 40);
    }

    // ──────────────────────────── 10. 纯函数纪律:不改动输入 ────────────────────────────
    #[test]
    fn merge_does_not_mutate_inputs() {
        let hard = vec![h("email", 10, 20, 10)];
        let model = vec![m("private_email", 10, 20, 1.0, 10)];
        let hard_before = hard.clone();
        let model_before = model.clone();
        let _ = merge_findings(&hard, &model);
        assert_eq!(hard, hard_before);
        assert_eq!(model, model_before);
    }

    // ───────── ISS-021:Hard kind × PrivacyLabel × merge 决策 全 kind 矩阵 golden ─────────
    //
    // ADR 0013 Revised(D-final-1 / D-final-2)要求把"D3 一刀切"细化为
    // "每条 Hard rule 的具体 merge 行为 + PrivacyLabel 映射"都锁死。
    //
    // 14 个 Hard kind 字面量(与 `vigil-redaction::lib.rs::ALL_RULES.name` 对齐;
    // 12 secret-类 + email + internal_ipv4)+ 期望 PrivacyLabel:
    const HARD_KIND_TO_LABEL: &[(&str, crate::PrivacyLabel)] = &[
        ("aws_access_key_id", crate::PrivacyLabel::Secret),
        ("github_token", crate::PrivacyLabel::Secret),
        ("anthropic_api_key", crate::PrivacyLabel::Secret),
        ("openai_api_key", crate::PrivacyLabel::Secret),
        ("jwt", crate::PrivacyLabel::Secret),
        ("pem_private_key", crate::PrivacyLabel::Secret),
        ("env_assignment", crate::PrivacyLabel::Secret),
        ("slack_webhook", crate::PrivacyLabel::Secret),
        ("stripe_secret_key", crate::PrivacyLabel::Secret),
        ("google_api_key", crate::PrivacyLabel::Secret),
        ("gitlab_pat", crate::PrivacyLabel::Secret),
        ("database_url", crate::PrivacyLabel::Secret),
        ("email", crate::PrivacyLabel::Email),
        ("internal_ipv4", crate::PrivacyLabel::Url),
    ];

    /// 为每个 Hard kind 选一个**与其 PrivacyLabel 一致**的 Model 端字面量。
    /// 选取规则:
    /// - Hard 落 `Email`  → Model `private_email`(Stage 2 模型典型输出)
    /// - Hard 落 `Url`    → Model `private_url`
    /// - Hard 落 `Secret` → Model `secret`(裸 label,Privacy Filter 33-class 之一)
    ///
    /// 这样 merge 重叠时,业务上"两边讲的是同一件事",Hard 赢的语义清晰。
    fn paired_model_kind(hard_kind: &str) -> &'static str {
        match hard_kind {
            "email" => "private_email",
            "internal_ipv4" => "private_url",
            // 其余 12 secret-类:Model 用裸 `secret`(8 类标签之一)
            _ => "secret",
        }
    }

    /// D-final-2 封闭映射:每个 Hard kind 字面量必须能映射到某个 PrivacyLabel,
    /// 且映射结果与本 ISS 锁定的 golden 表一致。
    #[test]
    fn iss_021_hard_kind_to_privacy_label_golden() {
        use crate::PrivacyLabel;
        for (kind, expected) in HARD_KIND_TO_LABEL {
            assert_eq!(
                PrivacyLabel::from_kind(kind),
                Some(*expected),
                "Hard kind {kind:?} 应映射到 {expected:?}\
                 (ADR 0013 Revised D-final-2 封闭映射;改字面量需同步 \
                 vigil-redaction::label.rs::from_kind + 本 golden 表)"
            );
        }
    }

    /// D-final-1 矩阵化:每个 Hard kind 在同 span 重叠时必赢、Model finding 必丢。
    #[test]
    fn iss_021_merge_overlap_hard_wins_for_each_kind() {
        for (kind, _) in HARD_KIND_TO_LABEL {
            let hard = vec![Finding::hard(kind, (10, 30), 25)];
            let model = vec![Finding::model(paired_model_kind(kind), (10, 30), 1.0, 25)];
            let merged = merge_findings(&hard, &model);
            assert_eq!(
                merged.len(),
                1,
                "Hard kind {kind:?} 同 span 重叠 merge 必去重为 1 条"
            );
            assert_eq!(
                merged[0].source,
                FindingSource::Hard,
                "Hard kind {kind:?} 同 span 重叠应 Hard 赢(ADR 0013 D-final-1)"
            );
            assert_eq!(merged[0].kind, *kind);
            // D4 不双倍:risk 只取 Hard 一次
            assert_eq!(
                merged[0].risk_delta, 25,
                "Hard kind {kind:?} 重叠时 risk 只计 Hard 一次,不应 Hard+Model 双加"
            );
        }
    }

    /// D5 矩阵化:每个 Hard kind 与非重叠 Model finding 共存时,两者都保留。
    #[test]
    fn iss_021_merge_no_overlap_both_kept_for_each_kind() {
        for (kind, _) in HARD_KIND_TO_LABEL {
            let hard = vec![Finding::hard(kind, (10, 30), 25)];
            let model = vec![Finding::model(paired_model_kind(kind), (50, 70), 1.0, 25)];
            let merged = merge_findings(&hard, &model);
            assert_eq!(
                merged.len(),
                2,
                "Hard kind {kind:?} 非重叠 merge 两者都保留(ADR 0013 D5)"
            );
            // 升序 by span.start:Hard 在前(10),Model 在后(50)
            assert_eq!(merged[0].source, FindingSource::Hard);
            assert_eq!(merged[1].source, FindingSource::Model);
        }
    }

    /// 集合守门(R1 NICE 强化):HARD_KIND_TO_LABEL 必须**精确等于**
    /// `crate::HARD_RULES.name` 集合 + ALL_RULES 独有的 email/internal_ipv4。
    ///
    /// 比单纯 `len == 14` 守门**更强**:Codex R1 NICE 指出 len 守门不能抓"加新
    /// HARD_RULES 但忘了同步 HARD_KIND_TO_LABEL"或"删了某个 HARD_RULES.name 但
    /// 这里残留"两类漂移。本测试做集合双向 diff,任一侧漂移即指出具体差异。
    ///
    /// **覆盖关系**:
    /// - `HARD_RULES`(crate::pub(crate) 静态)= 12 secret-类 hard rule
    /// - `ALL_RULES` 独有 = `email` + `internal_ipv4`(redact 路径用,**故意不进**
    ///   `HARD_RULES` 因为可能误报正常业务文本;但 PrivacyLabel::from_kind 必须
    ///   认它们,否则 Model 侧产 private_email/private_url 后映射会落空)
    /// - 总和 = 14,与 vigil-browser FindingKind 12 (LOCAL_ONLY 除外) 的关系由
    ///   `vigil-browser/tests/rule_sync.rs::iss_021_*` 守门(详见 ADR 0013 Revised
    ///   跨 crate 不变量表)
    #[test]
    fn iss_021_hard_kind_set_size_matches_redaction_rules() {
        use std::collections::BTreeSet;

        // 本表的 kinds
        let golden_kinds: BTreeSet<&str> = HARD_KIND_TO_LABEL.iter().map(|(k, _)| *k).collect();

        // 真实 HARD_RULES.name 集合(12 secret-类)+ ALL_RULES 独有的 2 项
        let mut expected_kinds: BTreeSet<&'static str> =
            crate::HARD_RULES.iter().map(|r| r.name).collect();
        expected_kinds.insert("email");
        expected_kinds.insert("internal_ipv4");

        // 集合双向 diff,任一侧漂移即 fail 并指出具体差异
        assert_eq!(
            golden_kinds, expected_kinds,
            "HARD_KIND_TO_LABEL 与 (HARD_RULES + email/internal_ipv4) 集合漂移;\
             检查 vigil-redaction lib.rs HARD_RULES 是否新增 / 删除了 hard rule,\
             以及 ALL_RULES 是否还独有 email/internal_ipv4(若改动需同步本表 + \
             ADR 0013 Revised 版本史)"
        );

        // 兜底:精确数量 14(R1 原守门保留,语义冗余但便于回归 triage)
        assert_eq!(golden_kinds.len(), 14);
    }
}
