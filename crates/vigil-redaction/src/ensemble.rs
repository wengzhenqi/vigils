//! v0.7-α3 Phase 3 S3(E6a) — Ensemble layer:多模型 union + IoU dedup。
//!
//! 把多个 [`crate::engine::RedactionEngine`] 实例并联,产出合并的 model findings。
//! 算法移植自 `scripts/spike-p3/bench_ensemble.py::ensemble_merge`(Python POC 已
//! 验证 EU recall 0.895 vs OpenAI 单模型 0.75-0.85)。
//!
//! # 设计纪律
//!
//! - **职责分离**:ensemble 只融合 model 侧(N 个 RedactionEngine),Hard rules 由
//!   外层 [`crate::scan::scan_text_with_engine`] 在 `merge_findings(hard, model)`
//!   末段统一 merge。EnsembleEngine **不**在内部跑 hard regex,避免与 ADR 0013 D1
//!   Hard 优先决策双 source。
//! - **canonical-label IoU dedup**:同 canonical kind 重叠(IoU ≥ 0.5)→ 取 longer
//!   span;不同 canonical 重叠 → 都保留(留给 caller 审计层决策)。
//! - **失败语义**:任一引擎返 Err → propagate(整 ensemble 失败,fail-closed);
//!   单引擎成功 + 单引擎失败的 graceful degrade 推 v0.7-α4(本 S3 保严格)。
//! - **顺序**:engines 按构造顺序串行调用;同 IoU 时**先到先记**,后来者只在更长
//!   span 时替换(spike-3 Python 同语义)。
//!
//! # 不变量保留
//!
//! - 返回 findings 仍是 [`Finding`] 类型(同 `RedactionEngine.infer` 契约)
//! - `risk_delta` 由 caller 在 `scan_text_with_engine` 重新补值(C-7 决议;
//!   ensemble 层不依赖 risk 表)
//! - confidence 取 ensemble 内**首个**命中 finding 的(简化策略;merge 优先级
//!   不参与 confidence 决策)

use std::sync::Arc;

use crate::engine::{EngineError, RedactionEngine};
use crate::merge::Finding;

/// IoU 重叠阈值(NER 领域标准 0.5;与 spike-3 Python POC 同口径)。
const IOU_THRESHOLD: f64 = 0.5;

/// 多引擎 union ensemble。
///
/// **典型用例**(S4 后接 firewall config):
///
/// ```ignore
/// use std::sync::Arc;
/// use vigil_redaction::engine::{NoopEngine, RedactionEngine};
/// use vigil_redaction::ensemble::EnsembleEngine;
///
/// let engines: Vec<Arc<dyn RedactionEngine>> = vec![
///     Arc::new(NoopEngine),
///     Arc::new(NoopEngine),
/// ];
/// let ens = EnsembleEngine::new(engines);
/// let _findings = ens.infer("hello").unwrap();
/// ```
pub struct EnsembleEngine {
    engines: Vec<Arc<dyn RedactionEngine>>,
    /// v0.7-α5 A step(E6a)— 双确认 label 集合(opt-in,Codex § 2 ACCEPT)。
    /// 在此集合的 canonical label 必须由 ≥ 2 不同 engine 同 IoU 区域共识才保留;
    /// 单 engine 报即丢(降 FP 高风险类:Address/Date/AccountNumber)。
    /// 默认空 = 关闭(原 R1h 行为不变)。
    dual_confirm_labels: std::collections::BTreeSet<crate::label::PrivacyLabel>,
    /// v0.8 Sprint 3 P2.0(E6a+) — caller 提供的 model_id 数组(并列于 engines vec)。
    /// `infer_with_attribution` 用此查 engine 名字,bench / diagnose 工具需暴露
    /// per-engine attribution。默认空 → attribution 返 ["unknown-N"]。
    model_ids: Vec<String>,
}

// 手动 impl Debug:`Vec<Arc<dyn RedactionEngine>>` 不能 derive(trait object 无 Debug
// supertrait,加 supertrait 是 breaking change for external implementer)。手写实现
// 暴露结构性信息(engine 数量 + dual_confirm 集 + model_ids),不暴露 engine 内部状态。
impl std::fmt::Debug for EnsembleEngine {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EnsembleEngine")
            .field("engine_count", &self.engines.len())
            .field("dual_confirm_labels", &self.dual_confirm_labels)
            .field("model_ids", &self.model_ids)
            .finish_non_exhaustive()
    }
}

/// 内部 ensemble 追踪:per-finding engine 来源(不暴露 SDK,避免 SemVer 锁定)。
/// dual_confirm 模式下用于检查同 IoU 区域是否有多 engine 共识。
struct PerEngineFinding {
    engine_idx: usize,
    finding: Finding,
}

/// v0.8 Sprint 3 P2.0 — 单 finding 的 cross-engine attribution。
///
/// 在 [`EnsembleEngine::infer_with_attribution`] 输出中,与 `findings: Vec<Finding>`
/// 平行返回:`finding_index` 对应 findings 数组位置,`contributing_engines` 是
/// 同 IoU cluster 内贡献的所有 engine model_id(distinct + 排序)。
///
/// **dual_confirm 数据驱动校准**(Sprint 3 主用例):
/// - cluster size = 1 → 单 engine 报告,可能是该 engine 主导 label(如 hard 在 secret)
/// - cluster size ≥ 2 → 多 engine 共识,降 FP 信号强
/// - 用 P1.2 diagnose_per_label.py 可识别 per-engine TP/FP 矩阵 + per-label
///   N-engine 共识贡献率
///
/// **R1 MUST-FIX(Codex 019deb45)— SemVer**:`#[non_exhaustive]` 强制 caller 用
/// 模式匹配时写 `_`,允许未来加 `cluster_id` / score / span_source 等字段而不破
/// SemVer。caller 仍可读 pub 字段(`attr.finding_index` / `attr.contributing_engines`),
/// 但**不能**用 struct literal 在 crate 外构造(必须用 `EnsembleEngine::infer_with_attribution`
/// 拿到实例)。
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct EngineAttribution {
    /// 在 [`EnsembleEngine::infer_with_attribution`] 返 `findings` 数组中的位置
    pub finding_index: usize,
    /// 同 IoU cluster 内贡献的 engine model_id(distinct,按字典序排序便于稳定输出)。
    /// 若 caller 未通过 [`EnsembleEngine::with_model_ids`] 提供 ids,默认 `"unknown-{idx}"`。
    pub contributing_engines: Vec<String>,
}

impl EnsembleEngine {
    /// 构造 ensemble:`engines` 顺序决定 IoU dedup 时的"first-come"优先(后来者
    /// 只在 span 更长时替换 — 与 spike-3 Python POC 同语义)。
    pub fn new(engines: Vec<Arc<dyn RedactionEngine>>) -> Self {
        Self {
            engines,
            dual_confirm_labels: std::collections::BTreeSet::new(),
            model_ids: Vec::new(),
        }
    }

    /// v0.8 Sprint 3 P2.0 — 提供 model_id 数组(下标对应 engines vec)。
    ///
    /// `infer_with_attribution` 用此返 `EngineAttribution.contributing_engines`
    /// 含真实 model_id;若不调此 builder,attribution 返 `"unknown-{idx}"`。
    /// 长度不一致(`ids.len() != engines.len()`)→ panic(配置错误,fail-fast)。
    pub fn with_model_ids<I, S>(mut self, ids: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        let collected: Vec<String> = ids.into_iter().map(Into::into).collect();
        assert_eq!(
            collected.len(),
            self.engines.len(),
            "EnsembleEngine::with_model_ids:ids.len()={} 与 engines.len()={} 不匹配",
            collected.len(),
            self.engines.len()
        );
        self.model_ids = collected;
        self
    }

    /// v0.7-α5 A step — 启用 cross-engine 双确认 for 指定 canonical label。
    ///
    /// 在 `labels` 集合内的 canonical label,EnsembleEngine.infer 仅保留**有 ≥ 2
    /// 不同 engine** 同 IoU ≥ 0.5 区域共识的 finding;单 engine 报即丢。
    /// 不在集合的 label 走原 union + IoU dedup(R1h 行为不变)。
    ///
    /// **典型用法**(Codex 推荐 high-FP 类):
    /// ```ignore
    /// let ensemble = EnsembleEngine::new(engines)
    ///     .with_dual_confirm([PrivacyLabel::Address, PrivacyLabel::Date,
    ///                         PrivacyLabel::AccountNumber]);
    /// ```
    pub fn with_dual_confirm<I>(mut self, labels: I) -> Self
    where
        I: IntoIterator<Item = crate::label::PrivacyLabel>,
    {
        self.dual_confirm_labels = labels.into_iter().collect();
        self
    }

    /// 引擎数量(诊断 / 配置展示用)
    pub fn engine_count(&self) -> usize {
        self.engines.len()
    }

    /// v0.8 Sprint 3 P2.0 — ensemble 推理 + per-finding cross-engine attribution。
    ///
    /// **与 [`Self::infer`] 区别**:平行返 `Vec<EngineAttribution>`,每元素描述
    /// 同位 finding 的 IoU cluster 内 distinct 贡献 engine 集合。**findings 顺序与
    /// attributions 顺序严格一致**(并列下标);`infer()` 仍走原 union dedup 路径。
    ///
    /// **算法**:复用 [`ensemble_merge_with_dual_confirm`] 内部 cluster 逻辑,
    /// 但保留每 cluster 的 distinct engine_idx 集合 + 经 `model_ids` 转字符串。
    ///
    /// **caller 用例**:
    /// - bench / diagnose:per-engine × per-label TP/FP 真矩阵(Sprint 3 dual_confirm
    ///   校准必备)
    /// - 审计 cross-trace:某 finding 由哪些 engine 共识产出(供 ADR 0017 evolution)
    ///
    /// **v0.9 Sprint 1 P1.3 NICE(Codex 019e03b7)+ v0.10 Sprint 3 兑付**:
    /// 本方法走 baseline path(`infer_with_attribution_with_lang(text, None)`
    /// 委托);如需 lang-aware attribution 用 [`Self::infer_with_attribution_with_lang`]
    /// (v0.10 Sprint 3 加,兑付 P1.3 R1 NICE)。
    pub fn infer_with_attribution(
        &self,
        text: &str,
    ) -> Result<(Vec<Finding>, Vec<EngineAttribution>), EngineError> {
        // **v0.10 Sprint 3 fix**:legacy 路径 → infer_with_attribution_with_lang(text, None)
        // (lang None 等价 v0.9 行为;子 engine 走 default threshold_profile)
        self.infer_with_attribution_with_lang(text, None)
    }

    /// **v0.10 Sprint 3** — ensemble 推理 + per-finding cross-engine attribution +
    /// **lang 透传**(P1.3 R1 NICE 兑付,Codex `019e03b7`)。
    ///
    /// 与 [`Self::infer_with_attribution`] 区别:接 `lang: Option<&str>`
    /// 参数,内部循环调用 `engine.infer_with_lang(text, lang)?` 透传到子 engine
    /// (如 OrtEngine 走 lang-conditional threshold)。
    ///
    /// **解决问题**:v0.9 P1.3 实测发现 `infer_with_attribution` 不接 lang 致
    /// BENCH_OUT JSON 在 lang_aware 模式下 attribution 与主路径数据不一致
    /// (主 result EU FP 37 / attribution 路径仍 baseline EU FP 59)。本方法
    /// 让 attribution 与主路径口径一致,diagnose 工具消费 lang_aware bench JSON
    /// 时得到真 lang-conditional per-engine 矩阵。
    ///
    /// **lang 规范**:同 `infer_with_lang` — case-sensitive ISO 639-1 lowercase;
    /// `None` 等价 `infer_with_attribution`(baseline 行为)。
    pub fn infer_with_attribution_with_lang(
        &self,
        text: &str,
        lang: Option<&str>,
    ) -> Result<(Vec<Finding>, Vec<EngineAttribution>), EngineError> {
        let mut per_engine: Vec<PerEngineFinding> = Vec::new();
        for (idx, engine) in self.engines.iter().enumerate() {
            // v0.10 Sprint 3:用 infer_with_lang 透传 lang(对齐主路径)
            let f = engine.infer_with_lang(text, lang)?;
            for finding in f {
                per_engine.push(PerEngineFinding {
                    engine_idx: idx,
                    finding,
                });
            }
        }

        // cluster 化(与 ensemble_merge_with_dual_confirm 同口径,保 attribution)
        let (findings, attrs) =
            ensemble_merge_with_attribution(per_engine, &self.dual_confirm_labels, &self.model_ids);
        Ok((findings, attrs))
    }
}

impl RedactionEngine for EnsembleEngine {
    fn infer(&self, text: &str) -> Result<Vec<Finding>, EngineError> {
        // **v0.9 Sprint 1 P1.3 fix**:legacy 路径委托 infer_with_lang(text, None)
        // (lang None 等价 v0.8 行为;子 engine 走 default threshold_profile)
        self.infer_with_lang(text, None)
    }

    /// **v0.9 Sprint 1 P1.3 fix**(关键 bug 修复)— EnsembleEngine 必须 override
    /// `infer_with_lang` 才能把 lang 透传到每个子 engine(如 OrtEngine 内部用
    /// lang 查 LangConditionalThresholdProfile 命中 (lang, label) override)。
    ///
    /// 历史 bug:trait default `infer_with_lang(text, _lang)` 委托 `self.infer(text)`,
    /// EnsembleEngine 不 override → ensemble 子 engine 收不到 lang → lang_conditional
    /// override 永远 miss(remote 实测 baseline / lang_aware 数据完全相同坐实 bug)。
    fn infer_with_lang(&self, text: &str, lang: Option<&str>) -> Result<Vec<Finding>, EngineError> {
        let mut per_engine: Vec<PerEngineFinding> = Vec::new();
        for (idx, engine) in self.engines.iter().enumerate() {
            // **关键**:用 infer_with_lang 透传 lang(若 engine 不 override 等价 infer)
            let f = engine.infer_with_lang(text, lang)?;
            for finding in f {
                per_engine.push(PerEngineFinding {
                    engine_idx: idx,
                    finding,
                });
            }
        }
        Ok(ensemble_merge_with_dual_confirm(
            per_engine,
            &self.dual_confirm_labels,
        ))
    }
}

/// IoU(byte-level interval [start, end))。与 [`crate::scan`] / spike-3 同实现。
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

/// 合并多个引擎 findings:同 kind IoU ≥ 0.5 → 取 longer span;否则都保留。
///
/// **顺序保证**:输出按 `span.start` 升序(沿用 [`crate::merge::merge_findings`]
/// 同口径,便于审计 / UI 渲染)。
///
/// 与 [`ensemble_merge_with_dual_confirm`] 的区别:本函数走纯 union(R1h 行为);
/// dual_confirm 集合空 = 等价此函数。保留独立函数便于守门测试。
#[allow(dead_code)] // 留 backward-compat 测试守门(_unconditional 仍走原 union)
fn ensemble_merge(all: Vec<Finding>) -> Vec<Finding> {
    let mut finals: Vec<Finding> = Vec::new();
    for f in all {
        let mut absorbed = false;
        for slot in finals.iter_mut() {
            if slot.kind == f.kind && iou(slot.span, f.span) >= IOU_THRESHOLD {
                let cur_len = f.span.1.saturating_sub(f.span.0);
                let exist_len = slot.span.1.saturating_sub(slot.span.0);
                if cur_len > exist_len {
                    *slot = f.clone();
                }
                absorbed = true;
                break;
            }
        }
        if !absorbed {
            finals.push(f);
        }
    }
    finals.sort_by_key(|f| f.span.0);
    finals
}

/// v0.7-α5 A step — 带 dual_confirm 的 ensemble merge。
///
/// **算法**:
/// 1. 按 `(canonical_label, span IoU ≥ 0.5)` 分组所有 PerEngineFinding 到 cluster
/// 2. 每 cluster 收集 distinct `engine_idx` set
/// 3. **dual_confirm 集合内 label**:cluster 必须含 ≥ 2 不同 engine_idx 才保留
///    (单 engine 报丢);保留 longest span finding
/// 4. **非 dual_confirm label**:cluster 任意 engine 共识即保留 longest span(union)
/// 5. 不同 cluster 间 finding 都保留(只内部 dedup)
/// 6. 输出按 `span.start` 升序
///
/// **canonical label 路由**:Finding.kind 经 `PrivacyLabel::from_kind` 路由到
/// canonical;dual_confirm 检查走 canonical 维度(防 native label 漂移)。
fn ensemble_merge_with_dual_confirm(
    per_engine: Vec<PerEngineFinding>,
    dual_confirm: &std::collections::BTreeSet<crate::label::PrivacyLabel>,
) -> Vec<Finding> {
    use crate::label::PrivacyLabel;

    // Cluster: (canonical_label, [PerEngineFinding 同 IoU ≥ 0.5 区域])
    let mut clusters: Vec<(Option<PrivacyLabel>, Vec<PerEngineFinding>)> = Vec::new();
    for pf in per_engine {
        let canonical = PrivacyLabel::from_kind(pf.finding.kind);
        // 找匹配 cluster idx(避免 mutable borrow 与 move 冲突)
        let target_idx = clusters.iter().position(|(existing_label, group)| {
            *existing_label == canonical
                && group
                    .iter()
                    .any(|g| iou(g.finding.span, pf.finding.span) >= IOU_THRESHOLD)
        });
        match target_idx {
            Some(idx) => clusters[idx].1.push(pf),
            None => clusters.push((canonical, vec![pf])),
        }
    }

    // 每 cluster 应用 dual_confirm 规则 + 选 longest span
    let mut finals: Vec<Finding> = Vec::new();
    for (canonical, group) in clusters {
        // 检查 dual_confirm 要求
        if let Some(label) = canonical {
            if dual_confirm.contains(&label) {
                let distinct: std::collections::BTreeSet<usize> =
                    group.iter().map(|p| p.engine_idx).collect();
                if distinct.len() < 2 {
                    // dual_confirm label 但仅 1 engine 报 — 丢弃整 cluster(降 FP)
                    continue;
                }
            }
        }
        // 选 longest span
        if let Some(longest) = group
            .into_iter()
            .map(|p| p.finding)
            .max_by_key(|f| f.span.1.saturating_sub(f.span.0))
        {
            finals.push(longest);
        }
    }

    finals.sort_by_key(|f| f.span.0);
    finals
}

/// v0.8 Sprint 3 P2.0 — `ensemble_merge_with_dual_confirm` 的 attribution-保留变种。
///
/// 与 `_with_dual_confirm` 同算法(同 cluster 化 + dual_confirm 检查 + longest span),
/// 但在 cluster 阶段额外记 distinct engine_idx,最终输出 `EngineAttribution` 数组,
/// 与 findings 数组下标严格对齐。
fn ensemble_merge_with_attribution(
    per_engine: Vec<PerEngineFinding>,
    dual_confirm: &std::collections::BTreeSet<crate::label::PrivacyLabel>,
    model_ids: &[String],
) -> (Vec<Finding>, Vec<EngineAttribution>) {
    use crate::label::PrivacyLabel;

    let mut clusters: Vec<(Option<PrivacyLabel>, Vec<PerEngineFinding>)> = Vec::new();
    for pf in per_engine {
        let canonical = PrivacyLabel::from_kind(pf.finding.kind);
        let target_idx = clusters.iter().position(|(existing_label, group)| {
            *existing_label == canonical
                && group
                    .iter()
                    .any(|g| iou(g.finding.span, pf.finding.span) >= IOU_THRESHOLD)
        });
        match target_idx {
            Some(idx) => clusters[idx].1.push(pf),
            None => clusters.push((canonical, vec![pf])),
        }
    }

    // 临时 Vec 收集(label,longest_finding,distinct_engines);后按 span.start 排序
    let mut staged: Vec<(Finding, std::collections::BTreeSet<usize>)> = Vec::new();
    for (canonical, group) in clusters {
        let distinct: std::collections::BTreeSet<usize> =
            group.iter().map(|p| p.engine_idx).collect();

        // dual_confirm 检查
        if let Some(label) = canonical {
            if dual_confirm.contains(&label) && distinct.len() < 2 {
                continue;
            }
        }
        // 选 longest span
        if let Some(longest) = group
            .into_iter()
            .map(|p| p.finding)
            .max_by_key(|f| f.span.1.saturating_sub(f.span.0))
        {
            staged.push((longest, distinct));
        }
    }

    staged.sort_by_key(|(f, _)| f.span.0);

    let mut findings = Vec::with_capacity(staged.len());
    let mut attrs = Vec::with_capacity(staged.len());
    for (idx, (finding, distinct)) in staged.into_iter().enumerate() {
        let mut contributing_engines: Vec<String> = distinct
            .into_iter()
            .map(|engine_idx| {
                model_ids
                    .get(engine_idx)
                    .cloned()
                    .unwrap_or_else(|| format!("unknown-{engine_idx}"))
            })
            .collect();
        // 按字符串字典序稳定输出(独立于 engine 注册顺序;Sprint 3 diagnose 工具消费稳)
        contributing_engines.sort();
        findings.push(finding);
        attrs.push(EngineAttribution {
            finding_index: idx,
            contributing_engines,
        });
    }

    (findings, attrs)
}

// ─────────────────────────── 单测(mock-engine 驱动)───────────────────────────

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use crate::engine::{MockEngine, NoopEngine};

    #[test]
    fn ensemble_empty_engines_returns_empty() {
        let ens = EnsembleEngine::new(vec![]);
        let f = ens.infer("text").unwrap();
        assert!(f.is_empty(), "0 engines 应返空 findings");
        assert_eq!(ens.engine_count(), 0);
    }

    #[test]
    fn ensemble_single_noop_returns_empty() {
        let ens = EnsembleEngine::new(vec![Arc::new(NoopEngine)]);
        let f = ens.infer("hello world").unwrap();
        assert!(f.is_empty());
        assert_eq!(ens.engine_count(), 1);
    }

    #[test]
    fn ensemble_two_engines_disjoint_findings_both_kept() {
        // engine_a 标 person (0,5);engine_b 标 email (10,30) — 无重叠
        let a = Arc::new(MockEngine::from_findings(vec![Finding::model(
            "person",
            (0, 5),
            0.9,
            5,
        )]));
        let b = Arc::new(MockEngine::from_findings(vec![Finding::model(
            "email",
            (10, 30),
            0.95,
            10,
        )]));
        let ens = EnsembleEngine::new(vec![a, b]);
        let f = ens.infer("anything").unwrap();
        assert_eq!(f.len(), 2, "无重叠应都保留");
        // 升序
        assert_eq!(f[0].span, (0, 5));
        assert_eq!(f[1].span, (10, 30));
    }

    #[test]
    fn ensemble_same_kind_overlapping_picks_longer_span() {
        // engine_a 给短 span (0, 5) "John";engine_b 给完整 span (0, 10) "John Smith"
        // 同 kind person + IoU = 5/10 = 0.5 → 取 longer
        let a = Arc::new(MockEngine::from_findings(vec![Finding::model(
            "person",
            (0, 5),
            0.9,
            5,
        )]));
        let b = Arc::new(MockEngine::from_findings(vec![Finding::model(
            "person",
            (0, 10),
            0.85,
            5,
        )]));
        let ens = EnsembleEngine::new(vec![a, b]);
        let f = ens.infer("anything").unwrap();
        assert_eq!(f.len(), 1, "同 kind IoU >= 0.5 应合并");
        assert_eq!(f[0].span, (0, 10), "应取 longer span (10 > 5)");
    }

    #[test]
    fn ensemble_same_kind_low_iou_both_kept() {
        // person (0, 5) "John";person (20, 30) "Smith" — 不重叠(IoU=0)
        let a = Arc::new(MockEngine::from_findings(vec![Finding::model(
            "person",
            (0, 5),
            0.9,
            5,
        )]));
        let b = Arc::new(MockEngine::from_findings(vec![Finding::model(
            "person",
            (20, 30),
            0.9,
            5,
        )]));
        let ens = EnsembleEngine::new(vec![a, b]);
        let f = ens.infer("any").unwrap();
        assert_eq!(f.len(), 2, "同 kind 不重叠应都保留");
    }

    #[test]
    fn ensemble_different_kind_overlapping_both_kept() {
        // 同 span (0, 10),但 kind 不同 — 都保留(由 caller 审计层决策)
        let a = Arc::new(MockEngine::from_findings(vec![Finding::model(
            "person",
            (0, 10),
            0.9,
            5,
        )]));
        let b = Arc::new(MockEngine::from_findings(vec![Finding::model(
            "email",
            (0, 10),
            0.9,
            10,
        )]));
        let ens = EnsembleEngine::new(vec![a, b]);
        let f = ens.infer("any").unwrap();
        assert_eq!(f.len(), 2, "不同 kind 重叠不去重");
    }

    #[test]
    fn ensemble_propagates_engine_error() {
        struct FailingEngine;
        impl RedactionEngine for FailingEngine {
            fn infer(&self, _: &str) -> Result<Vec<Finding>, EngineError> {
                Err(EngineError::InferRun("mock-failure".to_string()))
            }
        }
        let a = Arc::new(MockEngine::from_findings(vec![Finding::model(
            "person",
            (0, 5),
            0.9,
            5,
        )]));
        let b = Arc::new(FailingEngine);
        let ens = EnsembleEngine::new(vec![a, b]);
        let r = ens.infer("any");
        assert!(
            matches!(r, Err(EngineError::InferRun(_))),
            "任一引擎失败应 propagate(fail-closed)"
        );
    }

    #[test]
    fn ensemble_three_engines_iou_above_threshold_merges() {
        // 三引擎场景:
        // - "xlmr" 给 person (0, 6) — IoU(0,6)(0,10) = 6/10 = 0.6 ≥ 0.5
        // - "yonigo" 没出 person(MockEngine 空)
        // - 第三 mock(模拟"OpenAI")给 person (0, 10) 完整 span
        // 期望:IoU 0.6 触发合并,取 longer span (0, 10)
        let xlmr = Arc::new(MockEngine::from_findings(vec![Finding::model(
            "person",
            (0, 6),
            0.85,
            5,
        )]));
        let yonigo = Arc::new(MockEngine::from_findings(vec![]));
        let openai = Arc::new(MockEngine::from_findings(vec![Finding::model(
            "person",
            (0, 10),
            0.95,
            5,
        )]));
        let ens = EnsembleEngine::new(vec![xlmr, yonigo, openai]);
        let f = ens.infer("John Smith works here.").unwrap();
        assert_eq!(f.len(), 1, "三 engine 同 kind IoU 0.6 应合 1");
        assert_eq!(f[0].span, (0, 10), "应取 longer span (10 > 6)");
    }

    #[test]
    fn ensemble_spike3_realistic_iou_below_threshold_keeps_both() {
        // 这是 spike-3 实测真实场景:xlmr 给 (0, 4) "John",truth (0, 10);
        // IoU = 4/10 = 0.4 < 0.5 阈值。openai 假设给 (0, 10);两 spans 都保留
        // (体现 spike-3 person 0.67 recall 的真实算法行为 — IoU 不达,合并失败)
        let xlmr = Arc::new(MockEngine::from_findings(vec![Finding::model(
            "person",
            (0, 4),
            0.85,
            5,
        )]));
        let openai = Arc::new(MockEngine::from_findings(vec![Finding::model(
            "person",
            (0, 10),
            0.95,
            5,
        )]));
        let ens = EnsembleEngine::new(vec![xlmr, openai]);
        let f = ens.infer("John Smith.").unwrap();
        assert_eq!(f.len(), 2, "IoU 0.4 < 0.5 不合并(spike-3 实测真实行为)");
    }

    #[test]
    fn ensemble_iou_threshold_boundary_just_below_05_keeps_both() {
        // (0, 4) ∩ (3, 10) = (3, 4) → 长度 1; ∪ = (0, 10) → 长度 10;IoU = 0.1
        // < 0.5 阈值 → 都保留
        let a = Arc::new(MockEngine::from_findings(vec![Finding::model(
            "person",
            (0, 4),
            0.9,
            5,
        )]));
        let b = Arc::new(MockEngine::from_findings(vec![Finding::model(
            "person",
            (3, 10),
            0.9,
            5,
        )]));
        let ens = EnsembleEngine::new(vec![a, b]);
        let f = ens.infer("any").unwrap();
        assert_eq!(f.len(), 2, "IoU < 0.5 不合并");
    }

    // ─── v0.7-α5 A step:cross-engine 双确认守门 ───
    use crate::label::PrivacyLabel;

    /// dual_confirm 关闭(默认)→ 与 R1h 行为一致(单 engine 报也保留)
    #[test]
    fn dual_confirm_default_off_keeps_single_engine_finding() {
        let a = Arc::new(MockEngine::from_findings(vec![Finding::model(
            "private_address",
            (0, 10),
            0.9,
            5,
        )]));
        let b = Arc::new(MockEngine::from_findings(vec![]));
        let ens = EnsembleEngine::new(vec![a, b]); // dual_confirm 默认空
        let f = ens.infer("any").unwrap();
        assert_eq!(f.len(), 1, "默认无 dual_confirm,单 engine 报应保留");
    }

    /// dual_confirm Address 启用 → 单 engine address 丢弃
    #[test]
    fn dual_confirm_address_drops_single_engine_finding() {
        let a = Arc::new(MockEngine::from_findings(vec![Finding::model(
            "private_address",
            (0, 10),
            0.9,
            5,
        )]));
        let b = Arc::new(MockEngine::from_findings(vec![]));
        let ens = EnsembleEngine::new(vec![a, b]).with_dual_confirm([PrivacyLabel::Address]);
        let f = ens.infer("any").unwrap();
        assert!(
            f.is_empty(),
            "dual_confirm Address 启用 + 仅 engine_a 报 → 丢弃,实际: {:?}",
            f
        );
    }

    /// dual_confirm Address 启用 + 双 engine 共识 → 保留 longest
    #[test]
    fn dual_confirm_address_keeps_dual_engine_consensus() {
        // engine_a: address (0, 6) 短;engine_b: address (0, 10) 长
        // IoU = 6/10 = 0.6 ≥ 0.5 → cluster;2 distinct engine → 保留 longest (0, 10)
        let a = Arc::new(MockEngine::from_findings(vec![Finding::model(
            "private_address",
            (0, 6),
            0.9,
            5,
        )]));
        let b = Arc::new(MockEngine::from_findings(vec![Finding::model(
            "private_address",
            (0, 10),
            0.9,
            5,
        )]));
        let ens = EnsembleEngine::new(vec![a, b]).with_dual_confirm([PrivacyLabel::Address]);
        let f = ens.infer("any").unwrap();
        assert_eq!(f.len(), 1, "双 engine 共识应保留 1");
        assert_eq!(f[0].span, (0, 10), "应取 longest span");
    }

    /// dual_confirm Address 启用,但 Person 不在集合 → Person 单 engine 仍保留
    #[test]
    fn dual_confirm_selective_keeps_other_labels() {
        let a = Arc::new(MockEngine::from_findings(vec![
            Finding::model("private_person", (0, 10), 0.9, 5),
            Finding::model("private_address", (20, 30), 0.9, 5),
        ]));
        let b = Arc::new(MockEngine::from_findings(vec![])); // 空
        let ens = EnsembleEngine::new(vec![a, b]).with_dual_confirm([PrivacyLabel::Address]);
        let f = ens.infer("any").unwrap();
        // Person 不在 dual_confirm:保留;Address 在 dual_confirm + 单 engine:丢
        assert_eq!(f.len(), 1);
        assert_eq!(f[0].kind, "private_person");
    }

    /// dual_confirm 多 label 集合
    #[test]
    fn dual_confirm_multi_labels() {
        let a = Arc::new(MockEngine::from_findings(vec![
            Finding::model("private_address", (0, 10), 0.9, 5),
            Finding::model("private_date", (20, 30), 0.9, 5),
            Finding::model("private_email", (40, 50), 0.9, 5),
        ]));
        let b = Arc::new(MockEngine::from_findings(vec![])); // 全单 engine
        let ens = EnsembleEngine::new(vec![a, b])
            .with_dual_confirm([PrivacyLabel::Address, PrivacyLabel::Date]);
        let f = ens.infer("any").unwrap();
        // Address + Date 单 engine 丢;Email 不在集合保留
        assert_eq!(f.len(), 1);
        assert_eq!(f[0].kind, "private_email");
    }

    /// 不同 engine 不同 span(IoU < 0.5)→ 分独立 cluster,各自检查 dual_confirm
    #[test]
    fn dual_confirm_separate_clusters_each_checked() {
        // address (0, 5) by engine_a;address (20, 30) by engine_b — 不重叠
        // 两个独立 cluster,各 1 distinct engine → dual_confirm Address 各自丢
        let a = Arc::new(MockEngine::from_findings(vec![Finding::model(
            "private_address",
            (0, 5),
            0.9,
            5,
        )]));
        let b = Arc::new(MockEngine::from_findings(vec![Finding::model(
            "private_address",
            (20, 30),
            0.9,
            5,
        )]));
        let ens = EnsembleEngine::new(vec![a, b]).with_dual_confirm([PrivacyLabel::Address]);
        let f = ens.infer("any").unwrap();
        assert!(
            f.is_empty(),
            "两个独立 cluster 各 1 engine → 都丢(dual_confirm 不跨 cluster 共识)"
        );
    }

    // ─── v0.8 Sprint 3 P2.0:per-engine attribution 守门 ───

    #[test]
    fn attribution_default_uses_unknown_idx() {
        // 不调 with_model_ids → contributing_engines 应为 ["unknown-0"](单 engine cluster)
        let a = Arc::new(MockEngine::from_findings(vec![Finding::model(
            "person",
            (0, 10),
            0.9,
            5,
        )]));
        let ens = EnsembleEngine::new(vec![a]);
        let (findings, attrs) = ens.infer_with_attribution("any").unwrap();
        assert_eq!(findings.len(), 1);
        assert_eq!(attrs.len(), 1);
        assert_eq!(attrs[0].finding_index, 0);
        assert_eq!(attrs[0].contributing_engines, vec!["unknown-0".to_string()]);
    }

    #[test]
    fn attribution_with_model_ids_returns_real_names() {
        let a = Arc::new(MockEngine::from_findings(vec![Finding::model(
            "person",
            (0, 10),
            0.9,
            5,
        )]));
        let b = Arc::new(MockEngine::from_findings(vec![Finding::model(
            "email",
            (20, 30),
            0.9,
            5,
        )]));
        let ens = EnsembleEngine::new(vec![a, b])
            .with_model_ids(["openai-privacy-filter-v1", "xlmr-pii-v1"]);
        let (findings, attrs) = ens.infer_with_attribution("any").unwrap();
        assert_eq!(findings.len(), 2);
        assert_eq!(attrs.len(), 2);
        // 按 span.start 升序;person (0,10) 来自 engine 0,email (20,30) 来自 engine 1
        assert_eq!(
            attrs[0].contributing_engines,
            vec!["openai-privacy-filter-v1".to_string()]
        );
        assert_eq!(
            attrs[1].contributing_engines,
            vec!["xlmr-pii-v1".to_string()]
        );
    }

    #[test]
    fn attribution_consensus_lists_all_contributing_engines() {
        // 两 engine 同 IoU cluster(person (0, 6) + person (0, 10),IoU=0.6)
        // → 1 finding(longest)+ contributing_engines 含两个 model_id
        let a = Arc::new(MockEngine::from_findings(vec![Finding::model(
            "person",
            (0, 6),
            0.85,
            5,
        )]));
        let b = Arc::new(MockEngine::from_findings(vec![Finding::model(
            "person",
            (0, 10),
            0.95,
            5,
        )]));
        let ens = EnsembleEngine::new(vec![a, b])
            .with_model_ids(["xlmr-pii-v1", "openai-privacy-filter-v1"]);
        let (findings, attrs) = ens.infer_with_attribution("any").unwrap();
        assert_eq!(findings.len(), 1, "IoU 0.6 应合 1");
        assert_eq!(findings[0].span, (0, 10));
        assert_eq!(attrs.len(), 1);
        // distinct + 字典序排序:openai-... 在 xlmr-... 前
        assert_eq!(
            attrs[0].contributing_engines,
            vec![
                "openai-privacy-filter-v1".to_string(),
                "xlmr-pii-v1".to_string()
            ]
        );
    }

    #[test]
    #[should_panic(expected = "with_model_ids")]
    fn attribution_with_mismatched_ids_count_panics() {
        let a = Arc::new(MockEngine::from_findings(vec![]));
        let b = Arc::new(MockEngine::from_findings(vec![]));
        // 2 engines + 1 id → fail-fast panic
        let _ens = EnsembleEngine::new(vec![a, b]).with_model_ids(["only-one"]);
    }

    #[test]
    fn attribution_dual_confirm_drops_single_engine_consistent() {
        // dual_confirm Address 启用 + 单 engine 报 → finding 丢 + attribution 也不应出现
        let a = Arc::new(MockEngine::from_findings(vec![Finding::model(
            "private_address",
            (0, 10),
            0.9,
            5,
        )]));
        let b = Arc::new(MockEngine::from_findings(vec![]));
        let ens = EnsembleEngine::new(vec![a, b])
            .with_model_ids(["openai", "xlmr"])
            .with_dual_confirm([PrivacyLabel::Address]);
        let (findings, attrs) = ens.infer_with_attribution("any").unwrap();
        assert!(findings.is_empty());
        assert!(
            attrs.is_empty(),
            "dual_confirm 丢 finding 时 attribution 也应丢"
        );
    }

    #[test]
    fn attribution_finding_index_aligns_with_findings_array() {
        // 多 finding 场景验 finding_index 对应 findings 数组下标
        let a = Arc::new(MockEngine::from_findings(vec![
            Finding::model("address", (50, 100), 0.9, 5),
            Finding::model("person", (0, 10), 0.9, 5),
        ]));
        let b = Arc::new(MockEngine::from_findings(vec![Finding::model(
            "email",
            (20, 40),
            0.9,
            10,
        )]));
        let ens = EnsembleEngine::new(vec![a, b]).with_model_ids(["e0", "e1"]);
        let (findings, attrs) = ens.infer_with_attribution("any").unwrap();
        assert_eq!(findings.len(), 3);
        assert_eq!(attrs.len(), 3);
        for (i, a) in attrs.iter().enumerate() {
            assert_eq!(
                a.finding_index, i,
                "finding_index 必须与 findings 数组下标对齐"
            );
        }
    }

    // ─── v0.9 Sprint 1 P1.3 fix — EnsembleEngine.infer_with_lang 透传 lang 守门 ───

    /// 测试 mock:override `infer_with_lang` 捕获 lang;验证 ensemble 真透传到
    /// 每个子 engine,而非走 trait default 委托 self.infer(那是导致 v0.9 P1.3
    /// 远程实测 lang_aware 数据 == baseline 的关键 bug 根因)。
    struct LangCapturingTestEngine {
        captured: std::sync::Mutex<Vec<Option<String>>>,
    }

    impl LangCapturingTestEngine {
        fn new() -> Self {
            Self {
                captured: std::sync::Mutex::new(Vec::new()),
            }
        }

        fn captured(&self) -> Vec<Option<String>> {
            self.captured.lock().unwrap().clone()
        }
    }

    impl RedactionEngine for LangCapturingTestEngine {
        fn infer(&self, _text: &str) -> Result<Vec<Finding>, EngineError> {
            // legacy 路径不该被 ensemble.infer_with_lang(text, Some(_)) 触发
            // (因为 ensemble 应 override 透传 lang_with_lang 而非走 default)
            self.captured.lock().unwrap().push(None);
            Ok(Vec::new())
        }

        fn infer_with_lang(
            &self,
            text: &str,
            lang: Option<&str>,
        ) -> Result<Vec<Finding>, EngineError> {
            if lang.is_none() {
                return self.infer(text);
            }
            self.captured.lock().unwrap().push(lang.map(String::from));
            Ok(Vec::new())
        }
    }

    /// **关键回归守门**:ensemble.infer_with_lang(text, Some("de")) 必须把
    /// "de" 透传到每个子 engine 的 infer_with_lang(),而不是走 trait default
    /// 委托 self.infer(那是导致 P1.3 实测无效的 bug)。
    #[test]
    fn ensemble_infer_with_lang_propagates_lang_to_all_sub_engines() {
        let a = Arc::new(LangCapturingTestEngine::new());
        let b = Arc::new(LangCapturingTestEngine::new());
        let ens = EnsembleEngine::new(vec![a.clone(), b.clone()]);

        let _ = ens.infer_with_lang("any text", Some("de")).unwrap();

        // 两个子 engine 都应捕获 Some("de"),而非 None(走 default 委托 infer)
        assert_eq!(
            a.captured(),
            vec![Some("de".to_string())],
            "engine a 应收到透传的 lang Some(\"de\");若是 None 表明 ensemble 走 default 委托 infer (bug 根因)"
        );
        assert_eq!(
            b.captured(),
            vec![Some("de".to_string())],
            "engine b 应收到透传的 lang Some(\"de\")"
        );
    }

    /// ensemble.infer(text) legacy 路径委托 infer_with_lang(text, None) — 子 engine
    /// 接到 None 走 default 兼容;v0.8 行为不变。
    #[test]
    fn ensemble_infer_legacy_passes_none_lang() {
        let a = Arc::new(LangCapturingTestEngine::new());
        let ens = EnsembleEngine::new(vec![a.clone()]);
        let _ = ens.infer("any").unwrap();
        assert_eq!(
            a.captured(),
            vec![None],
            "legacy ensemble.infer 应让子 engine 走 lang None(等价 v0.8)"
        );
    }

    // ─── v0.10 Sprint 3 — infer_with_attribution_with_lang 守门(P1.3 R1 NICE 兑付)───

    /// 关键回归守门:`infer_with_attribution_with_lang(text, Some("de"))` 必须
    /// 把 "de" 透传到每个子 engine 的 `infer_with_lang()`(P1.3 R1 NICE 修复 —
    /// 不能 silent fallback baseline `engine.infer(text)`)。
    #[test]
    fn ensemble_infer_with_attribution_with_lang_propagates_lang() {
        let a = Arc::new(LangCapturingTestEngine::new());
        let b = Arc::new(LangCapturingTestEngine::new());
        let ens = EnsembleEngine::new(vec![a.clone(), b.clone()]).with_model_ids(["e0", "e1"]);

        let _ = ens
            .infer_with_attribution_with_lang("any", Some("de"))
            .unwrap();
        assert_eq!(
            a.captured(),
            vec![Some("de".to_string())],
            "engine a 必须收到 lang Some(\"de\")(P1.3 R1 NICE attribution lang 透传)"
        );
        assert_eq!(b.captured(), vec![Some("de".to_string())]);
    }

    /// `infer_with_attribution(text)` legacy 路径委托
    /// `infer_with_attribution_with_lang(text, None)` — v0.9 行为不变。
    #[test]
    fn ensemble_infer_with_attribution_legacy_passes_none_lang() {
        let a = Arc::new(LangCapturingTestEngine::new());
        let ens = EnsembleEngine::new(vec![a.clone()]).with_model_ids(["e0"]);
        let _ = ens.infer_with_attribution("any").unwrap();
        assert_eq!(
            a.captured(),
            vec![None],
            "legacy infer_with_attribution 应走 lang None(等价 v0.9 baseline)"
        );
    }

    #[test]
    fn ensemble_output_sorted_by_span_start() {
        // 故意倒序加 findings,验证输出按 span.start 升序
        let a = Arc::new(MockEngine::from_findings(vec![
            Finding::model("address", (50, 100), 0.9, 5),
            Finding::model("person", (0, 10), 0.9, 5),
        ]));
        let b = Arc::new(MockEngine::from_findings(vec![Finding::model(
            "email",
            (20, 40),
            0.9,
            10,
        )]));
        let ens = EnsembleEngine::new(vec![a, b]);
        let f = ens.infer("any").unwrap();
        assert_eq!(f.len(), 3);
        assert_eq!(f[0].span, (0, 10));
        assert_eq!(f[1].span, (20, 40));
        assert_eq!(f[2].span, (50, 100));
    }
}
