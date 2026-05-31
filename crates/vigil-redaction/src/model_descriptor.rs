//! v0.7-α3 Phase 3 Design(ADR 0017)— ModelDescriptor trait + canonical mapping。
//!
//! **scope 限制**:本模块为 **crate-private scaffold**(`pub(crate)`),不在
//! `lib.rs` re-export 到外部 / SDK Phase 1。设计冻结后由 P3-spike 验证(实测
//! 真模型),验证通过再扩 SDK(ADR 0015 边界)。
//!
//! **不变量**:
//! - 任何 [`ModelDescriptor`] 的 [`id2label`](Self::id2label) 元素经
//!   [`canonical_mapping`](Self::canonical_mapping) 必须**显式**返回
//!   `Some(PrivacyLabel)` 或 `None`(忽略);**不允许隐式遗漏**(由
//!   [`assert_canonical_mapping_total`] 测试守门)
//! - SDK [`PrivacyLabel::ALL`].len() == 8 是 canonical ABI;新模型即使有 12 / 16
//!   类语义,**必须**收敛到 8 类(防止"新增模型即扩 SDK"的失控扩张)
//!
//! **未来路径**(ADR 0017 § 7):
//! - P3-spike 验证后 SDK 暴露 [`ModelDescriptor`] + 关联类型
//! - Phase 3 实施加第二模型 manifest + selection API

use crate::label::PrivacyLabel;

/// 推理引擎使用的 tokenizer 规范。
///
/// 当前所有模型走 `tokenizers` crate `from_file(tokenizer.json)`,因而 v0.7-α3
/// 只暴露单一 variant;future-proof 为新 tokenizer 引擎(WordPiece-only / BPE-only)
/// 留扩展点。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TokenizerSpec {
    /// HuggingFace `tokenizers` crate 通用 `tokenizer.json` 加载路径;
    /// 嵌入式 vocab + post_processor 配置(BERT-WordPiece / SentencePiece / 等)
    HuggingFaceJson,
}

/// span 解码后处理策略。
///
/// 决定模型 logits 输出如何聚合成 (start, end, label) findings。
///
/// **v0.7-α3 Phase 3 (E6a S1)**:基于 spike 实证,新增 `Bio` variant
/// (xlmr-pii / yonigo-pii 模型用),保持 `Bioes` 兼容现 OpenAI 路径。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PostProcessorKind {
    /// BIOES 解码(B-/I-/O-/E-/S- 前缀);v0.6 OpenAI Privacy Filter 路径
    Bioes,
    /// BIO 解码(B-/I-/O- 前缀);xlmr-pii / yonigo-pii 等 ai4privacy 系列模型
    /// (P3-spike 实证)。`Iob` 是历史命名同义词
    Bio,
    /// IOB 解码 — 现归一为 [`Self::Bio`] 的别名(语义等价)
    #[allow(dead_code)]
    Iob,
    /// 简单 max-class per token(无 span 聚合);轻量模型可用
    #[allow(dead_code)]
    PerTokenMax,
}

/// per-label 置信度阈值 profile,**可选**(None = 模型自带阈值不调整)。
///
/// 校准用:特定模型某 label 模型常误报,可上调阈值降 FP;某 label 常漏报,可
/// 下调阈值升 recall。
///
/// **v0.7-α4 R1h(E6a)**:从未使用 → 真消费。OrtEngine.infer 在 canonical_mapping
/// 后用此 profile 过滤 low-confidence findings(单引擎 FP 控制),不影响 ensemble
/// 算法。FP 大头 label(per-engine 实测,见 docs/operations/bench/v0.7-fp-diagnosis.txt)
/// 设较高阈值 → 直接降 FP。
///
/// **决策纪律**:
/// - threshold 数值由 R1h FP diagnosis 实测驱动(p75 of FP conf,不靠拍脑袋)
/// - 大于 1.0 的阈值视为"屏蔽该 label"(永远丢)
/// - 未列项走模型默认(不调整,等价 conf 阈值 0.0)
#[derive(Debug, Clone, Default)]
pub struct ThresholdProfile {
    /// 每 PrivacyLabel 的最低置信度(0.0-1.0;> 1.0 等价禁用该 label);
    /// 未列项走模型默认
    pub thresholds: std::collections::BTreeMap<PrivacyLabel, f32>,
}

/// **v0.9 Sprint 1 P1.1** — lang-conditional threshold profile(spike)。
///
/// **数据驱动启动**(`docs/operations/v0.9-sprint1/p1_spike-candidates-92.md`):
/// 92-sample 真矩阵显示 top 5 候选(理想总收益 -22 FP / 0 TP loss):
/// - it × account_number / fr × account_number(xlmr 全 FP / openai 完全覆盖)
/// - de × person / en × person / de × account_number(xlmr 高 FP / openai 主导 TP)
///
/// **关键洞察**:全局 xlmr Person 1.1(v0.8 Sprint 4 followup FAIL,漏报 +45%)
/// 的根因是**没切 lang 维度** — `it × person` 反向 case(openai 1/2 噪声更多,
/// xlmr 2/1 健康),全局屏蔽误伤。**lang-conditional threshold** 是真正杠杆,
/// 与 v0.8 P2.1 "不引入 `per_label_min_engines`" 决议**不冲突**(那是 cross-engine
/// consensus 砍互补,本是 per (lang, label) 精准屏蔽,完全不同 lever)。
///
/// **API 设计**:
/// - `default`:无 lang 上下文 fallback(回退现有 `ThresholdProfile` 行为)
/// - `overrides[(lang, label)]`:命中即覆盖;若 caller 传 lang 但 (lang, label)
///   未配置,仍走 default
///
/// **P1.1 范围**(本 commit):仅 API + struct + xlmr top 5 overrides 静态数据;
/// **不**接到 `ModelDescriptor.threshold_profile` 使用路径(保 v0.8 default 路径
/// 绝对不变)。**P1.2** 加 `scan_text_with_lang(text, lang)` 时才真集成。
///
/// **SemVer**:`#[non_exhaustive]` — 未来加 `per_label_default` 等字段不破。
#[derive(Debug, Clone, Default)]
#[non_exhaustive]
pub struct LangConditionalThresholdProfile {
    /// 默认 threshold profile(无 lang 上下文走此)
    pub default: ThresholdProfile,
    /// (lang, PrivacyLabel) → threshold;命中即覆盖默认。lang 字符串
    /// case-sensitive(对齐 fixture lang 字段:"en"/"de"/"it"/"fr"/...)。
    pub overrides: std::collections::BTreeMap<(String, PrivacyLabel), f32>,
}

impl LangConditionalThresholdProfile {
    /// 从 [`ThresholdProfile`] 构造(无 overrides)。
    pub fn new(default: ThresholdProfile) -> Self {
        Self {
            default,
            overrides: std::collections::BTreeMap::new(),
        }
    }

    /// builder:加单条 (lang, label) → threshold override。
    ///
    /// **lang 规范**:case-sensitive,推荐 ISO 639-1 lowercase(`"en"`, `"de"`, ...);
    /// 与 fixture lang 字段对齐。重复 (lang, label) 调用以最后一次为准。
    pub fn with_override(
        mut self,
        lang: impl Into<String>,
        label: PrivacyLabel,
        threshold: f32,
    ) -> Self {
        self.overrides.insert((lang.into(), label), threshold);
        self
    }

    /// 给定 (label, optional lang) 查阈值。
    ///
    /// 优先级:
    /// 1. lang `Some(l)` 且 `(l, label)` 在 overrides → 用 override
    /// 2. 其他(lang None / lang Some 但未配置)→ 走 `default.thresholds`
    /// 3. default 也未列 → `None`(等价模型默认 conf 阈值 0.0)
    pub fn threshold_for(&self, label: PrivacyLabel, lang: Option<&str>) -> Option<f32> {
        if let Some(l) = lang {
            if let Some(t) = self.overrides.get(&(l.to_string(), label)) {
                return Some(*t);
            }
        }
        self.default.thresholds.get(&label).copied()
    }
}

/// **v0.9 Sprint 1 P1.1** — xlmr top 5 lang-conditional overrides(数据驱动)。
///
/// 来源:`docs/operations/v0.9-sprint1/p1_spike-candidates-92.md` — 92-sample
/// 真矩阵 spike candidates(spike_score ≥ 3,理想 -3 ~ -7 FP / 0 TP loss)。
///
/// 与 [`XLMR_PROFILE`] 关系:default 字段 = `XLMR_PROFILE` 克隆;overrides 加
/// 5 项 `(lang, label) → 1.1`(完全屏蔽该 lang × label 对 xlmr finding 命中)。
///
/// **P1.1 状态**:仅静态数据 + 守门;**未接** `XlmrPiiDescriptor.threshold_profile`
/// 路径(保 v0.8 default 绝对不变)。P1.2 加新方法 `lang_conditional_profile()`
/// 后才暴露;P1.3 实测 92-sample 真验证 -22 FP / 0 TP loss 假设。
pub static XLMR_LANG_CONDITIONAL_PROFILE: once_cell::sync::Lazy<LangConditionalThresholdProfile> =
    once_cell::sync::Lazy::new(|| {
        // default 与 XLMR_PROFILE 同步(v0.8 baseline:Email/Phone/Address 屏蔽)
        let default = (*XLMR_PROFILE).clone();
        LangConditionalThresholdProfile::new(default)
            // top 5 候选(v0.9 spike report §2)
            .with_override("it", PrivacyLabel::AccountNumber, 1.1) // -7 FP / 0 TP
            .with_override("de", PrivacyLabel::Person, 1.1)        // -5 FP / 0 TP
            .with_override("fr", PrivacyLabel::AccountNumber, 1.1) // -4 FP / 0 TP
            .with_override("de", PrivacyLabel::AccountNumber, 1.1) // -3 FP / 0 TP
            .with_override("en", PrivacyLabel::Person, 1.1)        // -3 FP / 0 TP
            // #6 Sprint 6 calibration(v0.10 spike Day 6+7 final verdict,commit 2abbdfc)
            // zh.spike_baseline 600 sample / 0 account_number truth(50 truth 全 split 入 heldout)/
            // 实测 -150 FP / 0 TP loss(xlmr 6 个 native PII labels — IDCARDNUM /
            // PASSPORTNUM / DRIVERLICENSENUM / CREDITCARDNUMBER / SOCIALNUM / TAXNUM —
            // 全 mapping canonical AccountNumber,zh 11-digit phone + 邮编 + 日期数字串
            // 被 model 误归)。silent-drop 不影响 ja/ru.account_number recall(per-(lang,label)
            // lookup 精准隔离)。来源:docs/operations/v0.10-sprint5-spike/day6-7-final-verdict.md
            .with_override("zh", PrivacyLabel::AccountNumber, 1.1) // -150 FP / 0 TP
    });

/// v0.7-α3 Phase 3 Design 核心 trait — 模型 ABI 边界抽象。
///
/// 实现者:
/// - 当前(v0.6 实施):[`OpenAIPrivacyFilterDescriptor`](见下)
/// - 未来(P3-spike):XLM-R PII / mT5 PII 实例
///
/// 实现要求:
/// - `Send + Sync`(可跨线程,与 `OrtEngine: Send + Sync` 对齐)
/// - 所有 method 是 cheap 不带 IO(只查内嵌静态表 / 字段)
/// - canonical_mapping 显式覆盖 id2label 全部元素(测试守门)
pub trait ModelDescriptor: Send + Sync {
    /// 模型唯一 id(如 `"openai-privacy-filter-v1"` / `"xlm-r-pii-v1"`);
    /// 用于 manifest selection 与 audit 关联。
    fn model_id(&self) -> &str;

    /// 语义化版本字符串(与 vigil-redaction crate 解耦);同 model_id 不同
    /// version 视为兼容升级,不同 model_id 视为独立模型。
    fn version(&self) -> &str;

    /// label-space-version:label 集合 + 字面量 + canonical_mapping 的版本;
    /// 任何变化即 breaking,触发启动失败(fail-fast,沿用 ADR 0012 模式)。
    fn label_space_version(&self) -> &str;

    /// 模型原生 id → 模型原生 label 字面量(BIOES 解码后的 core label);
    /// 例:OpenAI 33-class 完整 list(每元素是 `B-PRIVATE_PERSON` 解码后的
    /// `private_person`)。
    fn id2label(&self) -> &[&'static str];

    /// canonical_mapping:模型原生 label 字面量 → 8 类 PrivacyLabel。
    ///
    /// **强制覆盖**:[`id2label`](Self::id2label) 每元素经此函数应**显式**
    /// 返回 `Some(PrivacyLabel)` 或 `None`(显式忽略)。
    ///
    /// 返回 `None` 表示"模型识别出此类但 canonical 8 类无对应,主动忽略"
    /// (如某些模型有 `vehicle_id` / `medical_record_number` 等 PII 类,但
    /// canonical 8 类未涵盖,需显式忽略而非隐式漏)。
    fn canonical_mapping(&self, native_label: &str) -> Option<PrivacyLabel>;

    /// tokenizer 规范(嵌入式 vocab + post_processor 配置)。
    fn tokenizer_spec(&self) -> TokenizerSpec;

    /// post_processor:span 解码策略。
    fn post_processor(&self) -> PostProcessorKind;

    /// per-label 置信度阈值 profile;`None` = 默认(不调整)。
    fn threshold_profile(&self) -> Option<&ThresholdProfile> {
        None
    }

    /// **v0.9 Sprint 1 P1.2** — lang-conditional threshold profile(spike)。
    ///
    /// **default 实现**:返 `None`(走 [`Self::threshold_profile`] 兼容路径);
    /// **descriptor override**(目前仅 `XlmrPiiDescriptor`):返
    /// `Some(&XLMR_LANG_CONDITIONAL_PROFILE)`,让 OrtEngine.infer_with_lang 在
    /// `(lang, label)` 维度做精准 threshold 屏蔽。
    ///
    /// **优先级**(OrtEngine.infer_with_lang 实施):
    /// 1. `lang_conditional_profile().threshold_for(label, Some(lang))` 命中 override
    /// 2. fallback `lang_conditional_profile().default.thresholds.get(label)` 或
    ///    `threshold_profile().thresholds.get(label)`(若 lang_conditional 不存在)
    /// 3. 否则 None(模型默认 conf 阈值 0.0)
    ///
    /// **SemVer**:trait 加 default method 是兼容扩展;现有 descriptor 不 override
    /// 即走 `None`,等价 v0.8 行为。
    fn lang_conditional_profile(&self) -> Option<&LangConditionalThresholdProfile> {
        None
    }

    /// v0.7-α4 R1b(E6a)— ONNX 文件相对路径(从 model dir 起)。
    ///
    /// **背景**:不同模型仓库导出文件布局不同:
    /// - OpenAI Privacy Filter:`<dir>/model_q4f16.onnx`(顶层)
    /// - onnx-community/multilang-pii-ner-ONNX(xlmr):`<dir>/onnx/model_q4f16.onnx`
    /// - yonigo(optimum-cli 导出):`<dir>/model.onnx`(无 q4f16 后缀)
    ///
    /// 默认实现返 `"model_q4f16.onnx"`(OpenAI 兼容);新模型 descriptor override
    /// 此 method 即可适配自身布局,无需 symlink hack。
    ///
    /// **不变量**:相对路径 不带 leading `/`;[`crate::engine::OrtEngine::from_dir_with_descriptor`]
    /// 用 `dir.join(descriptor.onnx_filename())` 拼装。
    fn onnx_filename(&self) -> &str {
        "model_q4f16.onnx"
    }
}

// ─────────────────────────── OpenAI Privacy Filter v1 实例 ───────────────────────────
//
// 当前 v0.6 实施模型(`model_q4f16.onnx` + 33-class id2label)的 ModelDescriptor
// 实例化;验证设计可消费实际数据,同时保留作为 P3-spike 横向比较 baseline。

/// OpenAI Privacy Filter v1(33-class q4f16 ONNX)— v0.6 现行模型的 descriptor。
///
/// id2label 实参取自 `config.json` 解析(33 个 BIOES 解码后 core label);
/// canonical_mapping 沿用 [`PrivacyLabel::from_kind`] 的封闭映射逻辑。
#[derive(Debug)]
pub struct OpenAIPrivacyFilterDescriptor;

impl OpenAIPrivacyFilterDescriptor {
    /// 33 个 BIOES 解码后的 core label(去重去 BIOES 前缀)。
    /// 与 `engine.rs::parse_id2label` 的运行时解析口径对齐。
    ///
    /// 注:此处用 `&'static [&'static str]`,实际 id2label() 返回引用此表。
    /// 真实模型 id2label 含 BIOES 前缀(B-/I-/E-/S-/O-),但 ModelDescriptor
    /// trait 定义为 "post-BIOES core";已解码到核心 label 字面量。
    const NATIVE_LABELS: &'static [&'static str] = &[
        // PII 核心类(8 canonical 直接映射)
        "private_person",
        "private_email",
        "private_phone",
        "private_address",
        "private_date",
        "private_url",
        "private_account_number",
        // Secret 类(归并到 PrivacyLabel::Secret)
        "secret",
        // 兼容裸名(模型可能输出去前缀版本)
        "person",
        "email",
        "phone",
        "address",
        "date",
        "url",
        "account_number",
    ];
}

impl ModelDescriptor for OpenAIPrivacyFilterDescriptor {
    fn model_id(&self) -> &str {
        "openai-privacy-filter-v1"
    }

    fn version(&self) -> &str {
        // 与 bootstrap manifest version 字段保持解耦;此处是 descriptor 层的
        // 语义版本,改 canonical_mapping 即应 bump
        "1.0.0"
    }

    fn label_space_version(&self) -> &str {
        // canonical_mapping 集合 + 字面量稳定的版本号;
        // 任何 NATIVE_LABELS 增删 / canonical_mapping 改动 → 必 bump
        "8class-v1"
    }

    fn id2label(&self) -> &[&'static str] {
        Self::NATIVE_LABELS
    }

    fn canonical_mapping(&self, native_label: &str) -> Option<PrivacyLabel> {
        // SSOT:复用 PrivacyLabel::from_kind 的封闭映射;descriptor 层不重复
        // 字面量 match,避免 SSOT 漂移。
        //
        // OpenAI 模型 id2label 是大写如 "B-PRIVATE_PERSON",strip BIOES 后是
        // "PRIVATE_PERSON";PrivacyLabel::from_kind 期望 lowercase + 单下划线
        // 形态(`private_person`),因此先 normalize 再查。
        let normalized = native_label.to_lowercase().replace(['-', ' '], "_");
        PrivacyLabel::from_kind(&normalized).or_else(|| PrivacyLabel::from_kind(native_label))
    }

    fn tokenizer_spec(&self) -> TokenizerSpec {
        TokenizerSpec::HuggingFaceJson
    }

    fn post_processor(&self) -> PostProcessorKind {
        PostProcessorKind::Bioes
    }

    /// v0.7-α5 R1h+ 实验:OpenAI per-label threshold(实测**全部 setting 跌 recall**)
    ///
    /// **R1h+ 实验失败教训**(50-sample 实测):
    /// - 0.78 Person + 0.90 Address → recall 0.838(< 0.90)
    /// - 仅 0.85 Address → recall 0.865(仍 < 0.90)
    /// - **结论**:OpenAI Privacy Filter confidence 与 TP/FP **不可分离**,
    ///   conf-only threshold 必杀 TP,不能用作单维 FP filter
    ///
    /// **回归 R1h baseline**:OpenAI 不设 threshold profile(保 0.919 recall);
    /// 真做 FP 降需要 **cross-engine 双确认**(v0.7-α6+),conf-only filter 路径终止。
    fn threshold_profile(&self) -> Option<&ThresholdProfile> {
        None
    }
}

// ─────────────────────────── XLM-R PII v1 实例(spike-3 ensemble 验证)───────────────────────────
//
// 模型:onnx-community/multilang-pii-ner-ONNX(MIT, XLM-RoBERTa base 280M params)
// - 35 BIO labels(20 entity types + O):AGE/BUILDINGNUM/CITY/CREDITCARDNUMBER/DATE/
//   DRIVERLICENSENUM/EMAIL/GENDER/GIVENNAME/IDCARDNUM/PASSPORTNUM/SEX/SOCIALNUM/
//   STREET/SURNAME/TAXNUM/TELEPHONENUM/TIME/TITLE/ZIPCODE
// - 训练:ai4privacy/open-pii-masking-500k(token-key 风格,只标 entity 起始 token)
// - spike 实证:account/address/date 强(R 1.0),email/phone 弱(R 0)
// - canonical 8 类映射:6 类直达,2 类(secret/url)由 Hard rules 兜底,3 类显式 None

/// **v0.10 candidate F** — typed xlmr profile mode(替代裸 `VIGIL_XLMR_PROFILE` env)。
///
/// **触发**:Codex `019dfdab` 头脑风暴 F 决策点 + 用户拍板 — env-only 是 ops 配置层,
/// SDK consumer 需 reproducible / inspectable / 可进 DecisionRecord 的 typed config。
///
/// **设计纪律**:
/// - `#[non_exhaustive]`:未来扩 mode(如 `RecallFirst` / `MultiLangTuned`)不破 SemVer
/// - **Default = `Default`**:回归 v0.8 baseline 行为(EU recall 0.904)
/// - **opt-in `FpStrict`**:等价 `VIGIL_XLMR_PROFILE=fp_strict`(EU recall 0.887,
///   FP -22%,漏报 +45%)— 企业 / 高 FP 容忍度场景
/// - **typed 优先于 env**:`XlmrPiiDescriptor::with_mode(...)` 的 descriptor 实例
///   走 typed 路径,**不读 env**;legacy `XlmrPiiDescriptor::default()` 仍走
///   env-driven(零破坏过渡)
///
/// **SDK 暴露策略**(v0.10):
/// - `vigil-redaction::model_descriptor::XlmrProfileMode` 当前 v0.9 release 已 pub(本 commit)
/// - `vigil-sdk::XlmrProfileMode` re-export 推 v0.10 SDK trait/typed config 暴露 commit
///   (`scan_text_lang(text, lang)` 浅级 wrapper 一起做);触发 ADR 0015 § Phase 5
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum XlmrProfileMode {
    /// v0.8 baseline:屏蔽 Email/Phone/Address;Person 不屏蔽(EU recall 0.904)
    Default,
    /// v0.9 P0 opt-in:在 Default 基础上加 Person 1.1(EU recall 0.887,FP -22%,
    /// 漏报 +45% — 仅企业 / 高 FP-strict 偏好场景)
    FpStrict,
}

/// XLM-R PII v1(35 BIO labels)— spike-3 ensemble 候选模型 1。
///
/// **v0.10 candidate F**(本 commit):加 `mode: Option<XlmrProfileMode>` 字段
/// 支持 typed profile 选择(替代裸 env)。
/// - `XlmrPiiDescriptor::default()`(`mode: None`):**env-driven legacy 路径**
///   (`VIGIL_XLMR_PROFILE` env 选 default / fp_strict;v0.9 行为不变)
/// - `XlmrPiiDescriptor::with_mode(XlmrProfileMode::Default)`:typed default,**忽略 env**
/// - `XlmrPiiDescriptor::with_mode(XlmrProfileMode::FpStrict)`:typed fp_strict,**忽略 env**
///
/// **SemVer**:`unit struct → struct` 是 internal breaking,但 `XlmrPiiDescriptor`
/// 不在 vigil-sdk pub items,SDK consumer 不受影响;internal callers(vigil-firewall /
/// r1_ensemble_e2e)已同步改为 `::default()`(本 commit)。
#[derive(Debug, Default, Clone, Copy)]
pub struct XlmrPiiDescriptor {
    /// Some(_) → typed 路径(忽略 env);None → env-driven legacy(v0.9 默认行为)
    mode: Option<XlmrProfileMode>,
}

impl XlmrPiiDescriptor {
    /// **v0.10 candidate F**(本 commit)— typed mode 构造。
    ///
    /// 与 [`Self::default`] 区别:typed 路径**忽略** `VIGIL_XLMR_PROFILE` env;
    /// caller 显式选 mode(reproducible / inspectable / SDK-friendly)。
    pub const fn with_mode(mode: XlmrProfileMode) -> Self {
        Self { mode: Some(mode) }
    }
}

impl XlmrPiiDescriptor {
    /// 20 entity types(去 BIOES 前缀核 label),与远程 model_descriptor.json 对齐
    const NATIVE_LABELS: &'static [&'static str] = &[
        // PII 直达 canonical
        "GIVENNAME",
        "SURNAME",
        "TITLE",        // → person
        "EMAIL",        // → email
        "TELEPHONENUM", // → phone
        "STREET",
        "BUILDINGNUM",
        "CITY",
        "ZIPCODE", // → address
        "DATE",
        "TIME", // → date
        "IDCARDNUM",
        "PASSPORTNUM",
        "DRIVERLICENSENUM",
        "CREDITCARDNUMBER",
        "SOCIALNUM",
        "TAXNUM", // → account_number
        // 显式 None(canonical 8 类未覆盖)
        "AGE",
        "GENDER",
        "SEX",
    ];
}

impl ModelDescriptor for XlmrPiiDescriptor {
    fn model_id(&self) -> &str {
        "xlmr-pii-v1"
    }
    fn version(&self) -> &str {
        "1.0.0"
    }
    fn label_space_version(&self) -> &str {
        "8class-v1"
    }
    fn id2label(&self) -> &[&'static str] {
        Self::NATIVE_LABELS
    }

    fn canonical_mapping(&self, native_label: &str) -> Option<PrivacyLabel> {
        match native_label {
            // person 类
            "GIVENNAME" | "SURNAME" | "TITLE" => Some(PrivacyLabel::Person),
            // email
            "EMAIL" => Some(PrivacyLabel::Email),
            // phone
            "TELEPHONENUM" => Some(PrivacyLabel::Phone),
            // address(4 native → 1 canonical)
            "STREET" | "BUILDINGNUM" | "CITY" | "ZIPCODE" => Some(PrivacyLabel::Address),
            // date(2 native → 1 canonical)
            "DATE" | "TIME" => Some(PrivacyLabel::Date),
            // account_number(6 native → 1 canonical)
            "IDCARDNUM" | "PASSPORTNUM" | "DRIVERLICENSENUM" | "CREDITCARDNUMBER" | "SOCIALNUM"
            | "TAXNUM" => Some(PrivacyLabel::AccountNumber),
            // 显式忽略(canonical 8 类未覆盖)
            "AGE" | "GENDER" | "SEX" => None,
            // 其余未知 native → fall-through panic 由测试守门捕获
            _ => None,
        }
    }

    fn tokenizer_spec(&self) -> TokenizerSpec {
        TokenizerSpec::HuggingFaceJson
    }
    fn post_processor(&self) -> PostProcessorKind {
        PostProcessorKind::Bio
    }

    /// xlmr 仓库 onnx 在 `onnx/` 子目录(R1 用 symlink 绕过,R1b 正式适配)
    fn onnx_filename(&self) -> &str {
        "onnx/model_q4f16.onnx"
    }

    /// v0.7-α4 R1h + v0.9 Sprint 0 P0 + **v0.10 candidate F** — typed mode 优先 / env fallback。
    ///
    /// 优先级:
    /// 1. `self.mode = Some(XlmrProfileMode::Default)` → `&XLMR_PROFILE`(v0.8 baseline)
    /// 2. `self.mode = Some(XlmrProfileMode::FpStrict)` → `&XLMR_PROFILE_FP_STRICT`
    /// 3. `self.mode = None`(legacy `Default::default()`)→ `xlmr_profile_from_env()`
    ///    (env-driven;`VIGIL_XLMR_PROFILE=fp_strict` 触发,其他值/未设走 default)
    ///
    /// **典型用法**:
    /// - SDK consumer(reproducible):`XlmrPiiDescriptor::with_mode(XlmrProfileMode::Default)`
    /// - ops 配置层(env):`XlmrPiiDescriptor::default()` + `VIGIL_XLMR_PROFILE` env
    fn threshold_profile(&self) -> Option<&ThresholdProfile> {
        let profile = match self.mode {
            Some(XlmrProfileMode::Default) => &*XLMR_PROFILE,
            Some(XlmrProfileMode::FpStrict) => &*XLMR_PROFILE_FP_STRICT,
            None => xlmr_profile_from_env(),
        };
        Some(profile)
    }

    /// **v0.9 Sprint 1 P1.2** — xlmr lang-conditional threshold profile。
    ///
    /// 暴露 [`XLMR_LANG_CONDITIONAL_PROFILE`](top 5 候选 -22 FP / 0 TP loss
    /// 理想;数据源 `docs/operations/v0.9-sprint1/p1_spike-candidates-92.md`)。
    /// OrtEngine.infer_with_lang 优先查此 profile,fallback `threshold_profile()`。
    ///
    /// **lang 路径不影响 default 路径**:caller 不调用 `scan_text_with_engine_with_lang`
    /// → OrtEngine 走 `infer()` → 用 `threshold_profile()`(env-driven default 或
    /// fp_strict)— v0.8 baseline / v0.9 P0 opt-in 行为不变。
    fn lang_conditional_profile(&self) -> Option<&LangConditionalThresholdProfile> {
        Some(&XLMR_LANG_CONDITIONAL_PROFILE)
    }
}

/// xlmr R1h threshold profile —— FP 诊断驱动(default,v0.8 baseline)。
/// > 1.0 等价"永远丢该 label"(留给互补 engine + Hard rules 兜底)。
///
/// **历史 + v0.8 Person 实验决议**:
/// - R1h(v0.7-α4):Email/Phone/Address 完全屏蔽(0 TP / 全 FP 或显著互补 dominant)
/// - R1h+(v0.7-α5):Person 0.78 conf-only 实验 FAIL — 撤回
/// - **v0.8 Sprint 4 followup**(P2.1 §5.3 Codex 019deb53 Suggestion):试 Person 1.1
///   完全屏蔽,**实测 FAIL** — 92-sample 真跑数据驱动:
///   baseline:EU recall 0.904 / FP 59 / TP 104 / FN 11
///   Person blocked:EU recall **0.887**(-0.017)/ FP 46(-13)/ TP **102**(-3)/ FN **16**(+5)
///   xlmr person 11 TP 中 3 个是 **openai 没覆盖的独立 TP**(互补关系),非冗余;
///   FP 收益 -22% 但漏报 +23%,trade-off 与 dual_confirm date 实验**同负向口径**。
/// - **default 决议**:Person 不在 profile;**v0.9 Sprint 0 P0**:opt-in
///   fp_strict 模式作 alternative profile 暴露(见 [`XLMR_PROFILE_FP_STRICT`])。
static XLMR_PROFILE: once_cell::sync::Lazy<ThresholdProfile> = once_cell::sync::Lazy::new(|| {
    use std::collections::BTreeMap;
    let mut t = BTreeMap::new();
    // 全 FP / 0 TP — 完全屏蔽(yonigo email 主导)
    t.insert(PrivacyLabel::Email, 1.1_f32);
    // FP/TP 6:1 — 屏蔽(yonigo phone 主导)
    t.insert(PrivacyLabel::Phone, 1.1_f32);
    // FP/TP 16:3 — 屏蔽(openai address 主导)
    t.insert(PrivacyLabel::Address, 1.1_f32);
    // Person 不加(v0.8 Sprint 4 followup 实测 FAIL — 互补 TP 砍不得;
    // 详见上方 历史 + v0.8 Person 实验决议)
    ThresholdProfile { thresholds: t }
});

/// **v0.9 Sprint 0 P0 opt-in fp_strict profile**(企业 / 高 FP 容忍度场景)。
///
/// 在 [`XLMR_PROFILE`] 默认基础上**加 Person: 1.1**(完全屏蔽 xlmr person)。
///
/// **触发**:`VIGIL_XLMR_PROFILE=fp_strict` env 启用;默认值或其他值走
/// [`XLMR_PROFILE`](保持 v0.8 baseline)。
///
/// **trade-off**(v0.8 Sprint 4 followup 92-sample 实测,Codex 019deb45 closure):
///   baseline:EU recall 0.904 / FP 59 / TP 104 / FN 11
///   fp_strict: EU recall 0.887(-0.017)/ FP 46(-13,**-22%**)/ TP 102(-2)/ FN 16(+5)
///
/// **适用场景**(Codex closure 推荐):企业要求每 finding 强 precision,接受
/// 1.7% recall 代价换 22% FP 减少。**不应作 v0.8/v0.9 默认**(Vigil mission
/// 防漏报为主)— 仅 opt-in 可见。
///
/// **不变量**:fp_strict ⊃ default(default 屏蔽全部 + Person);default path
/// 任何变更必须同步 fp_strict(守门测试断言此包含关系)。
static XLMR_PROFILE_FP_STRICT: once_cell::sync::Lazy<ThresholdProfile> =
    once_cell::sync::Lazy::new(|| {
        use std::collections::BTreeMap;
        let mut t = BTreeMap::new();
        // default 路径同步(必须保持与 XLMR_PROFILE 一致)
        t.insert(PrivacyLabel::Email, 1.1_f32);
        t.insert(PrivacyLabel::Phone, 1.1_f32);
        t.insert(PrivacyLabel::Address, 1.1_f32);
        // **fp_strict 增量**:Person 1.1 屏蔽 — 接受 -1.7% recall 换 -22% FP
        t.insert(PrivacyLabel::Person, 1.1_f32);
        ThresholdProfile { thresholds: t }
    });

/// **v0.9 Sprint 0 P0** — env-driven profile 选择(default / fp_strict)。
///
/// 解析 `VIGIL_XLMR_PROFILE` env:
/// - `"fp_strict"` → [`XLMR_PROFILE_FP_STRICT`](opt-in 高 FP-strict 模式)
/// - 其他任何值 / 未设置 → [`XLMR_PROFILE`](v0.8 default baseline)
///
/// **容错**:unknown 值(如 `"strict"` / `"FP_STRICT"` 大小写差异 / 任意 garbage)
/// 一律 fallback default — fail-safe 不破默认安全路径。
fn xlmr_profile_from_env() -> &'static ThresholdProfile {
    match std::env::var("VIGIL_XLMR_PROFILE").as_deref() {
        Ok("fp_strict") => &XLMR_PROFILE_FP_STRICT,
        // 其他值或 env 未设 → default
        _ => &XLMR_PROFILE,
    }
}

// ─────────────────────────── Yonigo DistilmBERT PII v1 实例(spike-3 ensemble 候选 2)───────────────────────────
//
// 模型:yonigo/distilbert-base-multilingual-cased-pii(Apache 2.0, DistilmBERT 100M)
// - 57 BIO labels(28 entity types + O):BOD/BUILDING/CARDISSUER/CITY/COUNTRY/
//   DATE/DRIVERLICENSE/EMAIL/GEOCOORD/GIVENNAME1-2/IDCARD/IP/LASTNAME1-3/PASS/
//   PASSPORT/POSTCODE/SECADDRESS/SEX/SOCIALNUMBER/STATE/STREET/TEL/TIME/TITLE/USERNAME
// - 训练:ai4privacy/pii-masking-300k(character-span 标注,与 spike-1 不同)
// - spike 实证:email/phone 强(R 1.0/0.67),person 弱(R 0)— 与 xlmr 互补
// - canonical 8 类:6 类直达 + IP→Url + PASS→Secret + 2 类显式 None(SEX/USERNAME)

/// Yonigo DistilmBERT PII v1(57 BIO labels)— spike-3 ensemble 候选模型 2。
#[derive(Debug)]
pub struct YonigoPiiDescriptor;

impl YonigoPiiDescriptor {
    /// 28 entity types,与远程 model-yonigo/config.json 对齐
    const NATIVE_LABELS: &'static [&'static str] = &[
        // person 类(6 native → person)
        "GIVENNAME1",
        "GIVENNAME2",
        "LASTNAME1",
        "LASTNAME2",
        "LASTNAME3",
        "TITLE",
        // 直达
        "EMAIL",
        "TEL",
        // address(8 native → address)
        "BUILDING",
        "CITY",
        "COUNTRY",
        "GEOCOORD",
        "POSTCODE",
        "SECADDRESS",
        "STATE",
        "STREET",
        // date(3 native → date,BOD = birth date)
        "DATE",
        "TIME",
        "BOD",
        // account_number(5 native → account_number)
        "IDCARD",
        "PASSPORT",
        "DRIVERLICENSE",
        "SOCIALNUMBER",
        "CARDISSUER",
        // 跨 canonical 类
        "IP",   // → url
        "PASS", // → secret(password)
        // 显式 None
        "SEX",
        "USERNAME",
    ];
}

impl ModelDescriptor for YonigoPiiDescriptor {
    fn model_id(&self) -> &str {
        "yonigo-pii-v1"
    }
    fn version(&self) -> &str {
        "1.0.0"
    }
    fn label_space_version(&self) -> &str {
        "8class-v1"
    }
    fn id2label(&self) -> &[&'static str] {
        Self::NATIVE_LABELS
    }

    fn canonical_mapping(&self, native_label: &str) -> Option<PrivacyLabel> {
        match native_label {
            // person(6 native → person;GIVENNAME1/2 + LASTNAME1/2/3 + TITLE)
            "GIVENNAME1" | "GIVENNAME2" | "LASTNAME1" | "LASTNAME2" | "LASTNAME3" | "TITLE" => {
                Some(PrivacyLabel::Person)
            }
            // email
            "EMAIL" => Some(PrivacyLabel::Email),
            // phone(注:yonigo 命名是 TEL 不是 TELEPHONENUM)
            "TEL" => Some(PrivacyLabel::Phone),
            // address(8 native → address)
            "BUILDING" | "CITY" | "COUNTRY" | "GEOCOORD" | "POSTCODE" | "SECADDRESS" | "STATE"
            | "STREET" => Some(PrivacyLabel::Address),
            // date(3 native → date)
            "DATE" | "TIME" | "BOD" => Some(PrivacyLabel::Date),
            // account_number(5 native)
            "IDCARD" | "PASSPORT" | "DRIVERLICENSE" | "SOCIALNUMBER" | "CARDISSUER" => {
                Some(PrivacyLabel::AccountNumber)
            }
            // url(yonigo 唯一有 IP 类的模型)
            "IP" => Some(PrivacyLabel::Url),
            // secret(yonigo 唯一有 PASS 类的模型;password 是凭证类)
            "PASS" => Some(PrivacyLabel::Secret),
            // 显式 None(canonical 8 类未覆盖;SEX/USERNAME)
            "SEX" | "USERNAME" => None,
            _ => None,
        }
    }

    fn tokenizer_spec(&self) -> TokenizerSpec {
        TokenizerSpec::HuggingFaceJson
    }
    fn post_processor(&self) -> PostProcessorKind {
        PostProcessorKind::Bio
    }

    /// yonigo optimum-cli 导出无 q4f16 后缀(R1 用 symlink 绕过,R1b 正式适配)
    fn onnx_filename(&self) -> &str {
        "model.onnx"
    }

    /// v0.7-α4 R1h:yonigo per-label threshold(R1h FP 诊断驱动)。
    /// 50-sample fixture 实测:address 2/6(FP 主)/ person 0/1 / account 0/2 失衡。
    /// 屏蔽 address/person/account(留 openai+xlmr+Hard);
    /// email/phone(yonigo 强项)不调整。
    fn threshold_profile(&self) -> Option<&ThresholdProfile> {
        Some(&YONIGO_PROFILE)
    }
}

static YONIGO_PROFILE: once_cell::sync::Lazy<ThresholdProfile> = once_cell::sync::Lazy::new(|| {
    use std::collections::BTreeMap;
    let mut t = BTreeMap::new();
    // 全 FP / 0 TP — 屏蔽
    t.insert(PrivacyLabel::Person, 1.1_f32);
    // FP/TP 2:0 — 屏蔽(xlmr account 主导)
    t.insert(PrivacyLabel::AccountNumber, 1.1_f32);
    // FP/TP 6:2 — 屏蔽(openai address 主导)
    t.insert(PrivacyLabel::Address, 1.1_f32);
    ThresholdProfile { thresholds: t }
});

// ─────────────────────────── 守门工具 ───────────────────────────

/// canonical mapping 全覆盖断言:遍历 descriptor.id2label() 每元素,
/// 验证 canonical_mapping() 返回 `Some` 或者元素在 `expected_unmapped` 列表中
/// (显式忽略名单)。
///
/// **用途**:测试守门 — 给每个新 [`ModelDescriptor`] 实现写一条这种断言,
/// 在 unit test 阶段拒绝隐式 label 遗漏。
///
/// # Panics
/// 当某元素既不在 canonical_mapping 也不在 expected_unmapped 中,panic 列出
/// 缺失项。
#[cfg(test)]
pub(crate) fn assert_canonical_mapping_total<D: ModelDescriptor>(
    descriptor: &D,
    expected_unmapped: &[&str],
) {
    let mut missing: Vec<&str> = Vec::new();
    for &native in descriptor.id2label() {
        let mapped = descriptor.canonical_mapping(native);
        if mapped.is_none() && !expected_unmapped.contains(&native) {
            missing.push(native);
        }
    }
    assert!(
        missing.is_empty(),
        "ModelDescriptor[{}] canonical_mapping 隐式遗漏 native labels: {:?}\n\
         (修复:在 canonical_mapping 加映射,或加入 expected_unmapped 显式忽略名单)",
        descriptor.model_id(),
        missing
    );
}

// ─────────────────────────── 单测 ───────────────────────────

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    /// trait API 编译期可消费(基础 sanity)
    #[test]
    fn descriptor_trait_compiles_and_basic_fields() {
        let d = OpenAIPrivacyFilterDescriptor;
        assert_eq!(d.model_id(), "openai-privacy-filter-v1");
        assert_eq!(d.version(), "1.0.0");
        assert_eq!(d.label_space_version(), "8class-v1");
        assert_eq!(d.tokenizer_spec(), TokenizerSpec::HuggingFaceJson);
        assert_eq!(d.post_processor(), PostProcessorKind::Bioes);
        // R1h+ 实验后 OpenAI 撤回 threshold(conf-only filter 不可分离 TP/FP)
        assert!(
            d.threshold_profile().is_none(),
            "R1h+ verdict:OpenAI 不调 threshold(留 v0.6 baseline,推 v0.7-α6+ cross-engine)"
        );
    }

    /// canonical mapping 全覆盖断言(本 ADR 0017 § 2.2 强制不变量)。
    /// 隐式漏 label 即 fail。
    #[test]
    fn openai_descriptor_canonical_mapping_total() {
        // 当前 OpenAI Privacy Filter NATIVE_LABELS 全部应可 canonical 映射
        // (由 PrivacyLabel::from_kind 的封闭集合保证)
        assert_canonical_mapping_total(&OpenAIPrivacyFilterDescriptor, &[]);
    }

    /// 验证 PrivacyLabel::ALL 8 类全部被 OpenAI descriptor 覆盖至少一次
    /// (没有 canonical 类被孤立)
    #[test]
    fn openai_descriptor_covers_all_8_canonical_labels() {
        let d = OpenAIPrivacyFilterDescriptor;
        let mut covered: Vec<PrivacyLabel> = Vec::new();
        for &native in d.id2label() {
            if let Some(label) = d.canonical_mapping(native) {
                if !covered.contains(&label) {
                    covered.push(label);
                }
            }
        }
        for &expected in PrivacyLabel::ALL.iter() {
            assert!(
                covered.contains(&expected),
                "OpenAI descriptor 未覆盖 canonical label {:?}",
                expected
            );
        }
    }

    /// label_space_version 形式守门:必须含 "vN" 后缀(版本可解析)。
    /// 防 descriptor 升级时忘 bump。
    #[test]
    fn label_space_version_has_version_suffix() {
        let v = OpenAIPrivacyFilterDescriptor.label_space_version();
        assert!(
            v.contains("v1") || v.contains("v2") || v.contains("v3"),
            "label_space_version '{}' 应含 vN 后缀",
            v
        );
    }

    /// 编译期守门:OpenAIPrivacyFilterDescriptor 是 Send + Sync(trait bound 强制)。
    /// 不需要运行时,放心交给多线程使用。
    #[test]
    fn descriptor_is_send_sync() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<OpenAIPrivacyFilterDescriptor>();
    }

    /// trait object 可拼可调度(防 dyn-compat 漂移)
    #[test]
    fn descriptor_is_dyn_compatible() {
        let d: Box<dyn ModelDescriptor> = Box::new(OpenAIPrivacyFilterDescriptor);
        assert_eq!(d.model_id(), "openai-privacy-filter-v1");
    }

    // ─────────── E6a S1: XlmrPiiDescriptor / YonigoPiiDescriptor 守门 ───────────

    /// XlmrPiiDescriptor 基础字段 + post_processor = Bio
    #[test]
    fn xlmr_descriptor_basic_fields() {
        let d = XlmrPiiDescriptor::default();
        assert_eq!(d.model_id(), "xlmr-pii-v1");
        assert_eq!(d.version(), "1.0.0");
        assert_eq!(d.label_space_version(), "8class-v1");
        assert_eq!(
            d.post_processor(),
            PostProcessorKind::Bio,
            "xlmr 是 BIO scheme(spike-1 实证)"
        );
    }

    /// XlmrPiiDescriptor canonical mapping 全覆盖(隐式遗漏 fail)
    #[test]
    fn xlmr_descriptor_canonical_mapping_total() {
        // AGE/GENDER/SEX 显式忽略(canonical 8 类不覆盖)
        assert_canonical_mapping_total(&XlmrPiiDescriptor::default(), &["AGE", "GENDER", "SEX"]);
    }

    /// XlmrPiiDescriptor 直接覆盖 6/8 canonical(剩 url/secret 由 Hard rules 兜底)
    #[test]
    fn xlmr_descriptor_covers_6_of_8_canonical() {
        let d = XlmrPiiDescriptor::default();
        let mut covered: Vec<PrivacyLabel> = Vec::new();
        for &native in d.id2label() {
            if let Some(label) = d.canonical_mapping(native) {
                if !covered.contains(&label) {
                    covered.push(label);
                }
            }
        }
        // 6 类直达 + 2 类(Url/Secret)由 Hard rules 兜底,不应在 xlmr 直接覆盖
        let expected_covered = [
            PrivacyLabel::Person,
            PrivacyLabel::Email,
            PrivacyLabel::Phone,
            PrivacyLabel::Address,
            PrivacyLabel::Date,
            PrivacyLabel::AccountNumber,
        ];
        for label in expected_covered {
            assert!(covered.contains(&label), "xlmr 应覆盖 {:?}", label);
        }
        assert!(
            !covered.contains(&PrivacyLabel::Url),
            "xlmr 不应直接覆盖 Url(Hard rules 兜底)"
        );
        assert!(
            !covered.contains(&PrivacyLabel::Secret),
            "xlmr 不应直接覆盖 Secret(Hard rules 兜底)"
        );
    }

    /// YonigoPiiDescriptor 基础字段 + post_processor = Bio
    #[test]
    fn yonigo_descriptor_basic_fields() {
        let d = YonigoPiiDescriptor;
        assert_eq!(d.model_id(), "yonigo-pii-v1");
        assert_eq!(d.version(), "1.0.0");
        assert_eq!(d.label_space_version(), "8class-v1");
        assert_eq!(d.post_processor(), PostProcessorKind::Bio);
    }

    /// YonigoPiiDescriptor canonical mapping 全覆盖(SEX/USERNAME 显式忽略)
    #[test]
    fn yonigo_descriptor_canonical_mapping_total() {
        assert_canonical_mapping_total(&YonigoPiiDescriptor, &["SEX", "USERNAME"]);
    }

    /// YonigoPiiDescriptor 覆盖 8/8 canonical(IP→Url + PASS→Secret 双独家 native)
    #[test]
    fn yonigo_descriptor_covers_all_8_canonical_via_ip_pass() {
        let d = YonigoPiiDescriptor;
        let mut covered: Vec<PrivacyLabel> = Vec::new();
        for &native in d.id2label() {
            if let Some(label) = d.canonical_mapping(native) {
                if !covered.contains(&label) {
                    covered.push(label);
                }
            }
        }
        // yonigo 是唯一覆盖 Url + Secret native 的 model
        for label in PrivacyLabel::ALL {
            assert!(
                covered.contains(&label),
                "yonigo 应覆盖 canonical {:?}(IP→Url, PASS→Secret 是 yonigo 独家)",
                label
            );
        }
    }

    /// 三 descriptor 在同 fixture 上的 trait object polymorphism 编译验证
    #[test]
    fn three_descriptors_dyn_compatible_collection() {
        let descriptors: Vec<Box<dyn ModelDescriptor>> = vec![
            Box::new(OpenAIPrivacyFilterDescriptor),
            Box::new(XlmrPiiDescriptor::default()),
            Box::new(YonigoPiiDescriptor),
        ];
        let ids: Vec<&str> = descriptors.iter().map(|d| d.model_id()).collect();
        assert_eq!(ids.len(), 3);
        // 三 model_id 必互异(防止意外重命名碰撞)
        let mut sorted = ids.clone();
        sorted.sort();
        sorted.dedup();
        assert_eq!(sorted.len(), 3, "三 descriptor model_id 必互异");
    }

    /// 编译期守门:三 descriptor 都是 Send + Sync
    #[test]
    fn all_descriptors_send_sync() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<OpenAIPrivacyFilterDescriptor>();
        assert_send_sync::<XlmrPiiDescriptor>();
        assert_send_sync::<YonigoPiiDescriptor>();
    }

    /// PostProcessorKind::Bio variant 可用 + dispatch 编译期可见
    #[test]
    fn post_processor_bio_variant_visible() {
        let openai = OpenAIPrivacyFilterDescriptor.post_processor();
        let xlmr = XlmrPiiDescriptor::default().post_processor();
        let yonigo = YonigoPiiDescriptor.post_processor();
        assert!(matches!(openai, PostProcessorKind::Bioes));
        assert!(matches!(xlmr, PostProcessorKind::Bio));
        assert!(matches!(yonigo, PostProcessorKind::Bio));
    }

    // ─── v0.7-α4 R1b 守门:onnx_filename() default + override ───

    /// 三 descriptor onnx_filename 各自正确(对齐 R1 实测远程文件布局)
    #[test]
    fn descriptors_onnx_filename_match_layout() {
        assert_eq!(
            OpenAIPrivacyFilterDescriptor.onnx_filename(),
            "model_q4f16.onnx",
            "OpenAI default 路径"
        );
        assert_eq!(
            XlmrPiiDescriptor::default().onnx_filename(),
            "onnx/model_q4f16.onnx",
            "xlmr 在 onnx/ 子目录(onnx-community/multilang-pii-ner-ONNX 仓库布局)"
        );
        assert_eq!(
            YonigoPiiDescriptor.onnx_filename(),
            "model.onnx",
            "yonigo optimum-cli 导出无 q4f16 后缀"
        );
    }

    /// onnx_filename 不带 leading `/`(相对路径,from_dir_with_descriptor 用 dir.join 拼接)
    #[test]
    fn descriptors_onnx_filename_relative_path_invariant() {
        for d in [
            &OpenAIPrivacyFilterDescriptor as &dyn ModelDescriptor,
            &XlmrPiiDescriptor::default(),
            &YonigoPiiDescriptor,
        ] {
            let f = d.onnx_filename();
            assert!(
                !f.starts_with('/'),
                "onnx_filename 必相对(不带 leading /),实际 '{}' for {}",
                f,
                d.model_id()
            );
            assert!(f.ends_with(".onnx"), "应以 .onnx 结尾: '{}'", f);
        }
    }

    // ─── v0.7-α4 R1h 守门:per-engine threshold profile ───

    /// xlmr threshold profile 屏蔽 Email/Phone/Address(R1h FP 诊断驱动)
    #[test]
    fn xlmr_threshold_profile_masks_high_fp_labels() {
        let d = XlmrPiiDescriptor::default();
        let profile = d.threshold_profile().expect("xlmr 应有 threshold profile");
        // 这 3 类阈值 > 1.0 等价禁用(R1h FP 诊断:address 16/3 / phone 6/1 / email 0/4)
        for label in [
            PrivacyLabel::Email,
            PrivacyLabel::Phone,
            PrivacyLabel::Address,
        ] {
            let t = profile.thresholds.get(&label).copied().unwrap_or(0.0_f32);
            assert!(
                t > 1.0,
                "xlmr {:?} threshold 应 > 1.0(屏蔽),实际 {}",
                label,
                t
            );
        }
        // v0.7-α5 R1h+ 加 Person 0.78(原 R1h 不调,现追加);Date 仍不调
        assert!(!profile.thresholds.contains_key(&PrivacyLabel::Date));
        // Person 现在 profile 中(R1h+ 后),具体期望由 r1h_plus 测试核对
    }

    /// yonigo threshold profile 屏蔽 Person/AccountNumber/Address
    #[test]
    fn yonigo_threshold_profile_masks_high_fp_labels() {
        let d = YonigoPiiDescriptor;
        let profile = d
            .threshold_profile()
            .expect("yonigo 应有 threshold profile");
        for label in [
            PrivacyLabel::Person,
            PrivacyLabel::AccountNumber,
            PrivacyLabel::Address,
        ] {
            let t = profile.thresholds.get(&label).copied().unwrap_or(0.0_f32);
            assert!(t > 1.0, "yonigo {:?} threshold 应 > 1.0,实际 {}", label, t);
        }
        // Email / Phone 是 yonigo 强项,不屏蔽
        assert!(!profile.thresholds.contains_key(&PrivacyLabel::Email));
        assert!(!profile.thresholds.contains_key(&PrivacyLabel::Phone));
    }

    /// v0.7-α5 R1h+ verdict:OpenAI conf-only threshold **实验失败**,不应有 profile
    ///
    /// 教训:OpenAI Privacy Filter confidence 与 TP/FP 分布不可分离;0.78/0.85/0.90
    /// 都 wipe TP 致 recall < 0.90;真 FP 降需 v0.7-α6+ cross-engine 双确认。
    #[test]
    fn openai_no_threshold_profile_r1h_plus_verdict() {
        assert!(
            OpenAIPrivacyFilterDescriptor.threshold_profile().is_none(),
            "R1h+ 实验后 OpenAI 撤回所有 threshold(conf-only filter 路径终止)"
        );
    }

    /// v0.7-α5 R1h+ 撤回 + v0.8 Sprint 4 followup 实测 FAIL 双重撤回。
    ///
    /// 历史辨析(为何 Person 不在 profile):
    /// - R1h+(v0.7-α5):Person 0.78 conf-only 实测 FAIL(recall 跌)— **撤回**
    /// - v0.8 Sprint 4 followup(P2.1 §5.3 Codex 019deb53 Suggestion):试 Person 1.1
    ///   完全屏蔽,**92-sample 真跑实测 FAIL**:
    ///   - EU recall 0.904 → 0.887 (-0.017)
    ///   - EU TP 104 → 102 (-2,xlmr 独立 person TP 砍掉 2 个)
    ///   - EU FP 59 → 46 (-13,FP 收益)
    ///   - EU FN 11 → 16 (+5,**漏报 +45%**)
    ///
    ///   trade-off 与 dual_confirm date 实验同负向口径;ensemble engines 互补关系
    ///   再次显现(`feedback_ensemble_complementary`)— xlmr person 真有 openai 没覆盖
    ///   的独立 TP,屏蔽即砍互补。
    ///
    /// **决议**:Email/Phone/Address 屏蔽不变;Person **不**加 default profile。
    /// 直接验 XLMR_PROFILE static(不受 VIGIL_XLMR_PROFILE env 影响)。
    #[test]
    fn xlmr_default_profile_blocks_email_phone_address_only() {
        let profile = &*XLMR_PROFILE;
        // R1h 屏蔽 3 label 不变(> 1.0;留给 openai/yonigo + Hard rules 兜底)
        for lbl in [
            PrivacyLabel::Email,
            PrivacyLabel::Phone,
            PrivacyLabel::Address,
        ] {
            let t = profile.thresholds.get(&lbl).copied().unwrap_or(0.0);
            assert!(t > 1.0, "xlmr {:?} 应屏蔽 (> 1.0),实际 {}", lbl, t);
        }
        // Person 不在 default profile(R1h+ 撤回 0.78 + v0.8 Sprint 4 撤回 1.1 双重数据驱动决议)
        assert!(
            !profile.thresholds.contains_key(&PrivacyLabel::Person),
            "xlmr Person 不应在 default profile — v0.9 Sprint 0 P0 已把 1.1 包成 opt-in fp_strict;\
             default path 保持 v0.8 baseline(EU recall 0.904)"
        );
    }

    // ─── v0.9 Sprint 0 P0 — opt-in fp_strict profile 守门 ───

    /// fp_strict profile 必须 ⊃ default(包含 default 全 3 label + 加 Person)。
    /// 防 default 演进时 fp_strict 漂移(必须同步加 label)。
    #[test]
    fn xlmr_fp_strict_profile_is_superset_of_default_plus_person() {
        let default_profile = &*XLMR_PROFILE;
        let fp_strict_profile = &*XLMR_PROFILE_FP_STRICT;

        // fp_strict ⊃ default(default 每 label 必在 fp_strict 同值)
        for (lbl, default_t) in &default_profile.thresholds {
            let strict_t = fp_strict_profile
                .thresholds
                .get(lbl)
                .copied()
                .unwrap_or(0.0);
            assert!(
                (strict_t - *default_t).abs() < 1e-6,
                "fp_strict 必须包含 default 的 {:?}(threshold {} 应等于 default {})",
                lbl,
                strict_t,
                default_t
            );
        }

        // fp_strict 增量:Person 1.1 屏蔽
        let person_t = fp_strict_profile
            .thresholds
            .get(&PrivacyLabel::Person)
            .copied()
            .unwrap_or(0.0);
        assert!(
            person_t > 1.0,
            "fp_strict Person 应屏蔽 (> 1.0,实际 {})",
            person_t
        );

        // 大小:fp_strict = default + 1
        assert_eq!(
            fp_strict_profile.thresholds.len(),
            default_profile.thresholds.len() + 1,
            "fp_strict label 数应 = default + 1(加 Person)"
        );
    }

    /// **env 测试串行锁**(P1.3 fix 加):set/unset env 全局 mutate,
    /// `cargo test` 默认并发会让多 env-touching 测试相互污染(workspace 实测
    /// `lang_conditional_default_independent_of_env` 与本测试并发 fail)。
    /// 用 static Mutex 强制串行,**不**用 `serial_test` crate(避免新依赖)。
    static ENV_TEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    /// `xlmr_profile_from_env` 解析守门:fp_strict 切到 strict profile,
    /// 其他值 / 未设全部 fallback default(unknown 容错 fail-safe)。
    ///
    /// **并发安全**:用 ENV_TEST_LOCK 串行;测试结束 unset 恢复初值。
    #[test]
    fn xlmr_profile_from_env_select_and_fallback() {
        let _guard = ENV_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        // 保存原值(若有)恢复
        let original = std::env::var("VIGIL_XLMR_PROFILE").ok();
        let restore = || match &original {
            Some(v) => std::env::set_var("VIGIL_XLMR_PROFILE", v),
            None => std::env::remove_var("VIGIL_XLMR_PROFILE"),
        };

        // 1. unset → default
        std::env::remove_var("VIGIL_XLMR_PROFILE");
        let p = xlmr_profile_from_env();
        assert!(
            !p.thresholds.contains_key(&PrivacyLabel::Person),
            "unset env → default(Person 不屏蔽)"
        );

        // 2. fp_strict → fp_strict profile
        std::env::set_var("VIGIL_XLMR_PROFILE", "fp_strict");
        let p = xlmr_profile_from_env();
        let person_t = p
            .thresholds
            .get(&PrivacyLabel::Person)
            .copied()
            .unwrap_or(0.0);
        assert!(
            person_t > 1.0,
            "fp_strict env → fp_strict profile(Person 屏蔽,实际 {})",
            person_t
        );

        // 3. unknown 值 → fallback default(fail-safe)
        for unknown in ["strict", "FP_STRICT", "garbage", ""] {
            std::env::set_var("VIGIL_XLMR_PROFILE", unknown);
            let p = xlmr_profile_from_env();
            assert!(
                !p.thresholds.contains_key(&PrivacyLabel::Person),
                "unknown env value {:?} 应 fallback default(Person 不屏蔽)",
                unknown
            );
        }

        restore();
    }

    // ─── v0.9 Sprint 1 P1.1 — LangConditionalThresholdProfile 守门 ───

    /// new + with_override builder 链式行为
    #[test]
    fn lang_conditional_builder_basic() {
        let default = ThresholdProfile {
            thresholds: [
                (PrivacyLabel::Email, 1.1_f32),
                (PrivacyLabel::Phone, 1.1_f32),
            ]
            .into_iter()
            .collect(),
        };
        let p = LangConditionalThresholdProfile::new(default)
            .with_override("de", PrivacyLabel::Person, 1.1_f32)
            .with_override("it", PrivacyLabel::AccountNumber, 1.1_f32);

        assert_eq!(p.overrides.len(), 2);
        assert_eq!(
            p.overrides.get(&("de".to_string(), PrivacyLabel::Person)),
            Some(&1.1_f32)
        );
    }

    /// threshold_for 决策优先级:
    /// (1) lang Some + (lang, label) 在 overrides → 用 override
    /// (2) lang Some 但 (lang, label) 不在 overrides → 走 default
    /// (3) lang None → 走 default
    /// (4) default 也未列 → None(等价模型默认 0.0 conf)
    #[test]
    fn lang_conditional_threshold_for_priority() {
        let default = ThresholdProfile {
            thresholds: [(PrivacyLabel::Email, 0.5_f32)].into_iter().collect(),
        };
        let p = LangConditionalThresholdProfile::new(default).with_override(
            "de",
            PrivacyLabel::Person,
            1.1_f32,
        );

        // (1) lang 命中 override
        assert_eq!(
            p.threshold_for(PrivacyLabel::Person, Some("de")),
            Some(1.1_f32),
            "de × Person 命中 override"
        );

        // (2) lang 提供但 (lang, label) 未配置 → default
        assert_eq!(
            p.threshold_for(PrivacyLabel::Email, Some("de")),
            Some(0.5_f32),
            "de 但 Email 未在 overrides → default"
        );

        // (2b) lang 提供且 label 在 default 但非 (lang, label) → default
        assert_eq!(
            p.threshold_for(PrivacyLabel::Person, Some("en")),
            None,
            "en × Person 既非 override 也非 default → None"
        );

        // (3) lang None → 走 default
        assert_eq!(
            p.threshold_for(PrivacyLabel::Email, None),
            Some(0.5_f32),
            "lang None + Email 在 default → default"
        );

        // (4) default 也未列 + lang None → None
        assert_eq!(
            p.threshold_for(PrivacyLabel::Address, None),
            None,
            "Address 既非 override 也非 default → None"
        );
    }

    /// XLMR_LANG_CONDITIONAL_PROFILE static 数据驱动正确性 — 6 候选必含
    /// (v0.9 spike top 5 + v0.10 Sprint 6 calibration zh.AccountNumber)。
    ///
    /// 数据来源:
    /// - top 5: docs/operations/v0.9-sprint1/p1_spike-candidates-92.md
    /// - #6:   docs/operations/v0.10-sprint5-spike/day6-7-final-verdict.md(commit 2abbdfc)
    ///
    /// 任一 commit 修改此 6 候选必同步对应 SSOT 报告(feedback_ssot_drift_guard)。
    #[test]
    fn xlmr_lang_conditional_profile_top_6_overrides() {
        let p = &*XLMR_LANG_CONDITIONAL_PROFILE;

        // top 6(顺序与 model_descriptor.rs:163-174 builder 链一致;每条 1.1 屏蔽)
        let candidates: &[(&str, PrivacyLabel)] = &[
            ("it", PrivacyLabel::AccountNumber), // #1 -7 FP   (v0.9 spike)
            ("de", PrivacyLabel::Person),        // #2 -5 FP   (v0.9 spike)
            ("fr", PrivacyLabel::AccountNumber), // #3 -4 FP   (v0.9 spike)
            ("de", PrivacyLabel::AccountNumber), // #4 -3 FP   (v0.9 spike)
            ("en", PrivacyLabel::Person),        // #5 -3 FP   (v0.9 spike)
            ("zh", PrivacyLabel::AccountNumber), // #6 -150 FP (v0.10 Sprint 6,xlmr label mapping over-fire)
        ];
        for (lang, label) in candidates {
            assert_eq!(
                p.threshold_for(*label, Some(lang)),
                Some(1.1_f32),
                "{:?} × {:?} 应在 overrides(spike candidates top 6)",
                lang,
                label
            );
        }
        assert_eq!(p.overrides.len(), candidates.len(), "top 6 候选完整");

        // default 与 XLMR_PROFILE 同步(v0.8 baseline 屏蔽 Email/Phone/Address)
        for label in [
            PrivacyLabel::Email,
            PrivacyLabel::Phone,
            PrivacyLabel::Address,
        ] {
            let t = p.default.thresholds.get(&label).copied().unwrap_or(0.0);
            assert!(
                t > 1.0,
                "default {:?} 应继承 XLMR_PROFILE 屏蔽(>1.0,实际 {})",
                label,
                t
            );
        }
        // default Person 不屏蔽(v0.8 决议;P1.1 仅 lang-conditional 才屏蔽 Person)
        assert!(
            !p.default.thresholds.contains_key(&PrivacyLabel::Person),
            "default Person 不应屏蔽(v0.8 baseline);仅 lang-conditional 启用"
        );
    }

    /// **回归不变量**:P1.1 加 LangConditionalThresholdProfile 不应影响 v0.8
    /// default path — XLMR_PROFILE / XLMR_PROFILE_FP_STRICT static 静态值不动,
    /// XlmrPiiDescriptor.threshold_profile() 仍走 env-driven select(P1.1 不接路径)。
    /// **v0.10 fix**:用 ENV_TEST_LOCK 串行(防其他 env-touching 测试污染)。
    #[test]
    fn xlmr_default_path_unchanged_by_p1_1() {
        let _guard = ENV_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let original = std::env::var("VIGIL_XLMR_PROFILE").ok();
        std::env::remove_var("VIGIL_XLMR_PROFILE");

        let d = XlmrPiiDescriptor::default();
        let profile = d.threshold_profile().expect("xlmr profile");
        // v0.8 baseline:Person 不在 default profile(env 默认 default)
        assert!(
            !profile.thresholds.contains_key(&PrivacyLabel::Person),
            "v0.8 default path 必须保持 Person 不屏蔽(P1.1 不接 lang-conditional 路径)"
        );

        match original {
            Some(v) => std::env::set_var("VIGIL_XLMR_PROFILE", v),
            None => std::env::remove_var("VIGIL_XLMR_PROFILE"),
        }
    }

    // ─── v0.9 Sprint 1 P1.2 R1 NICE(Codex 019dfda1)— 优先级语义 + env × lang 回归 ───

    /// **NICE 1 文档化**:lang override **优先**于 default,即使 lang override
    /// 数值弱于 default(Some(0.0) 不"弱化"也算覆盖)。当前 P1.2 数据全是 1.1
    /// 屏蔽,不会触发此 case;但语义需明确 — lang 上下文是 caller **显式**决策,
    /// 优先级 > default 兜底。
    ///
    /// 不用 `max(lang, default)` fail-closed 策略的原因:caller 传 lang 是有意
    /// 调整;若 fail-closed 策略反而让 lang 上下文 useless(强制走 max)。
    #[test]
    fn lang_override_wins_even_if_weaker_than_default() {
        let mut default_thresholds = std::collections::BTreeMap::new();
        default_thresholds.insert(PrivacyLabel::Person, 0.8_f32); // default 严
        let default = ThresholdProfile {
            thresholds: default_thresholds,
        };
        let p = LangConditionalThresholdProfile::new(default).with_override(
            "de",
            PrivacyLabel::Person,
            0.0_f32,
        ); // lang override 弱(假设场景)

        // lang Some("de") + label Person → 用 override 0.0(即使比 default 0.8 弱)
        assert_eq!(
            p.threshold_for(PrivacyLabel::Person, Some("de")),
            Some(0.0_f32),
            "lang override 必须优先于 default,即使数值弱(caller 显式决策语义)"
        );
        // lang None + label Person → fallback default 0.8
        assert_eq!(
            p.threshold_for(PrivacyLabel::Person, None),
            Some(0.8_f32),
            "lang None → fallback default(本测试同时验 None 路径)"
        );
    }

    // ─── v0.10 candidate F — XlmrProfileMode typed mode 守门 ───

    /// `XlmrPiiDescriptor::default()`(legacy unit-style)走 env-driven path —
    /// 等价 v0.9 行为(`xlmr_profile_from_env()`)。env unset → Default profile。
    #[test]
    fn xlmr_default_descriptor_legacy_env_driven_path() {
        let _guard = ENV_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let original = std::env::var("VIGIL_XLMR_PROFILE").ok();
        std::env::remove_var("VIGIL_XLMR_PROFILE");

        let d = XlmrPiiDescriptor::default();
        let profile = d.threshold_profile().expect("xlmr profile");
        assert!(
            !profile.thresholds.contains_key(&PrivacyLabel::Person),
            "default descriptor + env unset → default profile(Person 不屏蔽)"
        );

        match original {
            Some(v) => std::env::set_var("VIGIL_XLMR_PROFILE", v),
            None => std::env::remove_var("VIGIL_XLMR_PROFILE"),
        }
    }

    /// `XlmrPiiDescriptor::default()` + env=fp_strict → fp_strict profile
    /// (legacy 路径仍读 env;向后兼容 v0.9 ops 配置)
    #[test]
    fn xlmr_default_descriptor_legacy_env_fp_strict() {
        let _guard = ENV_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let original = std::env::var("VIGIL_XLMR_PROFILE").ok();
        std::env::set_var("VIGIL_XLMR_PROFILE", "fp_strict");

        let d = XlmrPiiDescriptor::default();
        let profile = d.threshold_profile().expect("xlmr profile");
        assert!(
            profile.thresholds.contains_key(&PrivacyLabel::Person),
            "default descriptor + env=fp_strict → fp_strict profile(Person 屏蔽)"
        );

        match original {
            Some(v) => std::env::set_var("VIGIL_XLMR_PROFILE", v),
            None => std::env::remove_var("VIGIL_XLMR_PROFILE"),
        }
    }

    /// **核心**:`XlmrPiiDescriptor::with_mode(Default)` typed 路径**忽略 env**
    /// (即使 env=fp_strict,typed Default 仍走 baseline)— SDK reproducible 不变量。
    #[test]
    fn xlmr_typed_default_mode_ignores_env() {
        let _guard = ENV_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let original = std::env::var("VIGIL_XLMR_PROFILE").ok();
        std::env::set_var("VIGIL_XLMR_PROFILE", "fp_strict");

        let d = XlmrPiiDescriptor::with_mode(XlmrProfileMode::Default);
        let profile = d.threshold_profile().expect("xlmr profile");
        // typed Default 仅 v0.8 baseline(屏蔽 Email/Phone/Address;不屏蔽 Person)
        // 即使 env=fp_strict 也忽略 — typed 优先级高
        assert!(
            !profile.thresholds.contains_key(&PrivacyLabel::Person),
            "typed Default 必须忽略 env=fp_strict;Person 不屏蔽"
        );
        assert!(
            profile.thresholds.contains_key(&PrivacyLabel::Email),
            "typed Default 必须含 Email 屏蔽(v0.8 baseline)"
        );

        match original {
            Some(v) => std::env::set_var("VIGIL_XLMR_PROFILE", v),
            None => std::env::remove_var("VIGIL_XLMR_PROFILE"),
        }
    }

    /// `XlmrPiiDescriptor::with_mode(FpStrict)` typed 路径**忽略 env**
    /// (即使 env unset,typed FpStrict 仍走 fp_strict)— SDK reproducible 不变量。
    #[test]
    fn xlmr_typed_fp_strict_mode_ignores_env() {
        let _guard = ENV_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let original = std::env::var("VIGIL_XLMR_PROFILE").ok();
        std::env::remove_var("VIGIL_XLMR_PROFILE");

        let d = XlmrPiiDescriptor::with_mode(XlmrProfileMode::FpStrict);
        let profile = d.threshold_profile().expect("xlmr profile");
        // typed FpStrict 含 Person 1.1 屏蔽 — 即使 env unset 也启用
        let person_t = profile
            .thresholds
            .get(&PrivacyLabel::Person)
            .copied()
            .unwrap_or(0.0);
        assert!(
            person_t > 1.0,
            "typed FpStrict 必须屏蔽 Person (>1.0,实际 {})",
            person_t
        );

        match original {
            Some(v) => std::env::set_var("VIGIL_XLMR_PROFILE", v),
            None => std::env::remove_var("VIGIL_XLMR_PROFILE"),
        }
    }

    /// XlmrProfileMode enum non_exhaustive 守门 — caller match 必须写 `_` 通配,
    /// 允许未来加 variant(如 `RecallFirst`)不破 SemVer。
    ///
    /// **注意**:rustc 在 non_exhaustive enum **同 crate 内**仍把 `_` 标 unreachable
    /// (因可见所有 variant);**跨 crate** caller match 才有真意义。本测试用
    /// `#[allow(unreachable_patterns)]` 局部消音,意图是文档化 SemVer 不变量。
    #[test]
    #[allow(unreachable_patterns)]
    fn xlmr_profile_mode_non_exhaustive_match_compiles() {
        let mode = XlmrProfileMode::Default;
        let label = match mode {
            XlmrProfileMode::Default => "default",
            XlmrProfileMode::FpStrict => "fp_strict",
            // non_exhaustive 强制跨 crate caller _ 通配
            _ => "unknown_future",
        };
        assert_eq!(label, "default");
    }

    /// **NICE 2 回归**:env=fp_strict 时 default profile 含 Person 1.1;
    /// lang-conditional `default` 字段必须**跟随 env**(若实施需要),或独立于
    /// env。当前实施:`XLMR_LANG_CONDITIONAL_PROFILE.default = (*XLMR_PROFILE).clone()`
    /// 在 Lazy init 时一次性 clone v0.8 baseline(不含 Person),**不**跟随 env
    /// 切换。
    ///
    /// 含义:caller 同时 set env=fp_strict + 调 scan_text_with_engine_with_lang,
    /// lang-conditional 路径走 baseline(不含 Person 屏蔽);env path 仅影响
    /// threshold_profile() 路径(legacy infer)。两路径分离,不互冲。
    ///
    /// 这是当前**有意**设计:env=fp_strict 是粗粒度 opt-in(全 sample 屏蔽 Person);
    /// lang-conditional 是细粒度 per-(lang, label) — 不应互相替代。
    #[test]
    fn lang_conditional_default_independent_of_env() {
        // P1.3 fix:用 ENV_TEST_LOCK 串行(防止与 xlmr_profile_from_env_select_and_fallback
        // 并发污染同一 env)
        let _guard = ENV_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        // 临时 set env(测结束 unset);此测试不依赖外部 env 设置
        let original = std::env::var("VIGIL_XLMR_PROFILE").ok();
        std::env::set_var("VIGIL_XLMR_PROFILE", "fp_strict");

        // env_driven path:含 Person 1.1
        let env_profile = xlmr_profile_from_env();
        assert!(
            env_profile.thresholds.contains_key(&PrivacyLabel::Person),
            "env=fp_strict 时 threshold_profile 路径应含 Person"
        );

        // lang-conditional default 不跟随 env(static Lazy init 一次性 clone baseline)
        let lang_default = &XLMR_LANG_CONDITIONAL_PROFILE.default;
        assert!(
            !lang_default.thresholds.contains_key(&PrivacyLabel::Person),
            "lang-conditional default 字段独立于 env(不含 Person);env 切换仅影响 threshold_profile() 路径"
        );

        // restore
        match original {
            Some(v) => std::env::set_var("VIGIL_XLMR_PROFILE", v),
            None => std::env::remove_var("VIGIL_XLMR_PROFILE"),
        }
    }

    /// 自定义 descriptor 不 override 时回退 default
    #[test]
    fn descriptor_default_onnx_filename_fallback() {
        struct NoOverrideDescriptor;
        impl ModelDescriptor for NoOverrideDescriptor {
            fn model_id(&self) -> &str {
                "test-no-override"
            }
            fn version(&self) -> &str {
                "0.0.0"
            }
            fn label_space_version(&self) -> &str {
                "test-v0"
            }
            fn id2label(&self) -> &[&'static str] {
                &[]
            }
            fn canonical_mapping(&self, _: &str) -> Option<PrivacyLabel> {
                None
            }
            fn tokenizer_spec(&self) -> TokenizerSpec {
                TokenizerSpec::HuggingFaceJson
            }
            fn post_processor(&self) -> PostProcessorKind {
                PostProcessorKind::Bio
            }
        }
        // 不 override onnx_filename → 走 default
        assert_eq!(
            NoOverrideDescriptor.onnx_filename(),
            "model_q4f16.onnx",
            "default 实现应返 model_q4f16.onnx"
        );
    }
}
