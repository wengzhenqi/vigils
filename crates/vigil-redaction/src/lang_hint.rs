//! v0.10 Sprint 2 — typed `LanguageHint` wrapper(Decision A-prime,Codex `019dfdab`)。
//!
//! **触发**:v0.9 Decision D=C 锁定 production firewall **不接** lang;但 SDK consumer
//! 仍可能想 reproducible 走 lang-aware path。直接传 `Option<&str>` 不够 — 没有
//! provenance / confidence 信息,caller 无法判 trust;启发式 detect 误判(短文本
//! 17/45 EU sample,见 `feedback_lang_review_authoritative`)若混入 production 决策
//! 路径会静默 threshold 误路由。
//!
//! **A-prime 设计**(本模块):typed `LanguageHint { lang, source, confidence }`,
//! 强制 caller 表达**信息来源** + **可信度**;low-confidence 一律 fail-closed 退化
//! baseline。
//!
//! **当前 v0.10 范围**:
//! - typed wrapper + 工厂方法 + `into_lang_str()` 转 `Option<String>`(low-conf → None)
//! - `scan_text_with_engine_with_hint(text, engine, hint)` 浅级 wrapper(SDK 友好)
//! - SDK re-export(`vigil_sdk::{LanguageHint, LangHintSource}`)
//! - **不**接 Firewall::evaluate(D=C 锁定;v0.11+ 视用户反馈)

use crate::engine::RedactionEngine;
use crate::scan::{scan_text_with_engine_with_lang, RedactionResult, ScanError};

/// **v0.10 Sprint 2** — `LanguageHint` 信息来源 enum。
///
/// caller 必须表明 lang 字符串来自哪类信息 — 影响 audit trail + 可信度判定。
/// `into_lang_str()` 决策时按 source × confidence 综合判 fail-closed 退化:
/// - `CallerProvided`:caller 明确决策(如用户 locale 设置 / 业务上下文)— 高信任
/// - `FixtureExperimental`:fixture / 测试 / release-gate 模式 — 中信任(仅非 production)
/// - `Heuristic`:启发式 detect(unicode + 关键词)— 低信任,advisory only
///
/// **SemVer**:`#[non_exhaustive]` — 未来加 source(如 `UserAgent` / `MlClassifier`)
/// 不破。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum LangHintSource {
    /// caller 显式传入(可信度最高;典型 user locale / 业务上下文)
    CallerProvided,
    /// fixture / 测试 / release-gate 场景(权威源,但仅非 production)
    FixtureExperimental,
    /// 启发式 lang detect(unicode 字符集 + 关键词;仅 advisory,不可作权威决策)
    Heuristic,
}

impl LangHintSource {
    /// 该 source 是否本质可信(进 production 决策)。
    /// `Heuristic` 始终 false(`feedback_lang_review_authoritative` 约束)。
    pub fn is_trusted(&self) -> bool {
        // crate 内部穷举所有 variant(LangHintSource 定义在本 module);加新 variant
        // 时 compiler 会 force update 本 match — 比 runtime `_ => false` fail-closed
        // 兜底更早 catch。外部 SDK consumer 因 #[non_exhaustive] 必须写 `_` 兜底。
        match self {
            LangHintSource::CallerProvided => true,
            LangHintSource::FixtureExperimental => true,
            LangHintSource::Heuristic => false,
        }
    }
}

/// **v0.10 Sprint 2** — typed lang hint wrapper(Decision A-prime)。
///
/// **设计意图**:替代裸 `Option<&str>` 给 SDK consumer / 未来 firewall lang-aware
/// 路径用;**强制 provenance + confidence**,low-conf 一律 fail-closed 退化。
///
/// **典型用法**(SDK consumer):
/// ```rust
/// use vigil_redaction::lang_hint::{LanguageHint, LangHintSource};
///
/// // caller 知道用户 locale → 高信任
/// let hint = LanguageHint::caller_provided("de");
///
/// // 启发式 detect → advisory,low-conf 自动 fail-closed
/// let hint = LanguageHint::heuristic("de", 0.4);  // confidence 太低,into_lang_str → None
/// ```
///
/// **SemVer**:`#[non_exhaustive]` — 未来加字段(如 `audit_id` / `provider_chain`)
/// 不破;pub fields 可读,struct literal 构造仅 crate 内可用。
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct LanguageHint {
    /// ISO 639-1 lowercase(`"en"` / `"de"` / `"it"` / `"fr"` / ...);与 fixture
    /// lang 字段对齐
    pub lang: String,
    /// 信息来源(用于 audit trail + 可信度决策)
    pub source: LangHintSource,
    /// 置信度 [0.0, 1.0];low-conf(< 0.5)`into_lang_str` 一律返 None(fail-closed
    /// 退化 baseline path,避免误降 policy)
    pub confidence: f32,
}

/// `into_lang_str` 用的 fail-closed 阈值。confidence < 此值 → None(走 baseline)。
///
/// **0.5 选择理由**:
/// - 启发式 detect 在短文本无关键词时常返 0.3-0.4(`feedback_lang_review_authoritative`)
/// - caller_provided / fixture 一般 1.0(用户/fixture 权威源)
/// - 0.5 阈值切开"模糊 advisory" vs "可决策" 两类
pub const LANG_HINT_TRUSTED_CONFIDENCE: f32 = 0.5;

impl LanguageHint {
    /// caller 显式传入(`CallerProvided` source,confidence = 1.0)。
    /// 适用:用户 locale 设置 / 业务上下文 / 已校验输入。
    pub fn caller_provided(lang: impl Into<String>) -> Self {
        Self {
            lang: lang.into(),
            source: LangHintSource::CallerProvided,
            confidence: 1.0,
        }
    }

    /// fixture / 测试场景(`FixtureExperimental` source,confidence = 1.0)。
    /// 仅非 production;典型 release-gate / spike-gate / fixture lang 字段透传。
    pub fn fixture(lang: impl Into<String>) -> Self {
        Self {
            lang: lang.into(),
            source: LangHintSource::FixtureExperimental,
            confidence: 1.0,
        }
    }

    /// 启发式 detect(`Heuristic` source,caller 给 confidence)。
    /// **决策不可信**:即使 confidence = 1.0,`is_trusted` 返 false(由
    /// `LangHintSource` 静态判定);仅 advisory(diagnose / suggestion UI)。
    /// confidence < 0.5 时 `into_lang_str` 也返 None。
    pub fn heuristic(lang: impl Into<String>, confidence: f32) -> Self {
        Self {
            lang: lang.into(),
            source: LangHintSource::Heuristic,
            confidence: confidence.clamp(0.0, 1.0),
        }
    }

    /// **v0.10 Sprint 6** — 启发式 lang detect(advisory only)。
    ///
    /// 调用 [`detect_lang_heuristic`] 内部启发式(unicode 字符集 + 关键词),返
    /// `LanguageHint` with `LangHintSource::Heuristic`。
    /// **始终返 Heuristic** — `lang_str()` **永返 None**,无法触发 firewall 决策路径。
    ///
    /// 适用场景:
    /// - fixture lang 字段标注辅助(P1.0 启发式同口径,但用 Rust 端版本)
    /// - SDK consumer 诊断 UI / 建议性显示
    /// - **永不**作 production 决策权威(`feedback_lang_review_authoritative` 约束)
    pub fn detect(text: &str) -> Self {
        detect_lang_heuristic(text)
    }

    /// **fail-closed 转换**:返 `Option<&str>`(走 `scan_text_with_engine_with_lang`)。
    ///
    /// 决策规则:
    /// - confidence < `LANG_HINT_TRUSTED_CONFIDENCE`(0.5)→ `None`(退化 baseline)
    /// - `LangHintSource::Heuristic` → `None`(无论 confidence,启发式不可信)
    /// - 其他(`CallerProvided` / `FixtureExperimental` + confidence ≥ 0.5)→ `Some(&lang)`
    ///
    /// 这是 D=C 决议下的 SDK 边界 — caller 即使传 `Heuristic`,也**不会**触发
    /// lang-conditional threshold(防 production 误降 policy)。
    pub fn lang_str(&self) -> Option<&str> {
        if !self.source.is_trusted() {
            return None;
        }
        if self.confidence < LANG_HINT_TRUSTED_CONFIDENCE {
            return None;
        }
        Some(self.lang.as_str())
    }
}

/// **v0.10 Sprint 6** — 独立函数版启发式 lang detect(advisory only)。
///
/// **算法**(与 `scripts/spike-p3/analyze_fixture_distribution.py::detect_lang` 同口径):
/// 1. unicode 字符集(明确特征,confidence 高)
///    - 韩文 Hangul ≥ 2 字符 → `("ko", 0.9)`
///    - 日文 Hiragana/Katakana ≥ 2 → `("ja", 0.9)`
///    - 中文 CJK Han ≥ 2 → `("zh", 0.85)`(可能与 ja 共有汉字,故 confidence 略低)
/// 2. 拉丁语系关键词(明确特征,confidence 中-高)
///    - 德语关键词命中 → `("de", 0.7)`
///    - 法语关键词命中 → `("fr", 0.7)`
///    - 意大利语关键词命中 → `("it", 0.7)`
///    - 西班牙语关键词命中 → `("es", 0.7)`
/// 3. 重音字符 fallback(模糊,confidence 低)
///    - `äöüß` 字符 → `("de", 0.5)`
///    - 其他西欧重音字符 → `("fr", 0.4)`(默认归 fr,西欧最广)
/// 4. 无特征 → `("en", 0.3)`(短文本无关键词时低 confidence,fail-closed 退化)
///
/// **fail-closed**:无论返哪个 lang,`source = Heuristic` 永远不可作 production 决策。
/// caller 用 `into_lang_str()` / `lang_str()` 始终返 None(except low-conf <0.5 也返 None)。
pub fn detect_lang_heuristic(text: &str) -> LanguageHint {
    use LangHintSource::Heuristic;

    // CJK 字符集(明确特征)
    let mut cjk = 0;
    let mut hira = 0;
    let mut kata = 0;
    let mut hangul = 0;
    for ch in text.chars() {
        let cp = ch as u32;
        if (0x4E00..=0x9FFF).contains(&cp) {
            cjk += 1;
        } else if (0x3040..=0x309F).contains(&cp) {
            hira += 1;
        } else if (0x30A0..=0x30FF).contains(&cp) {
            kata += 1;
        } else if (0xAC00..=0xD7AF).contains(&cp) {
            hangul += 1;
        }
    }
    if hangul >= 2 {
        return LanguageHint {
            lang: "ko".to_string(),
            source: Heuristic,
            confidence: 0.9,
        };
    }
    if hira + kata >= 2 {
        return LanguageHint {
            lang: "ja".to_string(),
            source: Heuristic,
            confidence: 0.9,
        };
    }
    if cjk >= 2 {
        return LanguageHint {
            lang: "zh".to_string(),
            source: Heuristic,
            confidence: 0.85,
        };
    }

    // 关键词命中(中-高 confidence)
    let low = text.to_lowercase();
    let de_hints = [
        "herr ",
        "frau ",
        "straße",
        "strasse",
        "gmbh",
        "münchen",
        "berlin",
        "hamburg",
        "köln",
        "müller",
        "schmidt",
        " und ",
        "ich bin",
        "guten tag",
        "bitte",
        "webseite",
        "konto",
        "verwendet",
        "verfügbar",
        "geboren am",
    ];
    let fr_hints = [
        "monsieur",
        "madame",
        "bonjour",
        "paris",
        "lyon",
        "marseille",
        "merci",
        "veuillez",
        "envoyer",
        "visitez",
        "né le ",
        "née le ",
        "téléphone",
        "adresse:",
        " et ",
    ];
    let it_hints = [
        "signor",
        "signora",
        "roma",
        "milano",
        "napoli",
        "bologna",
        "buongiorno",
        "grazie",
        "contatta",
        "telefono",
        "nato il",
        "nata il",
        "codice fiscale",
        "visita ",
        "indirizzo:",
        " e ",
    ];
    let es_hints = [
        "señor",
        "señora",
        "calle ",
        "madrid",
        "barcelona",
        "valencia",
        "sevilla",
        "gracias",
        "por favor",
        "avenida",
    ];
    if de_hints.iter().any(|h| low.contains(h)) {
        return LanguageHint {
            lang: "de".to_string(),
            source: Heuristic,
            confidence: 0.7,
        };
    }
    if fr_hints.iter().any(|h| low.contains(h)) {
        return LanguageHint {
            lang: "fr".to_string(),
            source: Heuristic,
            confidence: 0.7,
        };
    }
    if it_hints.iter().any(|h| low.contains(h)) {
        return LanguageHint {
            lang: "it".to_string(),
            source: Heuristic,
            confidence: 0.7,
        };
    }
    if es_hints.iter().any(|h| low.contains(h)) {
        return LanguageHint {
            lang: "es".to_string(),
            source: Heuristic,
            confidence: 0.7,
        };
    }

    // 字符集 fallback(模糊;feedback_lang_review_authoritative 警告:短文本误判 17/45)
    let has_de_chars = text
        .chars()
        .any(|c| matches!(c, 'ä' | 'ö' | 'ü' | 'ß' | 'Ä' | 'Ö' | 'Ü'));
    if has_de_chars {
        return LanguageHint {
            lang: "de".to_string(),
            source: Heuristic,
            confidence: 0.45, // < TRUSTED 0.5(fail-closed 退化 baseline)
        };
    }
    let has_western_accent = text.chars().any(|c| {
        matches!(
            c,
            'à' | 'â'
                | 'ç'
                | 'é'
                | 'è'
                | 'ê'
                | 'ë'
                | 'î'
                | 'ï'
                | 'ô'
                | 'û'
                | 'ù'
                | 'À'
                | 'É'
                | 'È'
                | 'Ê'
                | 'Ô'
        )
    });
    if has_western_accent {
        return LanguageHint {
            lang: "fr".to_string(),
            source: Heuristic,
            confidence: 0.4,
        };
    }

    // 无特征 → en,低 confidence(fail-closed:lang_str 返 None)
    LanguageHint {
        lang: "en".to_string(),
        source: Heuristic,
        confidence: 0.3,
    }
}

/// **v0.10 Sprint 2** — `scan_text_with_engine_with_hint` 浅级 wrapper。
///
/// SDK consumer 友好版 `scan_text_with_engine_with_lang`:接 typed
/// [`LanguageHint`](Option),内部按 fail-closed 规则转 `Option<&str>`。
///
/// 等价于:
/// ```ignore
/// let lang = hint.and_then(|h| h.lang_str());
/// scan_text_with_engine_with_lang(input, engine, lang)
/// ```
///
/// 但 typed wrapper 让 caller 必须表达 source / confidence,**强制可解释 + 可
/// 进 audit**;裸 `Option<&str>` 无 provenance,SDK consumer 易混淆来源。
///
/// **SemVer**:新公共 API,SemVer 安全(legacy `scan_text_with_engine_with_lang`
/// 保留,未改签名)。
pub fn scan_text_with_engine_with_hint(
    input: &str,
    engine: &dyn RedactionEngine,
    hint: Option<&LanguageHint>,
) -> Result<RedactionResult, ScanError> {
    let lang = hint.and_then(|h| h.lang_str());
    scan_text_with_engine_with_lang(input, engine, lang)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn caller_provided_high_trust_returns_lang() {
        let h = LanguageHint::caller_provided("de");
        assert_eq!(h.source, LangHintSource::CallerProvided);
        assert!((h.confidence - 1.0).abs() < f32::EPSILON);
        assert_eq!(h.lang_str(), Some("de"));
    }

    #[test]
    fn fixture_experimental_returns_lang() {
        let h = LanguageHint::fixture("it");
        assert_eq!(h.source, LangHintSource::FixtureExperimental);
        assert_eq!(h.lang_str(), Some("it"));
    }

    /// **关键**:Heuristic source 即使 confidence=1.0 也返 None(不可信任)。
    /// 这是 D=C 决议下 SDK 边界;`feedback_lang_review_authoritative` 约束。
    #[test]
    fn heuristic_always_returns_none_even_max_confidence() {
        let h = LanguageHint::heuristic("de", 1.0);
        assert_eq!(h.source, LangHintSource::Heuristic);
        assert_eq!(
            h.lang_str(),
            None,
            "Heuristic source 即使 confidence=1.0 也必须返 None(决策不可信任)"
        );
    }

    /// low confidence(< 0.5)即使 trusted source 也返 None(fail-closed)
    #[test]
    fn low_confidence_returns_none_even_caller_provided() {
        let mut h = LanguageHint::caller_provided("de");
        h.confidence = 0.4; // 模拟 caller 自降信任
        assert_eq!(
            h.lang_str(),
            None,
            "confidence < 0.5 必须 fail-closed 返 None"
        );
    }

    /// confidence clamp [0.0, 1.0]
    #[test]
    fn heuristic_confidence_clamp() {
        let h_neg = LanguageHint::heuristic("de", -0.5);
        assert!(h_neg.confidence >= 0.0);
        let h_over = LanguageHint::heuristic("de", 2.0);
        assert!(h_over.confidence <= 1.0);
    }

    /// LangHintSource non_exhaustive — caller 必 _ 通配
    #[test]
    #[allow(unreachable_patterns)]
    fn lang_hint_source_non_exhaustive_match_compiles() {
        let s = LangHintSource::CallerProvided;
        let trusted = match s {
            LangHintSource::CallerProvided => true,
            LangHintSource::FixtureExperimental => true,
            LangHintSource::Heuristic => false,
            _ => false, // non_exhaustive 强制 _
        };
        assert!(trusted);
    }

    /// `is_trusted` 与 `lang_str` 决策一致(Heuristic / 未知 source 不可信)
    #[test]
    fn is_trusted_consistent_with_lang_str_decision() {
        assert!(LangHintSource::CallerProvided.is_trusted());
        assert!(LangHintSource::FixtureExperimental.is_trusted());
        assert!(!LangHintSource::Heuristic.is_trusted());
    }

    /// scan_text_with_engine_with_hint 等价于 hint.lang_str() + scan_with_lang
    #[test]
    fn scan_with_hint_empty_input_fail_closed() {
        let h = LanguageHint::caller_provided("de");
        let r = scan_text_with_engine_with_hint("", &crate::engine::NoopEngine, Some(&h));
        assert!(matches!(r, Err(ScanError::EmptyInput)));
    }

    /// hint = None 等价于 scan_text_with_engine(legacy)
    #[test]
    fn scan_with_hint_none_equivalent_to_legacy() {
        let r = scan_text_with_engine_with_hint("hello", &crate::engine::NoopEngine, None)
            .expect("non-empty");
        // NoopEngine 返空 model findings;Hard rules 在 "hello" 上不命中
        assert!(r.findings.is_empty(), "NoopEngine + 'hello' 无 finding");
    }

    // ─── v0.10 Sprint 6 — advisory lang detect 守门 ───

    /// CJK 字符明确特征(高 confidence)
    #[test]
    fn detect_lang_zh_chinese() {
        let h = detect_lang_heuristic("请联系王小明处理订单");
        assert_eq!(h.lang, "zh");
        assert_eq!(h.source, LangHintSource::Heuristic);
        assert!(h.confidence >= 0.8);
    }

    #[test]
    fn detect_lang_ja_japanese() {
        let h = detect_lang_heuristic("田中太郎さんが昨日来ました");
        assert_eq!(h.lang, "ja");
        assert!(h.confidence >= 0.85);
    }

    #[test]
    fn detect_lang_ko_korean() {
        let h = detect_lang_heuristic("김민수 씨에게 연락하세요");
        assert_eq!(h.lang, "ko");
        assert!(h.confidence >= 0.85);
    }

    /// 拉丁语系关键词命中(中 confidence 0.7)
    #[test]
    fn detect_lang_de_keyword() {
        let h = detect_lang_heuristic("Herr Schmidt arbeitet hier.");
        assert_eq!(h.lang, "de");
        assert!((h.confidence - 0.7).abs() < 0.01);
    }

    #[test]
    fn detect_lang_fr_keyword() {
        let h = detect_lang_heuristic("Monsieur Dupont travaille ici.");
        assert_eq!(h.lang, "fr");
    }

    #[test]
    fn detect_lang_it_keyword() {
        let h = detect_lang_heuristic("Il signor Rossi lavora qui.");
        assert_eq!(h.lang, "it");
    }

    /// 短文本无关键词 → en 低 confidence(fail-closed)
    #[test]
    fn detect_lang_short_text_low_confidence() {
        let h = detect_lang_heuristic("John Smith works here.");
        assert_eq!(h.lang, "en");
        assert!(
            h.confidence < LANG_HINT_TRUSTED_CONFIDENCE,
            "短英文文本 confidence 必须 < 0.5(fail-closed 退化 baseline)"
        );
        assert_eq!(
            h.lang_str(),
            None,
            "无论 lang 是什么,Heuristic source 永返 None"
        );
    }

    /// **关键不变量**:即使 detect 命中明确语言(高 confidence),lang_str 仍返 None
    /// (Heuristic source 永不可信任 — D=C 锁定下的 SDK 边界)
    #[test]
    fn detect_lang_high_confidence_still_not_trusted() {
        let h = detect_lang_heuristic("田中太郎さんが昨日来ました");
        assert!(h.confidence >= 0.85, "ja 应高 confidence");
        assert_eq!(
            h.lang_str(),
            None,
            "Heuristic source 即使 high confidence 也必须返 None(feedback_lang_review_authoritative)"
        );
    }

    /// `LanguageHint::detect(text)` 等价独立函数
    #[test]
    fn language_hint_detect_method_equivalent_to_function() {
        let text = "Herr Schmidt arbeitet hier.";
        let from_method = LanguageHint::detect(text);
        let from_fn = detect_lang_heuristic(text);
        assert_eq!(from_method.lang, from_fn.lang);
        assert_eq!(from_method.source, from_fn.source);
        assert_eq!(from_method.confidence, from_fn.confidence);
    }

    /// 重音字符 fallback(de ä/ö/ü/ß)— 模糊但比 en fallback 好
    #[test]
    fn detect_lang_de_accent_fallback() {
        // 短文本无关键词,但有 ß 字符
        let h = detect_lang_heuristic("Herr ß test");
        // 实际"Herr "命中关键词,先返 de;此 case 走关键词路径
        assert_eq!(h.lang, "de");

        // 真 fallback case:无关键词但有 ä/ö/ü/ß
        let h2 = detect_lang_heuristic("würde");
        assert_eq!(h2.lang, "de");
        assert!(
            h2.confidence < LANG_HINT_TRUSTED_CONFIDENCE,
            "fallback 模糊路径 confidence 必须 < 0.5"
        );
    }

    /// 与 fixture lang 字段(P1.0+ 人工核对权威)对比 — 启发式应**部分**命中,
    /// 但**绝不能**作权威源(本测试文档化:detect 仅 advisory)。
    #[test]
    fn detect_lang_documented_as_advisory_not_authoritative() {
        // 短文本,fixture 真值是 en,但启发式无关键词
        let h = detect_lang_heuristic("John Smith works here.");
        // 即使启发式判 en,confidence 仍低 → lang_str None,不影响 production 决策
        assert_eq!(h.source, LangHintSource::Heuristic);
        assert!(!h.source.is_trusted(), "Heuristic source 永远不可信任");
    }
}
