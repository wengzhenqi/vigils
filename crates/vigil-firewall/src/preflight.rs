//! ISS-010 — Firewall preflight:扫描 tool args 长文本 → T0 PII findings → 喂 PolicyEngine
//! + 落 SQLite 审计表(ISS-011 CRUD)。
//!
//! 设计原则(与任务 prompt 对齐):
//! 1. **fail-closed**:`PiiScanner::scan` 返 Err(除 `EmptyInput` 外)→ 上层转
//!    `FirewallError::PreflightScanFailed`;caller(`Firewall::evaluate`)视为 Deny 并抛错。
//! 2. **只加风险,不单独放行**:本模块只产出 `Vec<PiiFindingSummary>` + risk delta,规则
//!    引擎最终裁决不变(Allow/Deny/Approve 仍由 PolicyEngine 决定)。
//! 3. **审计缺失不拦业务**:`persist_scan_to_ledger` 失败只原子计数(见
//!    `Firewall::audit_persist_failures`),**不** stderr 污染、**不**拦决策。
//! 4. **零破坏 v0.3 redaction / audit / policy**:本模块仅消费其 pub API。
//! 5. **可测性(R2 BLOCKER 2 修复)**:scanner 走 [`PiiScanner`] trait,测试可注入
//!    测试里本地实现 [`PiiScanner`] 真触发 fail-closed 路径,不再靠"variant 存在"伪守门。
//!
//! 调用位置见 `engine.rs::Firewall::evaluate` 的 "3b) preflight" 段。

use std::collections::BTreeMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use sha2::{Digest, Sha256};
use vigil_audit::{Ledger, NewRedactionFinding, NewRedactionScan};
use vigil_policy::PiiFindingSummary;
use vigil_redaction::{PrivacyLabel, RedactionResult, ScanError};

/// v0.8 Sprint 1 A2 — PiiScanner 层引擎状态汇报。
///
/// **设计目标**:让 `Firewall::evaluate` 能感知 scanner 内部退化路径(timeout /
/// runtime error)→ 落审计 `engine_degraded` 事件 + decision_reasons 加 stable code,
/// 不依赖各 scanner 实现具备 budget 能力。
///
/// **与 [`vigil_redaction::EngineStatus`] 的区别**:redaction 层只表达"模型路径运行
/// 结果"(Ok/DegradedTimeout/DegradedError);本 enum 在 firewall caller 视角额外
/// 引入 `Unsupported`,用于标记 scanner 实现未 override [`PiiScanner::scan_with_status`]
/// (Codex § 2 改进版 A:**default 返 Unsupported,不返假安全 Ok**,caller 必须
/// 显式判此情况)。
///
/// **R1 NICE(Codex 019deb53)— SemVer**:`#[non_exhaustive]` 强制 caller 用
/// 模式匹配时写 `_` 通配,允许未来加 variant(如 `DegradedOom` / `DegradedPanic`)
/// 不破 SemVer。SDK 暴露(vigil-sdk re-export)的契约文档(docs/sdk-shallow-api.md
/// §4.2)已声明 non_exhaustive,本 enum 实际加 attribute 让契约和实现一致。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum EngineStatusReport {
    /// 模型路径正常完成(scanner override 返此值表示真"Ok")。
    Ok,
    /// 模型路径在 budget 内未完成,已退化为 Hard-only。caller 应落
    /// `engine_degraded` 审计 + decision_reasons.push("engine.status=degraded_timeout")。
    DegradedTimeout,
    /// 模型 panic / runtime error,已退化为 Hard-only。caller 应落
    /// `engine_degraded` 审计 + decision_reasons.push("engine.status=degraded_error")。
    DegradedError,
    /// scanner 实现未 override [`PiiScanner::scan_with_status`] —— caller **必须**
    /// 显式判此情况,**不能**当 Ok 处理。Codex § 2 改进版 A:default 返此值,
    /// 强制 caller 在编译期之外的 runtime path 走显式分支(无 status 不可隐式假定)。
    Unsupported,
}

impl EngineStatusReport {
    /// 落审计 / decision_reasons 用稳定字面量。**不**包含 PII;**不**靠 Debug 格式化。
    /// `Ok` / `Unsupported` 不预期被 caller 写入 reasons(只有退化路径需);返字面量便于
    /// 测试断言但 caller 不应对此分支落审计。
    pub fn stable_code(&self) -> &'static str {
        // crate 内部穷举所有 variant;加新 variant 时 compiler force update,作者
        // 在新增 variant 时**必须**显式选稳定 code 字面量(进 audit ledger 不破)。
        // 外部 SDK consumer 因 #[non_exhaustive] 必须写 `_` 兜底。
        match self {
            EngineStatusReport::Ok => "ok",
            EngineStatusReport::DegradedTimeout => "degraded_timeout",
            EngineStatusReport::DegradedError => "degraded_error",
            EngineStatusReport::Unsupported => "unsupported",
        }
    }
}

impl From<vigil_redaction::EngineStatus> for EngineStatusReport {
    fn from(s: vigil_redaction::EngineStatus) -> Self {
        match s {
            vigil_redaction::EngineStatus::Ok => Self::Ok,
            vigil_redaction::EngineStatus::DegradedTimeout => Self::DegradedTimeout,
            vigil_redaction::EngineStatus::DegradedError => Self::DegradedError,
        }
    }
}

/// **R2 BLOCKER 2 修复** —— 把 PII 扫描抽象为 trait,让测试能注入 failing scanner
/// 真触发 fail-closed 路径。默认实现 [`DefaultScanner`] 直接 forward 到
/// [`vigil_redaction::scan_text`]。
///
/// 生产 caller 不需要感知此 trait —— `Firewall::new` 默认用 `DefaultScanner`。
/// 测试可通过 `Firewall::with_scanner` 注入自定义实现。
pub trait PiiScanner: Send + Sync + 'static {
    /// 扫一段文本,产 `RedactionResult`。契约与 `vigil_redaction::scan_text` 完全一致:
    /// - 空输入返 `Err(ScanError::EmptyInput)`(caller 视为 continue)
    /// - 推理失败返 `Err(ScanError::InferenceFailed { .. })`(caller 视为 fail-closed Deny)
    fn scan(&self, text: &str) -> Result<RedactionResult, ScanError>;

    /// v0.8 Sprint 1 A2 — 扫文本并汇报 scanner 内部状态。
    ///
    /// **default 返 [`EngineStatusReport::Unsupported`]**(Codex § 2 改进版 A 关键改进):
    /// - 未 override 此方法的实现:`(scan(), Unsupported)`
    /// - caller(`Firewall::evaluate`)必须显式 match Unsupported,**不能**当 Ok 处理
    /// - 这避免了"trait default 返 Ok 让所有 scanner 默认伪报 Ok"的假安全
    ///
    /// **override 时机**:scanner 内部具备 budget / 退化路径(如
    /// [`BudgetedOrtPiiScanner`])时 override,返 `(result, status_from_inner)`。
    /// 简单 scanner(`DefaultScanner` / 不带 budget 的 [`OrtPiiScanner`])保持 default。
    ///
    /// 错误语义同 [`scan`](Self::scan):空输入 EmptyInput / 推理失败 InferenceFailed。
    fn scan_with_status(
        &self,
        text: &str,
    ) -> Result<(RedactionResult, EngineStatusReport), ScanError> {
        self.scan(text)
            .map(|r| (r, EngineStatusReport::Unsupported))
    }
}

/// 生产默认 scanner:直接走 `vigil_redaction::scan_text`。
///
/// **crate-internal only**(R2 NICE):不在 lib.rs pub re-export,生产 caller 不需
/// 直接构造 —— `Firewall::new` 内部通过 [`default_scanner_arc`] 选择。
#[derive(Debug, Default, Clone, Copy)]
pub(crate) struct DefaultScanner;

impl PiiScanner for DefaultScanner {
    fn scan(&self, text: &str) -> Result<RedactionResult, ScanError> {
        vigil_redaction::scan_text(text)
    }
}

/// 提取 `args` 中所有长度 ≥ `threshold`(字节)的 UTF-8 字符串字段,平铺返回 owned 副本。
///
/// **策略**:递归走 `serde_json::Value`。数组/对象一概下钻;遇到 `String` 按 `len()`
/// (byte,非 char)判定;Null/Bool/Number 跳过。**不保证顺序**与输入完全一致,但同输入
/// 同顺序(递归是深度优先;对象按 serde_json 的 key 迭代器顺序,insertion-order 保留)。
///
/// 返回 `Vec<String>`:每个元素是一段候选 preflight 扫描文本。空列表表示"没有长文本字段"。
pub(crate) fn extract_long_text_fields(args: &serde_json::Value, threshold: usize) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    walk(args, threshold, &mut out);
    out
}

fn walk(v: &serde_json::Value, threshold: usize, out: &mut Vec<String>) {
    match v {
        // v0.13 clippy 1.95 `collapsible_match`:if-guard 合并到 match arm
        serde_json::Value::String(s) if s.len() >= threshold => {
            out.push(s.clone());
        }
        serde_json::Value::Array(xs) => {
            for x in xs {
                walk(x, threshold, out);
            }
        }
        serde_json::Value::Object(m) => {
            for (_k, vv) in m.iter() {
                walk(vv, threshold, out);
            }
        }
        _ => {}
    }
}

/// 取单次 scan 对 firewall risk_score 的 delta。
///
/// 直接透传 `RiskSignals.total_risk_delta`(ISS-005 `aggregate_risk` 已按 ADR 0012 §1.3
/// 分级累加:Secret 25 / Email|Url 10 / 其他 PII 5)。**不**在本层重算分级,避免规则漂移。
pub(crate) fn compute_pii_risk_delta(result: &RedactionResult) -> u32 {
    result.risk_signals.total_risk_delta
}

/// 把一次 preflight scan 的 `RedactionResult` 落到 SQLite 审计两表。
///
/// 纪律:
/// - scan 级 fingerprint = `sha256(text)[..16]` hex-lower;
/// - finding 级 fingerprint = `sha256(原 span 切片)[..16]` hex-lower;
/// - 未被 `PrivacyLabel::from_kind` 识别的 kind **跳过**(不落未知 label,保守);
/// - UTF-8 非 char boundary 或越界 span 也跳过(防御性,理论上 regex 命中不会越界)。
///
/// **错误语义**:任何 audit 写失败都返 `Err`,但 caller(`Firewall::evaluate`)选择
/// 降级处理(`let _ =` 忽略)—— 审计缺失不应阻断业务决策。Scan 失败是另一条路径,
/// 走 `FirewallError::PreflightScanFailed`。
pub(crate) fn persist_scan_to_ledger(
    ledger: &Ledger,
    session_id: &str,
    text: &str,
    result: &RedactionResult,
) -> vigil_audit::Result<()> {
    // 防御:空文本不应到达这里(extract_long_text_fields 用 threshold ≥ 1 时已过滤),
    // 但 audit 侧 validate_fingerprint 只校验 hex 格式,空文本的 sha256 仍合法,
    // 这里直接继续,不做额外分支。
    let fp = sha256_prefix16_hex(text.as_bytes());

    let scan_id = ledger.insert_redaction_scan(NewRedactionScan {
        session_id,
        // ISS-010:preflight 总是扫 tool args,对应 audit schema 的 `tool_arg` 枚举。
        source: "tool_arg",
        text_length: text.len(),
        fingerprint: &fp,
    })?;

    for finding in &result.findings {
        // 未识别 kind 不落审计(审计 ALLOWED_REDACTION_LABELS 只接 8 枚举)。
        let Some(label) = PrivacyLabel::from_kind(finding.kind) else {
            continue;
        };

        let (start, end) = finding.span;
        // 边界 / UTF-8 防御:merge_findings 后正常不越界,但 Model 侧将来可能塞进
        // 非 char boundary;这里跳过避免 slice panic。
        if start > end || end > text.len() {
            continue;
        }
        if !text.is_char_boundary(start) || !text.is_char_boundary(end) {
            continue;
        }

        let span_slice = &text[start..end];
        let span_fp = sha256_prefix16_hex(span_slice.as_bytes());

        ledger.insert_redaction_finding(NewRedactionFinding {
            scan_id: &scan_id,
            label: label.as_str(),
            offset: start,
            fingerprint: &span_fp,
            // ISS-010 preflight:redaction crate 已产出 `redacted_text`,把原文替换视为
            // "已脱敏";blocked / allowed_once 语义留给下游(e.g. session-exempt 放行)。
            action_taken: "redacted",
        })?;
    }
    Ok(())
}

/// 取 `sha256(bytes)` 的前 16 字节(32 个 hex 字符,lowercase),对齐 audit 的 `validate_fingerprint`。
fn sha256_prefix16_hex(bytes: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update(bytes);
    let digest = h.finalize();
    let mut s = String::with_capacity(32);
    for b in digest.iter().take(16) {
        // 显式 lowercase hex,避免依赖 hex crate 的默认行为改变
        s.push_str(&format!("{b:02x}"));
    }
    s
}

/// preflight 运行结果:聚合后的 summary + 累加 risk delta + 每 label 条数(供审计 reasons)。
///
/// 由 `Firewall::evaluate` 消费:summary 进 `PolicyContext.pii_findings`,risk_delta
/// 饱和加到 `PolicyContext.risk_score`,`by_label_counts` 进 `DecisionRecord.reasons`。
pub(crate) struct PreflightOutcome {
    pub(crate) pii_summary: Vec<PiiFindingSummary>,
    pub(crate) risk_delta: u32,
    /// v0.8 Sprint 1 A2 — scanner 层退化状态聚合(取多文本中的"最严重"等级)。
    ///
    /// 聚合优先级(高到低):`DegradedError` > `DegradedTimeout` > `Ok` > `Unsupported`。
    /// `Firewall::evaluate` 收到 `DegradedError` / `DegradedTimeout` 必须落
    /// `engine_degraded` 审计 + 在 decision_reasons 加 stable code。
    /// `Ok` / `Unsupported` 不写审计(无信息可写)。
    pub(crate) engine_status: EngineStatusReport,
}

impl PreflightOutcome {
    /// 返回 label → count 的有序列表(供 reasons 构造使用)。
    pub(crate) fn counts_csv(&self) -> String {
        self.pii_summary
            .iter()
            .map(|s| format!("{}={}", s.label, s.count))
            .collect::<Vec<_>>()
            .join(",")
    }
}

/// preflight 错误:scan 失败走 fail-closed。
///
/// - `EmptyInput` **不**走此路径(`extract_long_text_fields` 按 threshold ≥ 1 过滤,
///   不会把空字符串送进 scan;即便送了,caller 也应把 EmptyInput 当 continue 处理)。
pub(crate) enum PreflightError {
    /// scanner 返非 EmptyInput 的其他 Err(目前只有 `InferenceFailed`,留给 ISS-008)
    ScanFailed { reason: String },
}

/// **R2 MUST-FIX 2 修复**:preflight 审计写失败累计(无原文;原 `eprintln!` stderr 污染
/// 已删除)。`Firewall::audit_persist_failures()` 暴露只读 snapshot,运维 / 测试可据此
/// 判断是否出现审计静默丢失。
pub(crate) type AuditPersistCounter = AtomicU64;

/// 跑一次完整的 preflight:扫所有长文本 → 累加 findings + risk_delta → 同时最佳努力写审计。
///
/// `scanner` 走 [`PiiScanner`] trait,生产默认 [`DefaultScanner`];测试可注入失败 scanner
/// 真触发 fail-closed 路径(见 tests/preflight.rs::preflight_fail_closed_on_scan_err)。
///
/// caller 拿到 `Ok(PreflightOutcome)` 正常流程;拿到 `Err` 必须把决策翻成 Deny + 返错。
/// `audit_failures` 在 audit 写失败时原子递增;caller 可事后查询,不走 stderr 污染路径。
pub(crate) fn run_preflight(
    scanner: &dyn PiiScanner,
    ledger: &Ledger,
    audit_failures: &AuditPersistCounter,
    session_id: &str,
    args: &serde_json::Value,
    threshold: usize,
) -> Result<PreflightOutcome, PreflightError> {
    let long_texts = extract_long_text_fields(args, threshold);

    // label → 累加条数;label 来自 PrivacyLabel::as_str() 字面量(稳定契约)
    let mut by_label: BTreeMap<&'static str, u32> = BTreeMap::new();
    let mut total_risk_delta: u32 = 0;
    // v0.8 Sprint 1 A2 — worst-status 聚合。
    // **R1 MUST-FIX(Codex 019de925)**:初始值必须是 `Unsupported` 而非 `Ok` —
    // 否则 scanner 走 default(全程返 Unsupported)的路径会被错误聚合为 Ok,
    // 复活 Codex § 2 改进版 A 严防的"fake-safe Ok"(虽然当前 engine.rs 对 Ok 不写
    // audit/reasons,行为上看不到差别,但 PreflightOutcome.engine_status 字段
    // 本身的语义会被破坏 —— "全 default scanner ≠ 全部正常完成扫描")。
    // 优先级:DegradedError > DegradedTimeout > Ok > Unsupported(`Ok > Unsupported`
    // 保持不变,让真"扫过且 Ok"覆盖"未上报"。)
    let mut worst_status = EngineStatusReport::Unsupported;

    for text in &long_texts {
        match scanner.scan_with_status(text) {
            Ok((result, status)) => {
                // 状态聚合:取严重度更高者
                worst_status = elevate_status(worst_status, status);

                // 累加 label × count(透传 aggregate_risk 口径)
                for (label, cnt) in &result.risk_signals.counts_by_label {
                    *by_label.entry(label.as_str()).or_insert(0) += cnt;
                }
                total_risk_delta = total_risk_delta.saturating_add(compute_pii_risk_delta(&result));

                // 最佳努力落审计:失败只原子计数,**不**污染 stderr、**不**阻断决策。
                // 运维通过 `Firewall::audit_persist_failures()` 读 snapshot。
                if persist_scan_to_ledger(ledger, session_id, text, &result).is_err() {
                    audit_failures.fetch_add(1, Ordering::Relaxed);
                }
            }
            Err(ScanError::EmptyInput) => {
                // 不该 happen(threshold 过滤了空串);保守 continue。
                continue;
            }
            // T4 ISS-008 Phase 2 secret-hygiene:固定字面量 reason,**严禁** Debug 拼接。
            // ORT/tokenizer error 的 Display/Debug 可能携带输入文本片段(spike 实测
            // tokenizer "encode" 错误会含 token 字符串),Debug 拼接会让原文回显到
            // audit ledger 的 DecisionRecord.reasons,违反 secret-hygiene 不变量。
            // caller 需要细粒度信息时,改去 ledger redaction_scans / redaction_findings
            // 或 stderr 跑诊断;DecisionRecord 只记稳定 code。
            Err(ScanError::InferenceFailed { .. }) => {
                return Err(PreflightError::ScanFailed {
                    reason: "t0_inference_failed".to_string(),
                });
            }
            // 兜底:未来 ScanError 新 variant 一律塌缩到稳定字面量,绝不 Debug 拼接。
            // 当前(2026-04-29)ScanError 仅 EmptyInput + InferenceFailed 两个 variant,
            // 编译期 reachable 但保留对未来扩展的 forward-compat。
            #[allow(unreachable_patterns)]
            Err(_other) => {
                return Err(PreflightError::ScanFailed {
                    reason: "t0_scan_failed".to_string(),
                });
            }
        }
    }

    let pii_summary: Vec<PiiFindingSummary> = by_label
        .into_iter()
        .map(|(label, count)| PiiFindingSummary {
            label: label.to_string(),
            count,
        })
        .collect();

    Ok(PreflightOutcome {
        pii_summary,
        risk_delta: total_risk_delta,
        engine_status: worst_status,
    })
}

/// v0.8 Sprint 1 A2 — 取两个 status 中"更严重"者(用于多 text 循环聚合)。
///
/// 严重度从高到低:`DegradedError` > `DegradedTimeout` > `Ok` > `Unsupported`。
/// 这是 firewall 视角的安全顺序 —— degraded 必须可见,Unsupported 是 scanner 实现层面的"无信息",
/// 不应覆盖 Ok(Ok 是真"扫过且正常",Unsupported 是"未上报",前者信息量更高)。
fn elevate_status(a: EngineStatusReport, b: EngineStatusReport) -> EngineStatusReport {
    fn rank(s: EngineStatusReport) -> u8 {
        // crate 内部穷举;加新 variant 时 compiler force update,作者必须显式选 rank
        // (新 variant 应归到 Degraded 类 ≥ 2 或独立优先级,不可默认 0 = 静默降级到
        // Unsupported)。这条规则比 runtime `_ => 0` 更强。
        match s {
            EngineStatusReport::DegradedError => 3,
            EngineStatusReport::DegradedTimeout => 2,
            EngineStatusReport::Ok => 1,
            EngineStatusReport::Unsupported => 0,
        }
    }
    if rank(a) >= rank(b) {
        a
    } else {
        b
    }
}

/// 便利构造:生产默认 scanner 作为 `Arc<dyn PiiScanner>`,供 `Firewall::new` 使用。
pub(crate) fn default_scanner_arc() -> Arc<dyn PiiScanner> {
    Arc::new(DefaultScanner)
}

// ──────────────────────────── ISS-008 Phase 2 T2:OrtPiiScanner ────────────────────────────
//
// Wrapper 把 [`vigil_redaction::OrtEngine`] 适配成 [`PiiScanner`] trait object,
// 让 `Firewall::with_scanner` 能透明替换默认 [`DefaultScanner`]。
//
// **SSOT 纪律**:wrapper 内**不**复制 merge / risk / redact 逻辑,全部委托
// `vigil_redaction::scan_text_with_engine`(同 `scan_text` 的 hard×model 决策路径)。
//
// **可见性**:`OrtPiiScanner` 类型本身保持 crate-private(T3 决议),外部只能通过
// `ort_scanner_arc_from_env()` 工厂拿到 `Arc<dyn PiiScanner>`,避免泄漏 ort 类型边界。

/// 仅在 `--features ort` 启用时编译。
#[cfg(feature = "ort")]
mod ort_scanner {
    use std::sync::Arc;
    use std::time::Duration;

    use vigil_redaction::{
        scan_text_with_engine, scan_text_with_engine_budgeted, OrtEngine, RedactionEngine,
        RedactionResult, ScanError,
    };

    use super::{EngineStatusReport, PiiScanner};

    /// `Arc<OrtEngine>` 适配为 `PiiScanner`。Send + Sync 由 `OrtEngine` 自身保证
    /// (engine.rs::ort_static_assertions::_check 编译期守门)。
    pub(crate) struct OrtPiiScanner {
        engine: Arc<OrtEngine>,
    }

    impl OrtPiiScanner {
        pub(crate) fn new(engine: Arc<OrtEngine>) -> Self {
            Self { engine }
        }
    }

    impl PiiScanner for OrtPiiScanner {
        fn scan(&self, text: &str) -> Result<RedactionResult, ScanError> {
            // SSOT 在 vigil-redaction;wrapper 不复制 merge/risk/redact 逻辑。
            scan_text_with_engine(text, &*self.engine)
        }
    }

    /// v0.7-α2 Phase 2D-fw(ADR 0016 § 5.4):带 budget 的 OrtPiiScanner 包装。
    ///
    /// 模型路径在 `budget` 内未完成 → 自动退化 Hard-only,fail-closed 保留(secret
    /// 类硬规则仍命中)。本 wrapper 内部走 [`scan_text_with_engine_budgeted`],
    /// 把 `BudgetedScanOutcome { result, status }` 中的 `status` **吞掉**(状态
    /// 不透出 `PiiScanner` trait,避免 SemVer breaking;退化决策在 budget 层完成,
    /// 等价"模型路径无信号" — 与 NoopEngine 路径行为对齐)。
    ///
    /// **caller 视角**:scan 仍返 `Result<RedactionResult, ScanError>`,语义同
    /// 默认 OrtPiiScanner;**唯一区别**是 timeout/error 不会卡住 firewall preflight,
    /// 而是退化到 Hard-only 后继续走 PolicyEngine 决策。
    pub(crate) struct BudgetedOrtPiiScanner {
        engine: Arc<OrtEngine>,
        budget: Duration,
    }

    impl BudgetedOrtPiiScanner {
        pub(crate) fn new(engine: Arc<OrtEngine>, budget: Duration) -> Self {
            Self { engine, budget }
        }
    }

    impl PiiScanner for BudgetedOrtPiiScanner {
        fn scan(&self, text: &str) -> Result<RedactionResult, ScanError> {
            // 兼容路径:legacy `scan` 仍丢弃 status(保持 SemVer);新 caller 应走
            // `scan_with_status` 拿到真实退化标记。
            self.scan_with_status(text).map(|(r, _status)| r)
        }

        /// v0.8 Sprint 1 A2 — override 透出真实退化状态。
        ///
        /// `BudgetedScanOutcome.status` 三态 (`Ok` / `DegradedTimeout` / `DegradedError`)
        /// 经 `From<vigil_redaction::EngineStatus>` 映射为 `EngineStatusReport`,
        /// 永不返 `Unsupported`(本 scanner 实现自带 budget 路径)。
        ///
        /// caller(`Firewall::evaluate`)拿到 `DegradedTimeout` / `DegradedError` 应:
        /// 1. 落 audit `engine_degraded` 事件(reason_code = stable_code())
        /// 2. decision_reasons.push("engine.status=<stable_code>")
        /// 3. 仍走 PolicyEngine 决策(已退化为 Hard-only,fail-closed 路径)
        fn scan_with_status(
            &self,
            text: &str,
        ) -> Result<(RedactionResult, EngineStatusReport), ScanError> {
            let engine: Arc<dyn RedactionEngine> = Arc::clone(&self.engine) as _;
            scan_text_with_engine_budgeted(text, engine, self.budget)
                .map(|outcome| (outcome.result, outcome.status.into()))
        }
    }

    /// v0.7-α5 R1g+(E6a)— 三引擎 ensemble 适配 PiiScanner trait。
    ///
    /// **架构**:`EnsembleEngine` 内部并联 OpenAI / xlmr / yonigo 三 OrtEngine,
    /// `scan_text_with_engine` 走完整 Hard rules + ensemble model union + ADR 0013
    /// merge。SSOT 在 vigil-redaction,wrapper 不复制逻辑。
    ///
    /// **lazy-load 决策**(Codex § 3 ACCEPT):**eager load**(构造时三模型同时 init)。
    /// 1.4-2.2GB RSS 由 caller 决策(企业 release runner 接受;default 用 single-engine
    /// path);真 lazy-load 推 v0.7-α6+。
    ///
    /// **budget 不暴露**(R1g+ 简化):budget 模式需 `EnsembleEngine: Clone`,
    /// 当前未实现;budget 路径推 v0.7-α6+。无 budget 模式 worst-case warm 856ms
    /// 实测 ≤ 1500ms ADR 0016 ensemble SLO,production 可接受。
    ///
    /// **fail-closed 保留**:任一 engine init 失败即 `EngineError::ModelNotFound` /
    /// `SessionInit`(沿用 ADR 0012 fail-fast);scan 路径 engine.infer Err
    /// → `ScanError::InferenceFailed`。
    pub(crate) struct EnsembleOrtPiiScanner {
        ensemble: vigil_redaction::EnsembleEngine,
    }

    impl EnsembleOrtPiiScanner {
        #[allow(dead_code)] // 留给纯 engines 路径(无 dual_confirm 简化构造)
        pub(crate) fn new(engines: Vec<Arc<dyn RedactionEngine>>) -> Self {
            Self {
                ensemble: vigil_redaction::EnsembleEngine::new(engines),
            }
        }

        /// v0.7-α5 A step:已配置好的 EnsembleEngine 注入(支持 with_dual_confirm)
        pub(crate) fn from_ensemble(ensemble: vigil_redaction::EnsembleEngine) -> Self {
            Self { ensemble }
        }
    }

    impl PiiScanner for EnsembleOrtPiiScanner {
        fn scan(&self, text: &str) -> Result<RedactionResult, ScanError> {
            // 走 scan_text_with_engine 完整路径(Hard rules + model ensemble
            // union + merge_findings + ADR 0013 D1-D6 决策)
            scan_text_with_engine(text, &self.ensemble)
        }

        // **v0.8 Sprint 1 A2 决策**:故意**不**override `scan_with_status`,
        // 走 trait default 返 `EngineStatusReport::Unsupported`。
        //
        // 理由:`EnsembleEngine` 当前 R1g+ 简化版**未实现 budget 路径**(无
        // `EnsembleEngine: Clone`,`scan_text_with_engine_budgeted` 不可用)。
        // ensemble 内任一 engine 长尾 → 整 scan 长尾,无 timeout 退化。
        //
        // caller(`Firewall::evaluate`)拿到 `Unsupported` 必须显式判:
        // - 不写 audit `engine_degraded` 事件(无信息可写)
        // - 不加 decision_reasons "engine.status=*"(无状态可报)
        // - 走正常决策路径(scan 真 fail 仍走 fail-closed Deny via ScanError)
        //
        // ensemble + budget 路径推 v0.8+(ADR 0017 Revised § A2 留待 Sprint 3 dual_confirm
        // calibration 后再看是否引入 EnsembleEngine: Clone)。
    }
}

/// 工厂:从 `VIGIL_PRIVACY_FILTER_MODEL_DIR` 同步加载 OrtEngine 并包成
/// `Arc<dyn PiiScanner>`,供 `Firewall::with_scanner` 注入。
///
/// **启动期 fail-fast**:cold-start ~7 s 在此一次性吃掉(模型加载 + Session
/// commit_from_file),首请求 SLA 不再受影响。错误(env unset / 模型缺失 / ORT
/// 初始化失败)直接返 [`vigil_redaction::engine::EngineError`],由 caller
/// (vigil-hub-cli `serve.rs::build_hub`)塌缩到 `ServeError::PrivacyFilterInit`
/// 启动失败,**不**降级为 NoopEngine。
///
/// # Errors
/// 见 [`vigil_redaction::engine::EngineError`] 的 6 个变体(ModelNotFound /
/// TokenizerLoad / SessionInit / InferRun / DecodeShape / Internal)。
#[cfg(feature = "ort")]
pub fn ort_scanner_arc_from_env(
) -> Result<Arc<dyn PiiScanner>, vigil_redaction::engine::EngineError> {
    let engine = Arc::new(vigil_redaction::OrtEngine::from_env()?);
    Ok(Arc::new(ort_scanner::OrtPiiScanner::new(engine)))
}

/// v0.7-α5 R1g+(E6a)— 三引擎 ensemble 工厂(production firewall 集成)。
///
/// 把 `vigil_redaction::EnsembleEngine`(openai + xlmr + yonigo)包成
/// `Arc<dyn PiiScanner>`,供 `Firewall::with_scanner` 注入。
///
/// **使用场景**:企业 release runner / 自有部署需要 multilang recall,接受
/// 1.4-2.2GB RAM 代价。Default firewall 路径(GUI / hub-cli)推荐继续用
/// [`ort_scanner_arc_from_env`] 单 OpenAI engine(838MB RAM)。
///
/// **三 dir env vars**(若任一缺即 fail-fast):
/// - `VIGIL_ENSEMBLE_OPENAI_DIR`(OpenAI Privacy Filter v1)
/// - `VIGIL_ENSEMBLE_XLMR_DIR`(xlmr-pii-v1)
/// - `VIGIL_ENSEMBLE_YONIGO_DIR`(yonigo-pii-v1)
///
/// **eager load**:构造时三 OrtEngine 同时 init(总 ~17s cold,与 spike-3 对齐)。
/// 真 lazy-load + warmup 推 v0.7-α6+。
///
/// # Errors
/// 任一 dir env 缺失 / 模型缺失 / ORT init 失败 → `EngineError`(沿用 ADR 0012
/// fail-fast,绝不降级)。
#[cfg(feature = "ort")]
pub fn ort_ensemble_scanner_arc_from_env(
) -> Result<Arc<dyn PiiScanner>, vigil_redaction::engine::EngineError> {
    // **v0.10 Sprint 1**:legacy 路径 → xlmr_mode = None(env-driven xlmr profile)
    build_ort_ensemble_scanner_arc_from_env(None)
}

/// **v0.10 Sprint 1 F 续** — typed `XlmrProfileMode` ensemble 工厂入口。
///
/// 与 [`ort_ensemble_scanner_arc_from_env`] 区别:caller 显式传 typed
/// [`vigil_redaction::model_descriptor::XlmrProfileMode`],**忽略**
/// `VIGIL_XLMR_PROFILE` env(SDK reproducible / inspectable)。
///
/// 三 model dir env 仍读(`VIGIL_ENSEMBLE_OPENAI_DIR` / `_XLMR_DIR` / `_YONIGO_DIR`)—
/// 这些是 ops 部署配置,不是 SDK consumer 责任。
///
/// **典型场景**:SDK consumer 想 reproducible 走 `XlmrProfileMode::Default`(v0.8
/// baseline)或显式 opt-in `XlmrProfileMode::FpStrict`(企业 / 高 FP 容忍度)
/// 而**不**依赖 env(避免 env 漂移)。
///
/// # Errors
/// 同 [`ort_ensemble_scanner_arc_from_env`]:env unset / 模型缺失 / ORT init
/// 失败 → `EngineError`。
#[cfg(feature = "ort")]
pub fn ort_ensemble_scanner_arc_from_env_with_xlmr_mode(
    xlmr_mode: vigil_redaction::model_descriptor::XlmrProfileMode,
) -> Result<Arc<dyn PiiScanner>, vigil_redaction::engine::EngineError> {
    build_ort_ensemble_scanner_arc_from_env(Some(xlmr_mode))
}

/// internal helper — 共享 3 model dir env 读 + EnsembleEngine 构造 + dual_confirm
/// env;`xlmr_mode = None` 走 legacy env,`Some(_)` 走 typed 路径(忽略 env)。
#[cfg(feature = "ort")]
fn build_ort_ensemble_scanner_arc_from_env(
    xlmr_mode: Option<vigil_redaction::model_descriptor::XlmrProfileMode>,
) -> Result<Arc<dyn PiiScanner>, vigil_redaction::engine::EngineError> {
    use std::path::PathBuf;
    use vigil_redaction::engine::EngineError;
    use vigil_redaction::model_descriptor::{
        OpenAIPrivacyFilterDescriptor, XlmrPiiDescriptor, YonigoPiiDescriptor,
    };

    let openai_dir = std::env::var("VIGIL_ENSEMBLE_OPENAI_DIR")
        .map(PathBuf::from)
        .map_err(|_| EngineError::ModelNotFound {
            dir: "<VIGIL_ENSEMBLE_OPENAI_DIR unset>".to_string(),
        })?;
    let xlmr_dir = std::env::var("VIGIL_ENSEMBLE_XLMR_DIR")
        .map(PathBuf::from)
        .map_err(|_| EngineError::ModelNotFound {
            dir: "<VIGIL_ENSEMBLE_XLMR_DIR unset>".to_string(),
        })?;
    let yonigo_dir = std::env::var("VIGIL_ENSEMBLE_YONIGO_DIR")
        .map(PathBuf::from)
        .map_err(|_| EngineError::ModelNotFound {
            dir: "<VIGIL_ENSEMBLE_YONIGO_DIR unset>".to_string(),
        })?;

    // v0.10 Sprint 1:xlmr descriptor 按 mode 选择
    let xlmr_descriptor = match xlmr_mode {
        Some(mode) => XlmrPiiDescriptor::with_mode(mode), // typed,忽略 env
        None => XlmrPiiDescriptor::default(),             // legacy env-driven
    };

    let openai = Arc::new(vigil_redaction::OrtEngine::from_dir_with_descriptor(
        &openai_dir,
        Box::new(OpenAIPrivacyFilterDescriptor),
    )?);
    let xlmr = Arc::new(vigil_redaction::OrtEngine::from_dir_with_descriptor(
        &xlmr_dir,
        Box::new(xlmr_descriptor),
    )?);
    let yonigo = Arc::new(vigil_redaction::OrtEngine::from_dir_with_descriptor(
        &yonigo_dir,
        Box::new(YonigoPiiDescriptor),
    )?);

    let engines: Vec<Arc<dyn vigil_redaction::RedactionEngine>> = vec![openai, xlmr, yonigo];

    // v0.7-α5 A step:可选 dual_confirm via env var(comma-separated canonical labels)
    // 示例:VIGIL_ENSEMBLE_DUAL_CONFIRM=address,date,account_number
    // 不设 = 关闭(原 R1h union 行为)
    let ensemble = vigil_redaction::EnsembleEngine::new(engines);
    let ensemble = if let Ok(s) = std::env::var("VIGIL_ENSEMBLE_DUAL_CONFIRM") {
        let labels: Vec<vigil_redaction::PrivacyLabel> = s
            .split(',')
            .filter_map(|t| {
                let trimmed = t.trim().to_lowercase();
                vigil_redaction::PrivacyLabel::from_kind(&trimmed)
            })
            .collect();
        if !labels.is_empty() {
            ensemble.with_dual_confirm(labels)
        } else {
            ensemble
        }
    } else {
        ensemble
    };

    Ok(Arc::new(ort_scanner::EnsembleOrtPiiScanner::from_ensemble(
        ensemble,
    )))
}

/// v0.7-α2 Phase 2D-fw(ADR 0016 § 5.4):带 budget 的 OrtPiiScanner 工厂。
///
/// 与 [`ort_scanner_arc_from_env`] 唯一区别:scan 路径走
/// [`vigil_redaction::scan_text_with_engine_budgeted`],模型推理超 `budget` 即
/// 退化 Hard-only(fail-closed 保留;secret 类硬规则仍命中)。
///
/// **生产推荐 budget**:`Duration::from_secs(2)`(ADR 0016 Enhanced path warm < 1s
/// 上界 + 50% 余量,避免极端慢请求把 firewall preflight 卡住)。
///
/// **status 透出**:本 Phase 2D-fw 极简集成,timeout/error 退化路径在 wrapper 内
/// 吞掉 status(行为等同模型路径无信号)。decision_reasons 审计标 + ledger
/// 'engine.degraded' 事件留 v0.7-α3 实施。
///
/// # Errors
/// 同 [`ort_scanner_arc_from_env`]:env unset / 模型缺失 / ORT init 失败时返
/// [`vigil_redaction::engine::EngineError`]。
#[cfg(feature = "ort")]
pub fn ort_scanner_arc_from_env_with_budget(
    budget: std::time::Duration,
) -> Result<Arc<dyn PiiScanner>, vigil_redaction::engine::EngineError> {
    let engine = Arc::new(vigil_redaction::OrtEngine::from_env()?);
    Ok(Arc::new(ort_scanner::BudgetedOrtPiiScanner::new(
        engine, budget,
    )))
}

#[cfg(test)]
#[allow(clippy::panic)] // 测试内 panic! 是合法失败信号
mod tests {
    use super::*;

    #[test]
    fn extract_long_text_fields_threshold_filters_short() {
        // threshold=100:短于 100 的字符串被过滤
        let args = serde_json::json!({
            "short": "hi",
            "long": "x".repeat(150),
        });
        let out = extract_long_text_fields(&args, 100);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].len(), 150);
    }

    #[test]
    fn extract_long_text_fields_recursive_arrays_and_objects() {
        let args = serde_json::json!({
            "outer": {
                "nested": ["a", "b".repeat(50)],
                "deep": { "leaf": "c".repeat(80) }
            }
        });
        let out = extract_long_text_fields(&args, 30);
        // 命中两条:b*50 + c*80
        assert_eq!(out.len(), 2);
    }

    #[test]
    fn extract_long_text_fields_null_args_returns_empty() {
        let out = extract_long_text_fields(&serde_json::Value::Null, 100);
        assert!(out.is_empty());
        let out2 = extract_long_text_fields(&serde_json::json!({}), 100);
        assert!(out2.is_empty());
    }

    #[test]
    fn extract_long_text_fields_skips_numbers_and_booleans() {
        let args = serde_json::json!({
            "n": 12345,
            "b": true,
            "s": "x".repeat(120),
        });
        let out = extract_long_text_fields(&args, 100);
        assert_eq!(out.len(), 1);
    }

    #[test]
    fn sha256_prefix16_hex_is_32_lowercase_chars() {
        let fp = sha256_prefix16_hex(b"hello world");
        assert_eq!(fp.len(), 32);
        assert!(fp
            .chars()
            .all(|c| c.is_ascii_hexdigit() && !c.is_uppercase()));
    }

    #[test]
    fn compute_pii_risk_delta_transparent_to_signals() {
        // 构造一个带已知 total_risk_delta 的 RedactionResult(走真 scan_text)
        let text = "junk ghp_abcdefghijklmnopqrstuvwxyzABCDEFGHIJ more";
        let r = vigil_redaction::scan_text(text).expect("non-empty");
        let delta = compute_pii_risk_delta(&r);
        assert!(
            delta >= 25,
            "Secret 类应至少 25,实际 {delta}(signals={:?})",
            r.risk_signals
        );
    }

    /// local mock,等价 tests/preflight.rs 的 TestFailingScanner。
    struct LocalFailingScanner;
    impl PiiScanner for LocalFailingScanner {
        fn scan(&self, _: &str) -> Result<RedactionResult, ScanError> {
            Err(ScanError::InferenceFailed {
                reason: "unit-test".into(),
            })
        }
    }

    #[test]
    fn failing_scanner_propagates_inference_failed() {
        // R2 BLOCKER 2:新增正向测试证本地 failing scanner impl 正确(真 fail-closed 路径)
        let s = LocalFailingScanner;
        match s.scan("some text") {
            Err(ScanError::InferenceFailed { reason }) => {
                assert_eq!(reason, "unit-test");
            }
            other => panic!("local failing scanner should return InferenceFailed, got {other:?}"),
        }
    }

    #[test]
    fn default_scanner_forwards_to_scan_text() {
        // DefaultScanner 与 vigil_redaction::scan_text 语义一致(空输入 Err)
        let s = DefaultScanner;
        match s.scan("") {
            Err(ScanError::EmptyInput) => {}
            other => panic!("DefaultScanner('') should be EmptyInput, got {other:?}"),
        }
    }

    // ─────────── v0.8 Sprint 1 A2 — R1 NICE(Codex 019de925)守门 ───────────

    /// `elevate_status` 严重度全序检查。锁定 Codex § 2 改进版 A 的安全顺序:
    /// `DegradedError > DegradedTimeout > Ok > Unsupported`。
    /// `Ok > Unsupported` 是设计 — 真"扫过且 Ok"覆盖"未上报"(default scanner)。
    #[test]
    fn elevate_status_total_order_safety() {
        use EngineStatusReport::*;
        // 自反:任何状态 elevate 自己 == 自己
        for s in [DegradedError, DegradedTimeout, Ok, Unsupported] {
            assert_eq!(elevate_status(s, s), s);
        }
        // 严格递减序对(右更严重 → 取右)
        assert_eq!(elevate_status(Unsupported, Ok), Ok);
        assert_eq!(elevate_status(Ok, DegradedTimeout), DegradedTimeout);
        assert_eq!(
            elevate_status(DegradedTimeout, DegradedError),
            DegradedError
        );
        assert_eq!(elevate_status(Unsupported, DegradedError), DegradedError);
        // 对称(参数交换不改变结果)
        assert_eq!(elevate_status(Ok, Unsupported), Ok);
        assert_eq!(elevate_status(DegradedError, Ok), DegradedError);
    }

    /// **R1 MUST-FIX 守门(Codex 019de925)**:scanner 走 trait default
    /// (不 override `scan_with_status` → 全程返 Unsupported)时,
    /// `run_preflight` 必须真实返 `outcome.engine_status == Unsupported`,
    /// **不**得被聚合错误升级为 Ok(fake-safe Ok)。
    ///
    /// 这是直接验证字段语义,补 tests/preflight.rs 那条只观察 audit/reasons
    /// 副作用的负向测试盲区(NICE 项 — 之前那条即使 outcome 报 Ok 也会过)。
    #[test]
    fn run_preflight_with_default_status_scanner_yields_unsupported() {
        struct LocalDefaultStatusScanner;
        impl PiiScanner for LocalDefaultStatusScanner {
            fn scan(&self, _text: &str) -> Result<RedactionResult, ScanError> {
                Ok(RedactionResult {
                    findings: Vec::new(),
                    redacted_text: String::new(),
                    risk_signals: vigil_redaction::RiskSignals::default(),
                })
            }
            // 故意不 override scan_with_status → 走 trait default 返 Unsupported
        }

        let ledger = vigil_audit::Ledger::open_in_memory().expect("open_in_memory");
        let sid = ledger
            .start_session("a2-r1-test", Some("default_status_unsupported"))
            .expect("start_session");
        let counter = AuditPersistCounter::new(0);
        let args = serde_json::json!({ "long": "x".repeat(200) });

        let outcome = run_preflight(
            &LocalDefaultStatusScanner,
            &ledger,
            &counter,
            &sid,
            &args,
            100,
        )
        .unwrap_or_else(|_| panic!("run_preflight should succeed with non-failing scanner"));

        assert_eq!(
            outcome.engine_status,
            EngineStatusReport::Unsupported,
            "default scan_with_status path 必须聚合为 Unsupported,**不**得被 fake-safe 升级为 Ok;\
             这是 Codex § 2 改进版 A 的关键不变量(R1 MUST-FIX 锁定项)"
        );
    }

    /// 反向对照:scanner override `scan_with_status` 真返 Ok 时,
    /// `run_preflight` outcome.engine_status 应为 Ok(不是 Unsupported)。
    /// 与上一测共同钉死"`Ok > Unsupported` 顺序在多 text 聚合下生效"。
    #[test]
    fn run_preflight_with_real_ok_status_overrides_unsupported() {
        struct LocalOkStatusScanner;
        impl PiiScanner for LocalOkStatusScanner {
            fn scan(&self, _text: &str) -> Result<RedactionResult, ScanError> {
                Ok(RedactionResult {
                    findings: Vec::new(),
                    redacted_text: String::new(),
                    risk_signals: vigil_redaction::RiskSignals::default(),
                })
            }
            fn scan_with_status(
                &self,
                text: &str,
            ) -> Result<(RedactionResult, EngineStatusReport), ScanError> {
                self.scan(text).map(|r| (r, EngineStatusReport::Ok))
            }
        }

        let ledger = vigil_audit::Ledger::open_in_memory().unwrap();
        let sid = ledger
            .start_session("a2-r1-test", Some("ok_overrides"))
            .unwrap();
        let counter = AuditPersistCounter::new(0);
        let args = serde_json::json!({ "long": "x".repeat(200) });

        let outcome = run_preflight(&LocalOkStatusScanner, &ledger, &counter, &sid, &args, 100)
            .unwrap_or_else(|_| panic!("run_preflight should succeed with ok scanner"));
        assert_eq!(
            outcome.engine_status,
            EngineStatusReport::Ok,
            "真 Ok status 必须覆盖初始 Unsupported(`Ok > Unsupported` 严重度)"
        );
    }

    // ─────────── v0.7-α2 Phase 2D-fw(ADR 0016 § 5.4)守门 ───────────
    //
    // 工厂 ort_scanner_arc_from_env_with_budget 的真行为测试需要真 OrtEngine env
    // (VIGIL_PRIVACY_FILTER_MODEL_DIR + 838MB 模型 + onnxruntime.dll),
    // 与 [`ort_scanner_arc_from_env`] 同走 Linux release runner gate。本守门只验
    // env 缺失时**不 panic**且返 ModelNotFound — 这是 fail-fast 不变量(ADR 0012)。

    /// v0.7-α5 R1g+ — ensemble 工厂在 3 dir env 缺失时返 ModelNotFound 不 panic
    /// (沿用 ADR 0012 § fail-fast on env miss);开发机已设 env 时 graceful skip。
    #[cfg(feature = "ort")]
    #[test]
    fn ort_ensemble_scanner_arc_from_env_missing_envs_returns_modelnotfound() {
        let any_set = [
            "VIGIL_ENSEMBLE_OPENAI_DIR",
            "VIGIL_ENSEMBLE_XLMR_DIR",
            "VIGIL_ENSEMBLE_YONIGO_DIR",
        ]
        .iter()
        .any(|k| std::env::var(k).is_ok());
        if any_set {
            eprintln!("skip: VIGIL_ENSEMBLE_*_DIR already set");
            return;
        }
        let r = ort_ensemble_scanner_arc_from_env();
        match r {
            Err(vigil_redaction::engine::EngineError::ModelNotFound { dir }) => {
                assert!(
                    dir.contains("VIGIL_ENSEMBLE_") && dir.contains("unset"),
                    "ModelNotFound.dir 应含 VIGIL_ENSEMBLE_ env 名,实际: {}",
                    dir
                );
            }
            other => panic!(
                "env unset 应返 ModelNotFound,实际: {:?}",
                other.map(|_| "Ok(scanner)")
            ),
        }
    }

    /// 工厂在 env 缺失时应返 ModelNotFound 不 panic(贯彻 ADR 0012 § fail-fast)。
    /// **不**改环境变量(Rust 2024 env::set_var 是 unsafe);测试在 CI 默认 env unset
    /// 状态下生效;若开发机已设 env(常见),测试 graceful skip。
    #[cfg(feature = "ort")]
    #[test]
    fn ort_scanner_arc_from_env_with_budget_env_miss_returns_modelnotfound() {
        if std::env::var("VIGIL_PRIVACY_FILTER_MODEL_DIR").is_ok() {
            // 已设(开发机或 release runner)→ skip,避免触发真模型加载 7s
            eprintln!("skip: VIGIL_PRIVACY_FILTER_MODEL_DIR already set");
            return;
        }
        let r = ort_scanner_arc_from_env_with_budget(std::time::Duration::from_secs(1));
        match r {
            Err(vigil_redaction::engine::EngineError::ModelNotFound { .. }) => {}
            other => panic!(
                "env unset 应返 ModelNotFound,实际: {:?}",
                other.map(|_| "Ok(scanner)")
            ),
        }
    }
}
