//! Firewall 高层缝合:extract → score → policy → 产出 `FirewallOutcome`。

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;

use sha2::{Digest, Sha256};
use thiserror::Error;
use uuid::Uuid;
use vigil_audit::{ApprovalTargetContext, EngineDegradedPayload, Ledger, Result as AuditResult};
use vigil_policy::{
    DescriptorState, PolicyAction, PolicyContext, PolicyDecision, PolicyEngine, PolicyError,
};
use vigil_types::{ApprovalRequest, DecisionKind, DecisionRecord, EffectVector, ToolInvocation};

use crate::extract::{
    BrowserActionExtractor, EffectExtractor, EmailExtractor, PathExtractor, SecretRefExtractor,
    ShellExtractor, SqlExtractor, UrlExtractor,
};
use crate::preflight::{run_preflight, EngineStatusReport, PreflightError};
use crate::scorer::{DescriptorOracle, DescriptorStatus, RiskScorer};

/// Firewall 错误。
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum FirewallError {
    /// 策略引擎错误。
    #[error("policy: {0}")]
    Policy(#[from] PolicyError),

    /// 审计写入错误。
    #[error("audit: {0}")]
    Audit(#[from] vigil_audit::AuditError),

    /// I10c-β2 R3 NICE 修复:`FirewallConfig.allowed_scopes` 使用了保留键
    /// `"allowed_hosts"`,会在 `evaluate` 合并步骤覆盖 host allowlist —— 启动期
    /// 硬拒绝,避免误配置破坏 host 白名单语义。
    #[error(
        "config: `allowed_scopes` must not reuse reserved key `allowed_hosts` \
         (host allowlist is managed via `FirewallConfig::allowed_hosts`)"
    )]
    ReservedScopeKey,

    /// ISS-010:T0 preflight 扫描(`vigil_redaction::scan_text`)返错。
    ///
    /// **语义**:安全核心的 fail-closed 路径 —— preflight 是在规则决策**之前**运行的,
    /// 扫描失败意味着我们无法判断本次调用是否带 PII / Secret,必须视为最坏情况。caller
    /// 应把此错误翻译成业务层 Deny(不继续走 policy 评估,也不入 approvals 表)。
    ///
    /// `reason` 由 `ScanError::{InferenceFailed, ..}` 的 Debug 形式派生,不含用户原文。
    #[error("preflight scan failed: {reason}")]
    PreflightScanFailed {
        /// 来自 `vigil_redaction::ScanError` 的 Debug 投影(无用户原文)。
        reason: String,
    },
}

/// Firewall 配置:项目根 / 允许主机 / OAuth scope allowlist / TTL 等。
#[derive(Debug, Clone)]
pub struct FirewallConfig {
    /// POSIX 规范化的项目根目录前缀
    pub project_roots: Vec<String>,
    /// 允许的主机列表(支持 `.github.com` 风格的后缀模式由 policy 的
    /// `host_matches` 实现;Firewall 这层只作为 RiskScorer 与 PolicyContext 的输入)
    pub allowed_hosts: Vec<String>,
    /// I10c-β2(R3 BLOCKER 修复):OAuth scope allowlist 注入通道。
    ///
    /// 键是 `Condition::ScopeNotInAllowList::allowlist_key` 引用的逻辑名
    /// (如 `"oauth_scopes"` / `"github_scopes"` / `"gitlab_scopes"`),值是该 AS
    /// 允许的 scope 白名单。Firewall 在评估前把 entry 合并到 `PolicyContext.allowlists`,
    /// 与 `allowed_hosts`(固定键 `"allowed_hosts"`)并列。
    ///
    /// **命名隔离约定**:请勿在此 map 里使用键 `"allowed_hosts"`,避免与 host allowlist
    /// 冲突;Firewall 不做 runtime 检查(类型上共享 `HashMap<String, Vec<String>>`),
    /// 配置加载层自行保证键不相撞。
    pub allowed_scopes: HashMap<String, Vec<String>>,
    /// 审批 TTL 秒。默认 300(5 分钟)。`0` 表示立即过期(供测试)。
    pub approval_ttl_secs: u64,

    /// ISS-010:T0 preflight 扫描的长文本阈值(字节)。
    ///
    /// `Firewall::evaluate` 递归 `ToolInvocation.args` 里的所有字符串字段,长度 `≥`
    /// 此阈值的才送进 `vigil_redaction::scan_text`。默认 `100`(覆盖典型提示词 / 邮件
    /// 正文 / SQL 大段,放过短工具参数如 `"path": "/etc/hosts"`)。
    ///
    /// **边界**:本阈值以 `str::len()`(UTF-8 bytes)为准,而非字符数;ASCII 场景下
    /// 等同于 char count。取 `0` 等同 "扫所有字符串"(含空串 —— 但空串在 scan_text 层
    /// 会被当 EmptyInput continue,不会误触 fail-closed)。
    pub long_text_threshold: usize,
}

impl Default for FirewallConfig {
    fn default() -> Self {
        Self {
            project_roots: Vec::new(),
            allowed_hosts: Vec::new(),
            allowed_scopes: HashMap::new(),
            approval_ttl_secs: 300,
            // ISS-010:典型 prompt / 粘贴板 / 邮件正文 ≥ 100 bytes,低于此的工具参数
            // 走纯规则引擎,避免为每个 `{"path": "x"}` 调用都跑 regex 扫。
            long_text_threshold: 100,
        }
    }
}

/// I10c-β2(R3 MUST-FIX 修复):调用路径的 OAuth 上下文,显式区分"非 OAuth"与"OAuth + scope"。
///
/// 出现在 [`Firewall::evaluate`] 签名里作为**必填参数**,强制调用方每次调用都明确选择,
/// 防止 HTTP MCP 集成点意外漏配 scope 导致静默绕过。
///
/// - [`OAuthScopeContext::NonOauth`] —— stdio MCP / 本地工具 / 不走 OAuth 的任何路径
/// - [`OAuthScopeContext::Scopes`] —— HTTP MCP + OAuth access token,scope 来自
///   `vigil_http_auth::ResolvedAccessToken::scope_set`(空集也必须显式 `Scopes(vec![])`,
///   触发 `ScopeNotInAllowList` 的 fail-closed 分支)
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum OAuthScopeContext {
    /// 非 OAuth 路径,`ScopeNotInAllowList` 不适用
    NonOauth,
    /// OAuth 路径 + token 携带的 scope 集合(可空 → fail-closed)
    Scopes(Vec<String>),
}

impl OAuthScopeContext {
    fn into_policy_requested_scopes(self) -> Option<Vec<String>> {
        match self {
            OAuthScopeContext::NonOauth => None,
            OAuthScopeContext::Scopes(s) => Some(s),
        }
    }
}

/// Firewall.evaluate() 返回的裁决结果。
///
/// caller(I04 MCP Hub)根据此结果决定:
/// - `Allowed`: 直接执行下游
/// - `Denied`: 对 agent 返回安全错误
/// - `Approve`: 创建 approval 并阻塞 / 异步等待 wait_for_resolution
#[derive(Debug, Clone)]
#[non_exhaustive]
pub enum FirewallOutcome {
    /// 放行。
    Allowed {
        /// 决策记录(已写入账本)
        decision: DecisionRecord,
        /// 推断出的 effects
        effects: EffectVector,
    },
    /// 拒绝。
    Denied {
        /// 决策记录(已写入账本)
        decision: DecisionRecord,
        /// 推断出的 effects
        effects: EffectVector,
    },
    /// 需要审批。
    Approve {
        /// 决策记录(已写入账本)
        decision: DecisionRecord,
        /// 推断出的 effects
        effects: EffectVector,
        /// 待审批请求(已入 `approvals` 表)
        approval: ApprovalRequest,
    },
}

impl FirewallOutcome {
    /// 快捷:返回底层 DecisionKind。
    pub fn decision_kind(&self) -> DecisionKind {
        match self {
            FirewallOutcome::Allowed { .. } => DecisionKind::Allow,
            FirewallOutcome::Denied { .. } => DecisionKind::Deny,
            FirewallOutcome::Approve { .. } => DecisionKind::Approve,
        }
    }
}

/// Firewall 主组件。持有 extractors / scorer / policy 引擎 / 审计账本 / PII scanner。
pub struct Firewall {
    ledger: Arc<Ledger>,
    policy: PolicyEngine,
    scorer: RiskScorer,
    extractors: Vec<Box<dyn EffectExtractor>>,
    config: FirewallConfig,
    /// ISS-010 R2:PII preflight scanner,默认 `DefaultScanner`(forward 到
    /// `vigil_redaction::scan_text`);测试可通过 `with_scanner` 注入。
    scanner: Arc<dyn crate::preflight::PiiScanner>,
    /// ISS-010 R2 MUST-FIX 2:preflight audit 写失败累计(无原文;不 stderr 污染)。
    audit_persist_failures: Arc<crate::preflight::AuditPersistCounter>,
}

impl std::fmt::Debug for Firewall {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Firewall")
            .field("policy_rule_count", &self.policy.len())
            .field("extractor_count", &self.extractors.len())
            .field("config", &self.config)
            .field(
                "audit_persist_failures",
                &self
                    .audit_persist_failures
                    .load(std::sync::atomic::Ordering::Relaxed),
            )
            .finish()
    }
}

impl Firewall {
    /// 组装一个 Firewall:内置 7 个 extractor + 提供的 policy + scorer + 默认
    /// `DefaultScanner`(见 [`Firewall::with_scanner`] 注入自定义)。
    pub fn new(ledger: Arc<Ledger>, policy: PolicyEngine, config: FirewallConfig) -> Self {
        Self::with_scanner(
            ledger,
            policy,
            config,
            crate::preflight::default_scanner_arc(),
        )
    }

    /// **ISS-010 R2 BLOCKER 2 修复**:同 `new`,但接受自定义 `scanner`,主要供测试注入
    /// `FailingScanner` 真触发 fail-closed 路径(见 tests/preflight.rs)。
    pub fn with_scanner(
        ledger: Arc<Ledger>,
        policy: PolicyEngine,
        config: FirewallConfig,
        scanner: Arc<dyn crate::preflight::PiiScanner>,
    ) -> Self {
        let roots: Vec<PathBuf> = config.project_roots.iter().map(PathBuf::from).collect();
        let scorer = RiskScorer::new(config.allowed_hosts.clone(), config.project_roots.clone());
        let extractors: Vec<Box<dyn EffectExtractor>> = vec![
            Box::new(PathExtractor::new(roots)),
            Box::new(UrlExtractor),
            Box::new(SqlExtractor),
            Box::new(ShellExtractor),
            Box::new(EmailExtractor),
            Box::new(SecretRefExtractor),
            Box::new(BrowserActionExtractor),
        ];
        Self {
            ledger,
            policy,
            scorer,
            extractors,
            config,
            scanner,
            audit_persist_failures: Arc::new(crate::preflight::AuditPersistCounter::new(0)),
        }
    }

    /// 返回 preflight audit 写失败累计(进程生命周期内)。0 = 一切正常。
    ///
    /// **R2 MUST-FIX 2**:替代旧的 `eprintln!` 观测通道。测试可用以验证
    /// audit 是否静默降级。
    pub fn audit_persist_failures(&self) -> u64 {
        self.audit_persist_failures
            .load(std::sync::atomic::Ordering::Relaxed)
    }

    /// 评估一次 tool call。I10c-β2 R3 统一签名:OAuth 上下文由 [`OAuthScopeContext`]
    /// **必填参数**显式传入,防止 HTTP MCP 集成点漏配 scope 导致静默绕过。
    ///
    /// - 本地工具 / stdio MCP:传 [`OAuthScopeContext::NonOauth`]
    /// - HTTP MCP + OAuth access token:传 [`OAuthScopeContext::Scopes`]
    ///   (scope 集合来自 `vigil_http_auth::ResolvedAccessToken::scope_set`;
    ///   空 scope 也必须显式 `Scopes(vec![])`,触发 fail-closed)
    ///
    /// 步骤(ADR 0003 §D3 + 方案 §3.3 + ADR 0004 §D8):
    /// 1. 所有 extractor 合并产出 `EffectVector`
    /// 2. 通过 [`DescriptorOracle`] 查询 descriptor 当前信任状态
    /// 3. `RiskScorer` 打分 + reasons
    /// 4. `PolicyEngine` 按规则评估,获得 `PolicyDecision`
    ///    (`FirewallConfig::allowed_scopes` 自动合并到 `PolicyContext.allowlists`)
    /// 5. 组装 `DecisionRecord`,调用 `Ledger::record_decision` 入账
    /// 6. 若 Approve,`create_approval` 入 approvals 表(带 server/tool/args_hash 上下文)
    pub fn evaluate(
        &self,
        call: &ToolInvocation,
        oracle: &dyn DescriptorOracle,
        scope_ctx: OAuthScopeContext,
    ) -> Result<FirewallOutcome, FirewallError> {
        // 0) **R2 R1 新发现 3 修复** —— reserved-key guard 在 preflight **之前**。
        //    配置错误时不应先扫描并落 redaction 审计副作用。
        //
        // VIGIL-SEC-005(security audit):allowed_scopes 与 allowed_hosts 共用 ctx.allowlists
        // 同一 map,后写覆盖。用**保留键集合**守门(而非单一字面量),未来引擎新增固定 allowlist
        // 键时只需扩 RESERVED_ALLOWLIST_KEYS,不会因约定遗忘而被 allowed_scopes 静默覆盖。
        const RESERVED_ALLOWLIST_KEYS: &[&str] = &["allowed_hosts"];
        if self
            .config
            .allowed_scopes
            .keys()
            .any(|k| RESERVED_ALLOWLIST_KEYS.contains(&k.as_str()))
        {
            return Err(FirewallError::ReservedScopeKey);
        }

        // 1) extract
        let mut effects = EffectVector::default();
        for ex in &self.extractors {
            ex.extract(call, &mut effects);
        }
        dedup_effects(&mut effects);

        // 2) oracle(权威来源)
        let descriptor = oracle.status(&call.server_id, &call.tool_name, &call.descriptor_hash);

        // 3) score
        let (risk_score, score_reasons) = self.scorer.score(&effects, descriptor);

        // 3b) ISS-010 preflight —— T0 redaction scan 产 PII findings + risk delta。
        //
        // 纪律:
        // - 扫 `call.args` 里所有 ≥ `long_text_threshold` 的字符串字段(递归 Value)
        // - `scan_text` 返 Err(非 EmptyInput)→ fail-closed `FirewallError::PreflightScanFailed`
        // - findings 聚合成 `PiiFindingSummary` 喂 `PolicyContext.pii_findings`,
        //   让规则层 `Condition::PiiContains` 消费
        // - risk_delta 按 ADR 0012 §1.3 已在 redaction 层累加,这里 saturating_add 后
        //   clamp 到 100(PolicyContext.risk_score 是 u8)
        let preflight = run_preflight(
            self.scanner.as_ref(),
            &self.ledger,
            &self.audit_persist_failures,
            &call.session_id,
            &call.args,
            self.config.long_text_threshold,
        )
        .map_err(|e| match e {
            PreflightError::ScanFailed { reason } => FirewallError::PreflightScanFailed { reason },
        })?;

        // 叠加:risk_score(u8) + preflight.risk_delta(u32),先升到 u32 饱和加,再 clamp 到 100
        let base_risk = risk_score;
        let pii_delta = preflight.risk_delta;
        let risk_with_pii = (base_risk as u32).saturating_add(pii_delta).min(100) as u8;

        // 3) policy —— 把 descriptor 状态透传给引擎,让 drift/first-seen 进规则体系。
        // 本 crate 与 DescriptorStatus 同源,AGENTS.md non_exhaustive 纪律要求写 `_`,
        // 编译器会把它标为 unreachable;接受这一警告由 #[allow] 局部消音。
        #[allow(unreachable_patterns)]
        let descriptor_state = match descriptor {
            DescriptorStatus::ApprovedStable => DescriptorState::ApprovedStable,
            DescriptorStatus::FirstSeen => DescriptorState::FirstSeen,
            DescriptorStatus::Drifted => DescriptorState::Drifted,
            // non_exhaustive fail-closed:未知扩展视为 FirstSeen 升级严厉度
            _ => DescriptorState::FirstSeen,
        };
        // reserved-key guard 已在 evaluate 第 0 步前置(R2 R1 新发现 3 修复)。
        // 之前此处的重复 guard 已删除。

        let mut ctx = PolicyContext {
            // ISS-010:policy 看到的 risk_score 是 PII 加权后的最终值;基础分
            // + PII delta 分别在 DecisionRecord.reasons 里留痕(便于审计溯源)。
            risk_score: risk_with_pii,
            descriptor: descriptor_state,
            // I10c-β2:OAuth 上下文由签名上的 `scope_ctx` 显式传入,转换为
            // `PolicyContext::requested_scopes` 三态(见其文档)。
            requested_scopes: scope_ctx.into_policy_requested_scopes(),
            // ISS-010:T0 redaction preflight 聚合后的 PII 摘要
            pii_findings: preflight.pii_summary.clone(),
            ..Default::default()
        };
        ctx.roots
            .insert("project_roots".into(), self.config.project_roots.clone());
        // host allowlist 用固定键 `allowed_hosts`。
        ctx.allowlists
            .insert("allowed_hosts".into(), self.config.allowed_hosts.clone());
        // I10c-β2 R3:OAuth scope allowlist 由 config 驱动合并。键由 caller 在
        // `FirewallConfig::allowed_scopes` 里自行命名(典型:`oauth_scopes` /
        // `github_scopes`);禁止与 `allowed_hosts` 相撞 —— 已在上方 reserved-key
        // guard 兜底,此处只做合并。
        for (k, v) in &self.config.allowed_scopes {
            ctx.allowlists.insert(k.clone(), v.clone());
        }
        let pdec: PolicyDecision = self.policy.evaluate(&effects, &ctx)?;

        // 4) decision —— risk_score 记 PII 加权后的最终值(policy 实际看到的);
        //    reasons 在 scorer reasons + policy reasons 之外,**额外追加 preflight 摘要**
        //    (R2 MUST-FIX 1 修复):`preflight: base_risk=X pii_delta=Y final=Z labels=<label=count,...>`
        //    让审计员能从单条 DecisionRecord 看出"底分 vs. PII 叠加"的完整拆分,不再需
        //    要去交叉查 redaction_scans / redaction_findings。
        let preflight_reason = format!(
            "preflight: base_risk={} pii_delta={} final={} labels={}",
            base_risk,
            pii_delta,
            risk_with_pii,
            if preflight.pii_summary.is_empty() {
                "(none)".to_string()
            } else {
                preflight.counts_csv()
            }
        );
        let mut decision_reasons = merge_reasons(&score_reasons, &pdec.reasons);
        decision_reasons.push(preflight_reason);

        // v0.8 Sprint 1 A2 — scanner 退化感知:若 preflight 期间任一文本走退化路径
        // (DegradedTimeout / DegradedError),把 stable code 推进 reasons 留痕。
        // `Ok` / `Unsupported` 不写 reasons(无新信息;Unsupported 是 trait default,
        // 表示 scanner 实现不上报状态,caller 维持原决策路径)。
        // crate 内部穷举 EngineStatusReport(定义在 vigil-firewall::preflight);加新
        // variant 时 compiler force update 本 match。外部 consumer 因 #[non_exhaustive]
        // 必须写 `_` 兜底,内部代码无需。新 variant 的 fail-closed 决策由 author 在加
        // variant 时显式选边(归 Degraded 类记 reasons / 归 Ok 类 None / 单独路径)。
        let degraded_status = match preflight.engine_status {
            EngineStatusReport::DegradedTimeout | EngineStatusReport::DegradedError => {
                let stable = preflight.engine_status.stable_code();
                decision_reasons.push(format!("engine.status={stable}"));
                Some(preflight.engine_status)
            }
            EngineStatusReport::Ok | EngineStatusReport::Unsupported => None,
        };

        // decision_id 提前生成:engine_degraded payload 需要它做 audit 跨表 join。
        let decision_id = Uuid::new_v4().to_string();
        let decision = DecisionRecord {
            decision_id: decision_id.clone(),
            invocation_id: call.invocation_id.clone(),
            decision: map_action(pdec.action),
            risk_score: risk_with_pii,
            reasons: decision_reasons,
            policy_ids: pdec.policy_ids.clone(),
            created_at: now_secs(),
        };
        let _ = self
            .ledger
            .record_decision(&call.session_id, &decision, &effects)?;

        // v0.8 Sprint 1 A2 — degraded 路径补落 audit `engine.degraded` 事件。
        // 写在 record_decision 之后,确保 decision_id 已落库;写失败仅原子计数
        // (`audit_persist_failures`),**不**阻断决策返回 —— 审计缺失不背锅当事。
        //
        // `engine_id` 暂用 stable string `"firewall_preflight_scanner"`:PiiScanner trait
        // 抽象层不暴露具体 model_id,细分 engine_id 留 v0.8 Sprint 2(EnsembleEngine 内
        // 单 model 退化标识)。budget_ms / elapsed_ms 同理留 Sprint 2(scan_with_status
        // 当前不透出耗时,需扩展 trait 返 (RedactionResult, EngineStatusReport, Option<Duration>))。
        if let Some(status) = degraded_status {
            let payload = EngineDegradedPayload {
                engine_id: "firewall_preflight_scanner".to_string(),
                status: status.stable_code().to_string(),
                reason_code: status.stable_code().to_string(),
                budget_ms: None,
                elapsed_ms: None,
                fail_closed_decision: "fall_back_hard_only".to_string(),
                decision_id: decision_id.clone(),
            };
            if self
                .ledger
                .record_engine_degraded(&call.session_id, &payload)
                .is_err()
            {
                self.audit_persist_failures
                    .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            }
        }

        // 5) 按 action 分支
        match pdec.action {
            PolicyAction::Allow => Ok(FirewallOutcome::Allowed { decision, effects }),
            PolicyAction::Deny => Ok(FirewallOutcome::Denied { decision, effects }),
            PolicyAction::Approve => {
                let (title, summary) = summarize(call, &effects, &decision);
                // args_hash:JCS 规范化后的 args SHA-256,用于 ThisSession scope 查询。
                let args_hash = compute_args_hash(&call.args)?;
                let ctx = ApprovalTargetContext {
                    server_id: Some(&call.server_id),
                    tool_name: Some(&call.tool_name),
                    args_hash: Some(&args_hash),
                };
                let approval: AuditResult<ApprovalRequest> = self.ledger.create_approval(
                    &call.session_id,
                    &decision,
                    &effects,
                    &title,
                    &summary,
                    self.config.approval_ttl_secs,
                    ctx,
                );
                let approval = approval?;
                Ok(FirewallOutcome::Approve {
                    decision,
                    effects,
                    approval,
                })
            }
            // PolicyAction 是 non_exhaustive:未知扩展一律 fail-closed Deny(AGENTS.md)
            _ => Ok(FirewallOutcome::Denied { decision, effects }),
        }
    }
}

fn dedup_effects(e: &mut EffectVector) {
    // 去重但保留顺序
    let mut seen = std::collections::HashSet::new();
    e.effects.retain(|k| seen.insert(*k));
    e.paths_read.sort();
    e.paths_read.dedup();
    e.paths_write.sort();
    e.paths_write.dedup();
    e.network_hosts.sort();
    e.network_hosts.dedup();
    e.secret_refs.sort();
    e.secret_refs.dedup();
    e.recipients.sort();
    e.recipients.dedup();
}

fn map_action(a: PolicyAction) -> DecisionKind {
    match a {
        PolicyAction::Allow => DecisionKind::Allow,
        PolicyAction::Deny => DecisionKind::Deny,
        PolicyAction::Approve => DecisionKind::Approve,
        // non_exhaustive:未知扩展映射为 Deny(fail-closed)
        _ => DecisionKind::Deny,
    }
}

fn merge_reasons(score: &[String], policy: &[String]) -> Vec<String> {
    let mut out = Vec::with_capacity(score.len() + policy.len());
    out.extend(score.iter().cloned());
    out.extend(policy.iter().cloned());
    out
}

fn summarize(
    call: &ToolInvocation,
    effects: &EffectVector,
    dec: &DecisionRecord,
) -> (String, String) {
    let title = format!("{} on {}", call.tool_name, call.server_id);
    let mut parts = Vec::new();
    parts.push(format!("risk {}/100", dec.risk_score));
    if !effects.paths_write.is_empty() {
        parts.push(format!("writes: {}", effects.paths_write.join(", ")));
    }
    if !effects.paths_read.is_empty() {
        parts.push(format!("reads: {}", effects.paths_read.len()));
    }
    if !effects.network_hosts.is_empty() {
        parts.push(format!("hosts: {}", effects.network_hosts.join(", ")));
    }
    if !effects.secret_refs.is_empty() {
        parts.push(format!("secrets: {}", effects.secret_refs.join(", ")));
    }
    if !effects.recipients.is_empty() {
        parts.push(format!("recipients: {}", effects.recipients.len()));
    }
    (title, parts.join(" | "))
}

fn now_secs() -> i64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// `args_hash` 计算:JCS 规范化后 SHA-256,十六进制小写。
/// 与 approvals 表中的 args_hash 列语义一致;I04 ThisSession scope 查询要求相等。
pub(crate) fn compute_args_hash(args: &serde_json::Value) -> Result<String, FirewallError> {
    let bytes = serde_jcs::to_vec(args)
        .map_err(|e| FirewallError::Audit(vigil_audit::AuditError::Json(e)))?;
    let mut h = Sha256::new();
    h.update(&bytes);
    Ok(hex::encode(h.finalize()))
}
