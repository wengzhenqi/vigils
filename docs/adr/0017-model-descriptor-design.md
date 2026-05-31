# ADR 0017 — ModelDescriptor & Multi-Model Schema Design (Phase 3 Design-only)

- 状态:**Accepted (Design-only)**(v0.7-α3 Phase 3 Design,2026-05-01)
- 日期:2026-05-01
- 依赖:ADR 0012(模型分发)/ ADR 0013(Hard × Model merge)/ ADR 0015(SDK Boundary)/
  ADR 0016(Performance Gate)
- 驱动决策:Phase 3 brainstorm Codex multi-perspective(session
  `019de2b9-82e4-77a3-b641-fb95bfc0f4ef`)
- **scope**:**仅设计 + 内部 scaffold**,不实施新模型;真模型集成留 P3-spike

## 0. 摘要

冻结 Phase 3 Multi-Model 的 ABI 边界:`ModelDescriptor` trait + canonical 8-label
mapping + manifest 三层 pin。**不**暴露到 SDK Phase 1(ADR 0015 边界保留),先做
crate-private scaffold 给 P3-spike 验证;spike 通过 → SDK 暴露 + Phase 3 实施。

## 1. 上下文

### 1.1 brainstorm § 3 综合结论

- **Top 1**:B 多语言专精(XLM-R / mT5 PII)— 唯一有 v0.6.1 multilang recall
  0.75 数据支撑的方向
- **启动前置**:ModelDescriptor trait 设计冻结 + canonical 8-label mapping +
  manifest 三层 pin
- **建议 spike**:1 模型 prototype 验证 recall / p95 / RSS / mapping 损失再决定

### 1.2 SDK 不变量(ADR 0015)

- **PrivacyLabel::ALL.len() == 8** doc-test 守门;扩 enum = breaking change
- 视为 **canonical ABI**:外部对接的稳定承诺,不应因新模型而扩张

### 1.3 现状

- 单模型:OpenAI Privacy Filter q4f16 ONNX,33-class id2label 收敛到 8 类(`label.rs`)
- bootstrap manifest:hardcode 单 manifest(三件套 + 三层 pin 缺 `label_space_version`)
- 无 ModelDescriptor 抽象,id2label 映射散落在 `engine.rs::parse_id2label`

## 2. 决策

### 2.1 ModelDescriptor trait(crate-private,P3-spike 后再 SDK 暴露)

```rust
pub trait ModelDescriptor: Send + Sync {
    /// 模型唯一 id(如 "openai-privacy-filter-v1" / "xlm-r-pii-v1");
    /// 用于 manifest selection 与 audit 关联
    fn model_id(&self) -> &str;

    /// 语义化版本(与 vigil-redaction crate 解耦);
    /// 同 model_id 不同 version 视为兼容升级
    fn version(&self) -> &str;

    /// 三件套 / N 件套 artifact 整文件 sha256(hex,小写);
    /// 与 manifest 写入值对账,任何不一致即 fail-fast
    fn artifact_sha256(&self) -> &[(&str, &str)];

    /// label-space-version:label 集合 + 字面量 + canonical_mapping 的版本;
    /// 任何变化即 breaking,触发启动失败
    fn label_space_version(&self) -> &str;

    /// 模型原生 id → 模型原生 label 字面量(BIOES 解码后的 core label);
    /// 例:OpenAI 33-class 完整列表 / XLM-R 自定义 label set
    fn id2label(&self) -> &[&str];

    /// canonical_mapping:模型原生 label 字面量 → 8 类 PrivacyLabel;
    /// **强制覆盖**所有 id2label() 的元素(每条必有映射或 None 显式忽略)
    fn canonical_mapping(&self, native_label: &str) -> Option<PrivacyLabel>;

    /// tokenizer 规范(嵌入式 vocab + post_processor 配置);
    /// 当前实现统一走 tokenizers crate `from_file(tokenizer.json)`,
    /// future-proof 为 future tokenizer 引擎留扩展点
    fn tokenizer_spec(&self) -> TokenizerSpec;

    /// post_processor:span 解码策略(BIOES / IOB / aggregation 模式);
    /// 默认 BIOES(沿用 v0.6 实施),P3 多模型按需切换
    fn post_processor(&self) -> PostProcessorKind;

    /// per-label 置信度阈值 profile(可调,模型质量校准用);
    /// None = 默认阈值(threshold profile = 模型自带,不调整)
    fn threshold_profile(&self) -> Option<&ThresholdProfile>;
}
```

### 2.2 canonical 8-label mapping(SDK ABI 守门)

**强制不变量**:
- 任何 `ModelDescriptor` 的 `id2label()` 返回的每个 native label,通过
  `canonical_mapping(native_label)` **必须**映射到 `Some(PrivacyLabel)` 或
  显式 `None`(忽略)
- 测试守门:`tests::descriptor_canonical_mapping_total_for_all_native_labels`
  对每个注册 descriptor 遍历 id2label() × canonical_mapping(),拒绝隐式遗漏

**为什么强制**:
- 防"新模型悄悄漏 label"导致 silent recall 降
- 防"新增 8 类外的语义"扩 SDK enum(breaking)
- canonical mapping 让模型可任意类数,SDK 始终 8 类(stable ABI)

### 2.3 Manifest 三层 pin(扩展现有 schema)

```rust
pub struct ModelManifest {
    /// 沿用现有字段:model_name + version + chunk_count + files
    pub model_name: String,
    pub version: String,
    pub chunk_count: u32,
    pub files: Vec<ManifestFile>,

    // ─── v0.7 Phase 3 新增三层 pin ───
    /// model_id(对账 ModelDescriptor.model_id());
    /// 与 model_name 互补:model_name 是 logical/UI,model_id 是 selection key
    pub model_id: String,
    /// label-space-version(对账 ModelDescriptor.label_space_version());
    /// 任何变化即 breaking,启动失败
    pub label_space_version: String,
    /// 是否 default selection(同 manifest 内多 model 时的 fallback);
    /// 单模型 manifest 自然 default
    #[serde(default)]
    pub default: bool,
}

/// 顶层 manifest 改为 array 容器(向前兼容:单元素 array = 老 schema 等价)
pub struct Manifest {
    /// 多模型 array;v0.5 P2 单 manifest schema 自动迁移到单元素 array
    pub models: Vec<ModelManifest>,
}
```

**向前兼容**:
- 老 manifest schema(顶层 `model_name` + `files`)仍可解析,自动包成
  `models: [{...}]` 单元素 array(serde 自定义反序列化)
- 老 deployment(v0.5/v0.6/v0.6.1)无需改 manifest

### 2.4 Selection 优先级(运维视角)

1. `FirewallConfig.model_id: Option<String>` — 显式注入(企业)
2. `VIGIL_MODEL_ID` env var — 开发/测试 ad-hoc 切换
3. `manifest.models[i].default == true` 或第一条 — bootstrap 启动 fail-fast 兜底

**fail-fast 触发**:
- model_id 选择不存在 → `ModelNotFound`(沿用 ADR 0012)
- artifact_sha256 不匹配 → `BootstrapError::IntegrityCheckFailed`
- label_space_version 不匹配 → `EngineError::DescriptorDrift`(新增)
- canonical_mapping 不全 → 编译期 unit test 拒入合并

### 2.5 双模型并存内存

- **Default**:single-load(启动期 fail-fast)
- **Enhanced** (P3+ 实施):lazy-load secondary,首次按 selection 触发
- **预算控制**:`VIGIL_MAX_MODEL_RESIDENT_MB` env var(设上界);超即拒新加载,
  audit 落 `engine.budget_exceeded` 事件(留 v0.7-α3+ ledger 扩展)

### 2.6 SDK 暴露策略

- **Phase 3 Design(本 ADR)**:trait + manifest schema **crate-private**;
  scaffold 在 vigil-redaction 内部,不动 SDK Phase 1
- **P3-spike 验证后**:trait 暴露 SDK + manifest schema 暴露;
  Codex review 评估是否扩 SDK pub items(预计 +5-10 items)
- **Phase 3 实施后**:第二模型 manifest 与 spike 模型替换/共存

## 3. 理由

### 为什么 crate-private scaffold 而非 SDK 直接暴露?

- spike 验证前 trait 设计可能调整(实测需求 driven)
- SDK pub items 在 0.0.x 仍允许调整,但每改一次就要 ADR;crate-private 调整无 ABI 风险
- v0.7-α3 投资在"设计正确性",而非"过早冻结"

### 为什么 canonical_mapping 强制全覆盖?

- silent label drop 是最难追踪的 silent recall 退化(模型说有,系统说没)
- 编译期 unit test + 显式 None 让"忽略"是显式决策而非疏忽

### 为什么不直接做 P3-spike 而要先 P3-design?

- spike 没设计 = "随便实现,完了不知道怎么收"(常见研究项目失败模式)
- P3-design 让 spike 有明确**验收门**:trait 实现 + manifest 兼容 + canonical 全覆盖
- spike 失败 fallback 单模型仍受益(label space 抽象使主路径更清晰)

## 4. 后果

### 正面

- Phase 3 实施有清晰边界(trait + schema + mapping 三件齐)
- 不破 SDK Phase 1 ABI(crate-private 路径)
- spike 验证后扩展决策有数据支撑(recall / p95 / RSS / mapping 损失)
- 老 manifest schema 自动迁移(0 ops 改动)

### 负面 / 风险

- crate-private 设计无 SDK consumer 反馈,可能与真实需求漂移
- canonical 8-label 强约束新模型的 label space(若新模型严重不对齐 PII vertical
  例如医疗 PHI,需重做 mapping 或扩 SDK,**这是有意的边界**)
- threshold_profile / post_processor 抽象可能过度设计(YAGNI 风险)

### 缓解

- spike 期间记录 trait 真实使用模式,修正过度设计
- threshold_profile / post_processor 默认实现 = 现有行为,不影响实际 v0.6 单模型
- canonical mapping 必填测试守门"显式 None" 让设计意图明确(忽略 ≠ 漏)

## 5. 实施(本 commit / P3-design)

### 5.1 ADR 0017 创建(本文件)

- [x] 决策记录 + brainstorm 引用 + Codex session ID
- [x] trait API 设计 + canonical mapping 不变量 + 三层 pin schema

### 5.2 vigil-redaction scaffold(crate-private)

- [ ] `crates/vigil-redaction/src/model_descriptor.rs` 新模块:trait + 关联类型
      (TokenizerSpec / PostProcessorKind / ThresholdProfile)
- [ ] OpenAI Privacy Filter `OpenAIPrivacyFilterDescriptor` 实例(v0.6 现有模型
      的 trait 实例化,验证设计可消费实际数据)
- [ ] 单测:trait API 编译 + canonical mapping 全覆盖(33-class 全映射)+
      label_space_version 稳定

### 5.3 manifest schema 扩展(向前兼容)

- [ ] `bootstrap/manifest.rs::ModelManifest` 加 `model_id` / `label_space_version`
      / `default` 字段(serde default 兼容老 schema)
- [ ] `bootstrap/manifest.rs::Manifest` 改 `models: Vec<ModelManifest>`(serde
      自定义反序列化老 schema → 单元素 array)
- [ ] 单测:老 schema deser → 新结构 + 新 schema deser + 多 manifest array

### 5.4 SDK 不暴露

- [ ] vigil-sdk 不加 ModelDescriptor / TokenizerSpec / PostProcessorKind 等
      trait/类型;P3-spike 验证后再扩 SDK

### 5.5 文档同步

- [ ] roadmap-v0.7 § 1 Phase 3 状态从 "🥉 Phase 3" → "🥉 Phase 3 (Design done,
      spike pending user)"
- [ ] CHANGELOG `[v0.7-α3]` 段加 P3-design 落地

## 6. 与既有 ADR 关系

- **ADR 0012**(模型分发):manifest schema 是其扩展;现有 placeholder + 真值注入
  机制不变,只是 schema 多 array 一层
- **ADR 0013**(Hard × Model merge):decision 不变;新模型仍走 merge,只是 model
  侧 findings 来源换 descriptor
- **ADR 0015**(SDK Boundary):本 ADR scope 显式 **不扩展 SDK Phase 1**;
  P3-spike 验证后再 ADR 扩展 SDK
- **ADR 0016**(Performance Gate):per-model warm p95 budget 仍按 path-sliced
  SLO 适用;新模型必须达到 Enhanced path < 1s warm

## Revised — v0.7-α4 R1h(2026-05-02)

### 实测驱动的 ThresholdProfile 真消费

P3 Phase 3 设计阶段 `ThresholdProfile` 是占位结构(`#[allow(dead_code)]`)。
v0.7-α4 R1h 经 50-sample 实测 FP 诊断驱动:

- **诊断工具**:`scripts/spike-p3/diagnose_fp.py` 跑 50-sample 抽 per-engine
  per-label TP/FP/confidence 分布,锁定 high-FP `(engine, label)` 组合
- **per-engine threshold 配置**(>1.0 等价屏蔽):
  - `XlmrPiiDescriptor`:Email / Phone / Address(R1e 实测 FP/TP 16:3 / 6:1 / 0:4)
  - `YonigoPiiDescriptor`:Person / AccountNumber / Address(0:1 / 0:2 / 2:6)
  - `OpenAIPrivacyFilterDescriptor`:**不调**(保 v0.6 行为,openai-only path 仍可用)
- **OrtEngine.infer 第 8 步消费 threshold_profile**:`if pass_threshold {
  findings.push(...) }` 块;**不能用 `continue`**(会跳过外层 `i = j.max(i + 1)` 推进
  导致死循环 — Sprint 2 实测发现并修复)

### Bench 改善

| Metric | R1e (no threshold) | R1h (threshold) | Delta |
|---|---|---|---|
| EU recall | 0.946 | 0.919 | -0.027 |
| EU precision | 0.47 | 0.65 | **+0.18 ✅** |
| Full N=50 FP | 59 | 23 | **-61%** |

EU recall 微降 0.027 换 precision +0.18,保持 ≥ 0.90 spike-plan 阈值。

### v0.7-α4 R1g CI Gate

ADR 0017 设计的"P3-spike 验证后扩 SDK 暴露"路径已细化为分层守门:
- **PR gate**:`.github/workflows/ci.yml::ensemble-example-compile` job 编译护栏
  (ort feature 完整性 + 113 unit tests)
- **Release gate**:远程 release runner(`vigils.ai`)真 ORT e2e + verdict gate
  strict mode,详见 `docs/operations/v0.7-alpha4-release-runbook.md`

---

## Revised — v0.8 Sprint 1 A2 firewall ↔ ledger integration design(2026-05-02)

### 背景

v0.7-α2 Phase 2D-fw(commit `a7a03d5`)`BudgetedOrtPiiScanner.scan` **隐式吞掉**
`EngineStatus`(只返 `RedactionResult`),Firewall caller 不知道退化发生。
v0.7-α6 A1(`b06e2fa`)已加 `vigil_audit::EngineDegradedPayload` typed schema +
`Ledger::record_engine_degraded` method,但 firewall 端仍未 wire — production
audit 路径**有 gap**(retroactive risk:degraded scan 默认走"放行")。

### 决策(Codex `019de2b9` § 2 ACCEPT — 改进版方案 A)

`PiiScanner` trait 加 default method,**关键改进**:default 实现 **不**返"假
安全 Ok",应返 `EngineStatus::Unsupported` 或抛错。Firewall 检测 budgeted
path 但 status reporting unsupported → **必 fail-fast / deny**,绝**不**默认 allow。

```rust
// 草案(v0.8 Sprint 1 实施)
pub trait PiiScanner: Send + Sync + 'static {
    fn scan(&self, text: &str) -> Result<RedactionResult, ScanError>;

    /// v0.8 A2:可选 status reporting(default 返 Unsupported,Firewall caller
    /// 必检查;不返 Ok 防"假安全"隐患)。BudgetedOrtPiiScanner 等 budgeted
    /// path override,scan 结束后填实际 status。
    fn last_engine_status(&self) -> EngineStatusReport {
        EngineStatusReport::Unsupported // default — Firewall caller 必显式判
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EngineStatusReport {
    Ok,
    DegradedTimeout,
    DegradedError,
    /// default 实现返此;caller 收到此应 fail-fast 或 deny
    Unsupported,
}
```

**Firewall::evaluate 集成**:

```rust
// preflight scan 后
let result = self.scanner.scan(text)?;
let status = self.scanner.last_engine_status();
match status {
    EngineStatusReport::Ok => { /* 正常路径 */ }
    EngineStatusReport::DegradedTimeout | DegradedError => {
        // fail-closed:退化路径 → Hard-only fallback + audit
        let payload = EngineDegradedPayload {
            engine_id: ...,
            status: status_to_string(status),
            reason_code: "budget_exceeded" | "infer_run_error",
            fail_closed_decision: "fall_back_hard_only",
            decision_id: decision.decision_id.clone(),
            ...
        };
        self.ledger.record_engine_degraded(session_id, &payload)?;
        decision_reasons.push(format!("engine.status={}", status_to_string(status)));
    }
    EngineStatusReport::Unsupported => {
        // Codex 警示:budgeted path 但 status reporting 不支持
        // → fail-fast deny(避免 silent allow on degraded path)
        if self.config.budgeted_path_enabled {
            return Err(FirewallError::PreflightScanFailed {
                reason: "budgeted scanner missing status reporting".to_string(),
            });
        }
        // 非 budgeted path:Unsupported 是默认正常,继续
    }
}
```

### 不变量保留

- ✅ `PiiScanner` trait SemVer 不破(default method 加,旧实现自动 fallback)
- ✅ degraded **必 fail-closed**(audit 必有,decision_reasons 必含 stable code)
- ✅ canonical 8-class ABI 不动
- ✅ audit `EngineDegradedPayload` schema 已锁(v0.7-α6 b06e2fa,本 ADR Revised
  仅消费方更新)

### 实施 commits 计划(v0.8 Sprint 1)

- `[A2.1]` PiiScanner trait 加 last_engine_status default method(返 Unsupported)
- `[A2.2]` BudgetedOrtPiiScanner override + 内部 last_status 字段
- `[A2.3]` EnsembleOrtPiiScanner override(若 ensemble 内部任一 engine 退化)
- `[A2.4]` Firewall::evaluate hook + decision_reasons stable code
- `[A2.5]` 守门测试:fail-closed degraded path / Unsupported deny path

---

## 7. 后续(供 P3-spike 启动参考)

- 候选模型:`Davlan/xlm-roberta-base-ner-pii` 或 `mt5-base-pii-tagger`
- spike 验收:multilang recall ≥ 0.85 / warm p95 < 1s / RSS < 1.2GB total /
  canonical mapping 损失 < 10%
- spike 失败:接受 E(放弃 Phase 3)→ 投资 v0.7-α3+ Phase 1/2 后续
- spike 成功:启动 Phase 3 实施 + SDK 扩展 ADR

---

## Revised — v0.9 Sprint 1 P1.1 + P1.2 lang-conditional threshold spike(2026-05-03)

**触发**:v0.9 P1 spike GREEN 启动(commit `aa2464f` 数据驱动决议:5+ candidates
理想 -22 FP / 0 TP loss);commit `5d85547` (P1.1 API) + `39575b6` (P1.2 路径)。

### Revised § 8.1 — LangConditionalThresholdProfile API

```rust
#[non_exhaustive]
pub struct LangConditionalThresholdProfile {
    pub default: ThresholdProfile,
    pub overrides: BTreeMap<(String, PrivacyLabel), f32>,
}

impl LangConditionalThresholdProfile {
    pub fn new(default: ThresholdProfile) -> Self;
    pub fn with_override(self, lang: impl Into<String>, label: PrivacyLabel, t: f32) -> Self;
    pub fn threshold_for(&self, label: PrivacyLabel, lang: Option<&str>) -> Option<f32>;
}

pub static XLMR_LANG_CONDITIONAL_PROFILE: Lazy<LangConditionalThresholdProfile>;
```

**优先级语义**(`threshold_for`):
1. `lang Some(l)` 且 `(l, label)` 在 `overrides` → 用 override(即使数值弱于
   default,caller 显式决策优先;**不**用 `max()` fail-closed 策略,否则 lang
   上下文 useless)
2. fallback `default.thresholds.get(label)`
3. 否则 `None`(模型默认 0.0 conf)

### Revised § 8.2 — Trait 演进(SemVer 安全扩展)

`RedactionEngine` trait 加 default method:
```rust
fn infer_with_lang(&self, text: &str, _lang: Option<&str>) -> Result<Vec<Finding>, EngineError> {
    self.infer(text)
}
```

`ModelDescriptor` trait 加 default method:
```rust
fn lang_conditional_profile(&self) -> Option<&LangConditionalThresholdProfile> {
    None
}
```

`OrtEngine.infer_with_lang` override:threshold 应用优先级:
1. `descriptor.lang_conditional_profile().threshold_for(label, lang)` 命中
2. fallback `descriptor.threshold_profile().thresholds.get(label)`
3. `None`(模型默认)

### Revised § 8.3 — 公共 API

```rust
pub fn scan_text_with_engine_with_lang(
    input: &str,
    engine: &dyn RedactionEngine,
    lang: Option<&str>,
) -> Result<RedactionResult, ScanError>;
```

legacy `scan_text_with_engine` 委托 `lang None`(等价 v0.8 行为)。

### Revised § 8.4 — xlmr top 5 overrides(数据驱动)

| lang | label | threshold | 预期收益(理想)|
|------|-------|-----------|----------------|
| it | AccountNumber | 1.1 | -7 FP / 0 TP |
| de | Person | 1.1 | -5 FP / 0 TP |
| fr | AccountNumber | 1.1 | -4 FP / 0 TP |
| de | AccountNumber | 1.1 | -3 FP / 0 TP |
| en | Person | 1.1 | -3 FP / 0 TP |

总计 -22 FP / 0 TP(spike report 数据来源:
`docs/operations/v0.9-sprint1/p1_spike-candidates-92.md`)。

### Revised § 8.5 — env × lang 路径分离(R1 NICE 2)

env=fp_strict 是**粗粒度** opt-in(全 sample 屏蔽 Person);lang-conditional
是**细粒度** per-(lang, label)。两者**不互替代**:
- env 影响 `threshold_profile()` 路径(legacy `infer`)
- lang-conditional 影响 `infer_with_lang(text, lang)` 路径
- `XLMR_LANG_CONDITIONAL_PROFILE.default = XLMR_PROFILE.clone()` 在 Lazy init
  一次性 clone v0.8 baseline(**不**跟随 env 切换);守门测试
  `lang_conditional_default_independent_of_env` 锁定此分离

### Revised § 8.6 — SDK 暴露策略(v0.9 → v0.10+)

**当前 v0.9 不暴露**:
- `LangConditionalThresholdProfile` trait/struct 仍在 `vigil_redaction::model_descriptor::*` 路径,**不**进 vigil-sdk(避免 SemVer 锁过早)
- `scan_text_with_engine_with_lang` pub 但仅 vigil-redaction 自己用;SDK 不 re-export
- env name `VIGIL_*` 仍 ops 配置层

**v0.10+ 候选**(若用户反馈表明需要 typed config):
- SDK pub `LangConditionalProfile` builder + `scan_text_lang(text, lang)` 浅级 wrapper
- 触发 ADR 0015 Revised § Phase 4 SDK 决策

### Revised § 8.7 — P1.3 待做(SSH 恢复后)

- ✅ 升级 r1_ensemble_e2e example 加 lang-aware 路径(`VIGIL_R1_LANG_AWARE=1` env;
  本 commit 落地)
- ⏳ 远程 92-sample 实测验证 -22 FP / 0 TP loss 假设(margin ≤ 2 TP loss 接受)
- Codex review SemVer 完整闭环(P1.1 R1 ACCEPT + P1.2 R1 ACCEPT-WITH-NICE 已通)

### Revised § 8.8 — Decision D(lang 来源)— **采纳 C: fixture-only / dev-only**

**Codex session `019dfdab` 头脑风暴**:3 候选评估后强推荐 **C — fixture-only / dev-only**;
production Firewall::evaluate **不接** lang,保 v0.8 baseline 行为(EU recall 0.904)。

**理由**(Codex § Recommendation):
- **C 是 v0.9 最安全**:无新 production bypass / downgrade 路径,EU recall baseline 不动
- **B(启发式 detect)拒绝**:`feedback_lang_review_authoritative` 已立 — 短文本误判
  17/45;启发式作 firewall 决策权威 → 静默 threshold 误路由
- **A(caller 显式 Option<&str>)推 v0.10**:若实施需 `LanguageHint { lang, source,
  confidence }` typed 形式 + provenance/audit 字段 + fail-closed fallback

**作用域**(C 决议下 v0.9 实际 surface):
- ✅ `scan_text_with_engine_with_lang(input, engine, lang)` SDK 内部 API(已落)
- ✅ `r1_ensemble_e2e --lang-aware` release-gate 验证模式(已落)
- ❌ `Firewall::evaluate` 不接 lang(P1.2 范围内已不接,**永久** v0.9 不接)
- ❌ vigil-firewall PiiScanner trait 不接 lang(SemVer 安全 — caller 通过
  `scan_text_with_engine_with_lang` 直调,不走 firewall preflight)
- ❌ vigil-sdk 不暴露 lang-aware API(typed `LanguageHint` 设计推 v0.10)

**v0.10+ 路径**:
- A-prime trusted typed hint:`LanguageHint { lang, source: enum { CallerProvided,
  FixtureExperimental, Heuristic }, confidence: f32 }`,untrusted/unknown → baseline
- 存入 DecisionRecord/audit 字段(可解释 + 可回溯)
- 触发 ADR 0015 Revised § Phase 5(SDK trait 暴露候选)

### Revised § 8.9 — Attribution lang 透传遗留(P1.3 R1 NICE,Codex `019e03b7`)

**当前 v0.9 状态**:`EnsembleEngine::infer_with_attribution(text)` **不接 lang**,
始终走 baseline path(`engine.infer(text)`),与 lang-aware 主路径
(`scan_text_with_engine_with_lang`)**数据可能不一致**:
- 主路径 lang_aware:EU FP 37(应用 -22 FP)
- attribution 路径 baseline:EU FP 59(未应用 lang-conditional)

**当前影响**:
- BENCH_OUT JSON 收集的 `per_sample_diff[].preds[].src` 是 baseline attribution
- diagnose_per_label.py 消费 BENCH_OUT 做 per-engine 矩阵 → 若 caller 跑 lang_aware
  生成 BENCH_OUT,得到的 attribution 不反映 lang-conditional 真实贡献

**v0.10 候选**:扩 API `infer_with_attribution_with_lang(text, lang)`
(推 SDK trait 暴露时一起做,避免独立 commit 反复改);现 doc 显式 legacy 标注。

**当前 P1.3 实测不受影响**:verdict gate(EU recall / TP / FP)直接来自
`scan_text_with_engine_with_lang` 主路径 result;attribution 仅 BENCH_OUT 副产物,
本 P1.3 实测验证不依赖 attribution(BENCH_OUT JSON 在 lang_aware 模式下仅作
baseline attribution 留档)。

---

## Revised — v0.10 candidate F: XlmrProfileMode typed enum(2026-05-09)

**触发**:Codex `019dfdab` 头脑风暴 F 决策点 + 用户拍板("F = typed `PersonThresholdMode::
Baseline | FpStrictOptIn` enum 替代裸 env";本 ADR 命名为 `XlmrProfileMode` 以保
xlmr-specific 语义)。

### Revised § 8.10 — XlmrProfileMode typed mode

```rust
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum XlmrProfileMode {
    Default,    // v0.8 baseline:屏蔽 Email/Phone/Address;Person 不屏蔽
    FpStrict,   // v0.9 P0 opt-in:Default + Person 1.1
}

pub struct XlmrPiiDescriptor {
    mode: Option<XlmrProfileMode>,  // None → env legacy;Some → typed
}

impl XlmrPiiDescriptor {
    pub const fn with_mode(mode: XlmrProfileMode) -> Self;
}
```

**优先级**(`threshold_profile()` 实施):
1. `Some(Default)` → `&XLMR_PROFILE`(忽略 env)
2. `Some(FpStrict)` → `&XLMR_PROFILE_FP_STRICT`(忽略 env)
3. `None`(legacy `Default::default()`)→ `xlmr_profile_from_env()`

**SemVer**:
- `XlmrPiiDescriptor` `unit struct → struct with field` — internal breaking
- 不在 vigil-sdk pub items;internal callers(vigil-firewall / r1_ensemble_e2e /
  engine.rs tests)同步改为 `XlmrPiiDescriptor::default()`(本 commit)
- SDK consumer 不受影响(走工厂入口 `ort_ensemble_scanner_arc_from_env`)

### Revised § 8.11 — SDK 暴露策略(v0.10 候选)

**当前 v0.10 candidate F 已就位**(本 commit):
- `XlmrProfileMode` enum 在 `vigil_redaction::model_descriptor::*` 路径,**未**进 vigil-sdk
- `XlmrPiiDescriptor::with_mode(...)` 关联函数

**v0.10 SDK 暴露 commit 范围**(后续):
- vigil-sdk re-export `XlmrProfileMode`
- 加工厂入口 `ort_ensemble_scanner_arc_with_xlmr_mode(mode: XlmrProfileMode)`
  (replace `ort_ensemble_scanner_arc_from_env` 内 hardcoded `XlmrPiiDescriptor::default()`)
- typed `LanguageHint { lang, source, confidence }` wrapper(D=A-prime 设计)
- 触发 ADR 0015 Revised § Phase 5

### Revised § 8.12 — env 路径不删除(向后兼容过渡)

`VIGIL_XLMR_PROFILE` env 仍生效,**但仅在 `XlmrPiiDescriptor::default()`(legacy
路径)下读**;typed `with_mode` 实例**忽略 env**(reproducible / inspectable
要求)。

未来 v0.11+ 视用户反馈决定是否 deprecation env 路径(若所有 caller 迁移到 typed,
可能加 `#[deprecated]` 警告)。

---

## Revised — v0.9 Sprint 0 P0 opt-in FP-strict profile(2026-05-03)

**触发**:v0.8 Sprint 4 followup(P2.1 §5.3 Codex 019deb45 closure)— xlmr Person 1.1
threshold profile 实测 EU recall -1.7% / FP -22%,**默认拒绝**(防漏报为主)但
Codex closure 提示"高 FP 容忍度场景有产品价值",建议作 **opt-in**。

### Revised § 7.1 — XLMR_PROFILE_FP_STRICT 设计

**两 profile 共存**:
- `XLMR_PROFILE`(default,v0.8 baseline):屏蔽 Email/Phone/Address(3 label)
- `XLMR_PROFILE_FP_STRICT`(opt-in,v0.9 加):上述 3 label + **加 Person**(完全屏蔽)

**触发**:`VIGIL_XLMR_PROFILE=fp_strict` env;其他值 / 未设走 default(unknown
fallback fail-safe)。

**不变量**:`fp_strict ⊃ default + Person`(default 任何变更必须同步 fp_strict;
守门测试 `xlmr_fp_strict_profile_is_superset_of_default_plus_person` 断言此
包含关系)。

### Revised § 7.2 — Trade-off(数据驱动,引用 v0.8 实测)

| 路径 | EU recall | EU TP | EU FP | EU FN | 适用场景 |
|------|-----------|-------|-------|-------|---------|
| **default**(v0.8 baseline) | 0.904 | 104 | 59 | 11 | Vigil mission 防漏报为主(默认) |
| **opt-in fp_strict** | 0.887 | 102 | 46 | 16 | 企业 / 高 FP 容忍度场景(每 finding 强 precision) |

实测引用 `docs/operations/bench/v0.8-sprint4-followup-xlmr-person-block-92.json`
(profile 内容等价,无需重新实测;Codex closure session `019deb45` ACCEPT)。

### Revised § 7.3 — SDK 暴露策略(v0.9)

**当前 v0.9 不暴露**:
- profile struct / threshold 配置 trait → 仍内部(避免 SemVer 锁过早)
- env name `VIGIL_XLMR_PROFILE` 是 ops 配置层,不是 SDK API

**v0.10+ 候选**(若用户反馈表明需要 typed config):
- SDK pub item `XlmrProfile { Default, FpStrict }` enum
- `XlmrPiiDescriptor::with_profile(XlmrProfile)` builder
- 触发 ADR 0015 Revised § Phase 3 SDK 决策

---

## 8. 引用

- Phase 3 brainstorm:`docs/sessions/2026-05-01-v0.7-phase3-brainstorm.md`
- Codex multi-perspective session:`019de2b9-82e4-77a3-b641-fb95bfc0f4ef`
- v0.6.1 multilang bench:`docs/operations/bench/v0.6.1-multilang.json`
- ADR 0013 Revised(multilang 决策):`docs/adr/0013-hardfp-model-merge.md`
- ADR 0016(performance):`docs/adr/0016-performance-gate.md`
- v0.8 Sprint 4 followup 决策:`docs/operations/v0.8-sprint3/p2_1-dual-confirm-calibration.md` §5.3
- v0.9 roadmap:`docs/roadmap-v0.9.md`
