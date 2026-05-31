# ADR 0015 — SDK Boundary & SemVer Policy

- 状态:**Accepted**(v0.7-α Phase 1,2026-05-01)
- 日期:2026-05-01
- 依赖:ADR 0001(Action Control Plane)/ ADR 0013(Hard × Model merge)
- 相关 commit:本 commit(crates/vigil-sdk 首发)
- 驱动决策:Codex multi-perspective brainstorm(session `019ddf19`)

## 0. 摘要

创建 `crates/vigil-sdk` facade crate,选最小 SDK pub items 做 stable 边界;
**显式不暴露** server runtime / 运行时 backend / ops 基建 / MCP 路由 / 凭据 /
policy internals。SDK consumer 走 default-safe path,不可绕过 DecisionRecord 强制
+ fail-closed + no-plaintext invariants。

## 1. 上下文

v0.6 production runtime 完成;Vigil v2 mission 是"本地 AI agent 控制层 + 隐私
最小化引擎"。现状:13 crates,各自 pub API 已较丰富但没有统一 SDK 边界。
3rd-party 想集成 Vigil 必须读多个 crate doc + 自决组合,**易踩 invariants**。

## 2. 决策

### 2.1 创 `crates/vigil-sdk` facade crate

- 仅 re-export 选定 pub items
- 不含运行时实现(纯 facade)
- workspace member,与既有 13 crates 同级

### 2.2 SDK Phase 1 选择(最小核心,Codex ACCEPT)

| Crate | 暴露 |
|---|---|
| `vigil-types` | ApprovalRequest/Resolution/Scope/Status, AuditEvent, DecisionKind/Record, EffectKind/Vector, ToolInvocation(11 items)|
| `vigil-firewall` | Firewall, FirewallConfig, FirewallError, FirewallOutcome, OAuthScopeContext, PiiScanner(6 items)|
| `vigil-redaction` | scan_text, scan_text_with_engine, Finding, FindingSource, PrivacyLabel, RedactionEngine(trait), RedactionResult, RiskSignals, ScanError(9 items)|
| `vigil-mcp` | descriptor_hash(1 item)|
| `vigil-policy` | (无)— 全 internal,引擎暴露会绕过 firewall path |

### 2.3 显式 NOT in SDK(invariant 守门)

- **Server runtime**(Hub / RegistryDescriptorOracle):consumer 不应自建 Vigil server
- **Concrete engines**(NoopEngine/MockEngine/OrtEngine):太底层,test-only
  / bypass-prone / runtime detail
- **Bootstrap**(ensure_model_available / BootstrapError / ModelPaths):
  ops 基建,SDK consumer 不参与模型分发
- **MCP routing**(JsonRpc types / ToolRouter / McpUpstream):routing/server
  integration,SDK consumer 应通过 Firewall 接 Vigil 而非自构 MCP
- **Policy engine internals**(default_pii_rules / Engine / rule types):
  暴露会鼓励绕过 firewall + DecisionRecord 路径
- **Lease / 凭据**:违反 no-token-passthrough 不变量

### 2.4 SemVer 政策

- **当前 0.0.x**:SDK pub items 仍允许小改进(item 签名 / 行为)— 但**移除**
  视为 breaking change;新增允许
- **v1.0 freeze 之后**:SDK pub items 严格 SemVer
  - PATCH:bug fix,行为修正
  - MINOR:新增 pub item
  - MAJOR:**移除/重命名/改签名** SDK pub item
- **non-SDK crate**(vigil-policy / vigil-mcp 内部 / vigil-runner / vigil-audit
  等):仍 v0.x 可独立演进,与 SDK SemVer 解耦

### 2.5 守门机制

- **每 SDK pub item ≥ 1 doc-test**(crates/vigil-sdk/src/lib.rs 已实施)
- **`pub mod prelude`**:default-safe import path
- **SDK 边界变化必经 codex review**(类 ADR 流程):新增项 require Codex ACCEPT;
  移除项 require ADR(本 ADR 0015 后续 Revised 段)
- **`PrivacyLabel::ALL.len() == 8` doc-test 守门**:enum variant 添加触发 SDK
  breaking change 警示

## 3. 理由

### 为什么"最小核心"而非"全 re-export"?

Codex 评估:暴露过多会让早期设计错误冻结成 SemVer 承诺;SDK consumer 真需要
什么尚未明确(无早期用户实证),易陷入"暴露后撤回不能"的死结。**最小核心**给
consumer 走 default-safe path,扩展项随真实用例驱动。

### 为什么 NoopEngine / MockEngine 不暴露?

- `NoopEngine`:总返空 model findings,在生产路径暴露会让 consumer "禁用模型 +
  期望 default 拦截"形成 silent bypass — 违反 fail-closed 不变量
- `MockEngine`:test-only 类型,生产暴露 = 鼓励生产 misuse

### 为什么 `descriptor_hash` 暴露但 `JsonRpc*` 不?

- `descriptor_hash`:audit 关联用,纯 hash 函数,无 server-coupling 风险
- `JsonRpc*`:暴露会鼓励 consumer 自构 MCP server,绕过 Vigil firewall + 
  DecisionRecord 强制 — 违反 control plane 不变量

## 4. 后果

### 正面

- Vigil v0.7 之后任何 3rd-party 集成走稳定 SDK,**自动**受 invariant 守护
- SemVer 政策清晰,1.0 后 SDK consumer 可放心升级
- doc-test 守门确保 SDK 行为契约不漂

### 负面 / 风险

- **暴露不足**:某些 advanced consumer 想自构 engine / hub 会"卡边界",
  需 case-by-case 决策(本 ADR Revised 段记录)
- **SemVer 锁定**:1.0 之后撤回项要付出 MAJOR cost — 但 0.0.x 缓冲允许 v0.7-α
  → v0.7 final 之间小改 SDK item

### 缓解

- v0.7-α/β/final 阶段保留 0.0.x SemVer,允许微调 SDK 选择
- 真用户反馈出现后再决定是否扩展 SDK 暴露(prevent over-design)

## 5. 实施

`crates/vigil-sdk/`(commit 见 git log master):
- `Cargo.toml`:workspace member,4 path-deps(types/firewall/redaction/mcp)
- `src/lib.rs`:pub use 选定 items + prelude module + 4 unit test + 2 doc-test
- `README.md`:quickstart + invariant 约定 + Phase 1 deferred 列表

## 6. 与既有 ADR 关系

- ADR 0001(Action Control Plane):SDK 强制 DecisionRecord 路径,延续此 ADR
  的 control plane 不变量
- ADR 0013(Hard × Model merge):SDK 暴露 `scan_text`(默认 Hard-only)+ 
  `scan_text_with_engine`(扩展点),merge 决策 D1-D6 不变
- ADR 0014(Tauri embed Hub):Hub 不在 SDK 中(server-side internal)

## 7. v0.7 后续 Phase

- Phase 2 Performance:可能加 [`PiiScanner::scan_perf`] benchmark hooks 到 SDK
- Phase 3 Multi-Model:加 ModelDescriptor + selection API 到 SDK

---

## Revised — v0.8 Sprint 4 P3.1 浅级 ensemble 暴露(2026-05-03)

**触发**:v0.8 Phase 3 Multi-Model Ensemble production-ready 收官(EU recall 0.904
P1.3 92-sample 真跑 PASS,Sprint 3 P2.1 dual_confirm 算法稳:不引入 per_label_min_engines
API)。SDK 现具备稳定边界条件暴露 ensemble**配置级 API**,但**不**暴露完整 trait
(ModelDescriptor / EnsembleEngine / EngineAttribution)— 后者算法仍可演进,过早 SemVer
锁定有过度设计风险。

### 7.1 v0.8 新增 SDK pub items(commit `f2ec7f0` + R1 ACCEPT)

| Pub item | 路径 | 用途 |
|----------|------|------|
| `SDK_MODEL_ID_OPENAI_PRIVACY_FILTER_V1` | const &str | model_id 配置 / audit join |
| `SDK_MODEL_ID_XLMR_PII_V1` | const &str | (同上) |
| `SDK_MODEL_ID_YONIGO_PII_V1` | const &str | (同上) |
| `EngineStatusReport` | re-export from vigil-firewall | scanner 退化状态 (Sprint 1 R1 补) |
| `ort_ensemble_scanner_arc_from_env` | **SDK-owned wrapper** (`ort` feature) | 三引擎工厂入口 |
| `EngineFactoryError` | **SDK-owned enum** (`ort` feature, non_exhaustive) | 工厂错误类型;wrap 底层 `EngineError` |

**R1 MUST-FIX(Codex 019deb53)**:`ort_ensemble_scanner_arc_from_env` 由直接
re-export 改为 **SDK-owned wrapper**(thin facade),签名 pin 在 SDK 层
(`-> Result<Arc<dyn PiiScanner>, EngineFactoryError>`)。底层 vigil-firewall /
vigil-redaction `EngineError` 签名变化不级联破 SDK SemVer。`EngineFactoryError`
是 `non_exhaustive` 自有 enum,3 主 variant + Other 兜底;Display 字符串可演进
(MINOR),variant 名锁定(MAJOR 改)。

**ort feature**:Cargo.toml 加 opt-in `ort` feature;默认关闭,SDK default-safe
path(NoopEngine + Hard rules)不依赖 ORT runtime。启用即透传到
vigil-firewall/ort + vigil-redaction/ort。

### 7.2 显式 NOT in SDK(v0.8 仍内部)

| 内部项 | 不暴露理由 |
|--------|-----------|
| `EnsembleEngine` 直接构造 | caller 自组 engines vec 易配置错(model_id 顺序 / dual_confirm 集合 / etc),工厂入口已封装最佳实践 |
| `EngineAttribution` | P2.0 内部诊断;Sprint 3 P2.1 决议**不引入** `per_label_min_engines` API,EngineAttribution 是配套数据结构,目前仅 bench/diagnose 工具消费,SDK consumer 不需要 |
| `ModelDescriptor` trait | 模型变更频率高(threshold profile / canonical mapping 调整),trait 暴露会让每次模型升级都触发 SemVer event |
| `with_dual_confirm` / `with_model_ids` builder | 内部配置;dual_confirm 决议:数据驱动当前不启用任何 label;builder 留 v0.9+ 视情况暴露 |

### 7.3 守门(commit `f2ec7f0`)

- doc-test `__sdk_ensemble_v0_8_visible`:三 model_id 字符串值 + distinct
- unit test `sdk_model_id_constants_match_descriptor_source`:与 vigil-redaction
  descriptor 同源(任一漂移 fail);用 `ModelDescriptor.model_id()` 方法对比
- unit test `sdk_ort_ensemble_factory_visible_with_feature`:`ort` feature 启用
  时工厂入口可见(feature-gated 编译期守门)

### 7.4 SemVer 影响(R1 修订)

- 三 model_id 常量:v0.8 锁定字符串值 + identifier 名;改 = MAJOR
- `ort_ensemble_scanner_arc_from_env`:**SDK-owned wrapper**(R1 修订:不再直接
  re-export);签名 `() -> Result<Arc<dyn PiiScanner>, EngineFactoryError>` pin SDK 层
- `EngineFactoryError`:SDK-owned enum,non_exhaustive;variant 名锁定(MAJOR 改),
  Display 字符串可演进(MINOR);新 variant 加 = MINOR(non_exhaustive 缓冲)
- `EngineStatusReport`:re-export from vigil-firewall(SDK 层无独立类型,Sprint 1
  R1 补 re-export 修 guide §4.2 漂移)
- ort feature 锁定:启用透传到 vigil-firewall/ort + vigil-redaction/ort,改透传集 = MINOR

### 7.5 v0.9+ 候选(留观察期)

- xlmr-only `Person: 1.1` threshold profile(R1 Suggestion 录入,P2.1 §5.3)
  → ✅ v0.9 P0 落地为 opt-in fp_strict env;v0.10 Sprint 1 升级为 typed `XlmrProfileMode`(§ Phase 5)
- `EngineAttribution` 暴露(若 SDK consumer 真需 cross-engine 共识可见性)
- `ModelDescriptor` trait(若 3rd-party 真需自定义模型);触发 ADR 决策

---

## Phase 5 — v0.10 Sprint 1: typed XlmrProfileMode SDK 暴露(2026-05-09)

**触发**:Codex `019dfdab` 头脑风暴 F 决策 + 用户拍板;v0.10 candidate F
(typed enum 替代裸 env)在 v0.9 release 后启动。

### Phase 5.1 — v0.10 新 SDK pub items(commits `ccd0e48` + 本 commit)

| Pub item | 路径 | 用途 |
|----------|------|------|
| `XlmrProfileMode` | re-export from `vigil_redaction::model_descriptor::*`(non_exhaustive)| typed xlmr profile mode 替代裸 `VIGIL_XLMR_PROFILE` env |
| `ort_ensemble_scanner_arc_with_xlmr_mode` | **SDK-owned wrapper**(`ort` feature)| typed 工厂入口;忽略 env(reproducible) |

### Phase 5.2 — typed vs env 路径分工

| 路径 | 触发 | 行为 | 用途 |
|------|------|------|------|
| `ort_ensemble_scanner_arc_from_env` | `XlmrPiiDescriptor::default()` legacy | 读 `VIGIL_XLMR_PROFILE` env | ops 部署配置(向后兼容 v0.9) |
| `ort_ensemble_scanner_arc_with_xlmr_mode(mode)` | typed | 忽略 env;走 mode | SDK consumer reproducible / inspectable |

**典型 SDK consumer 用法**:
```rust
use vigil_sdk::{ort_ensemble_scanner_arc_with_xlmr_mode, XlmrProfileMode};
// reproducible — 不依赖 env(企业 / SaaS / 测试)
let scanner = ort_ensemble_scanner_arc_with_xlmr_mode(XlmrProfileMode::Default)?;
```

### Phase 5.3 — 守门(commit `ccd0e48` + 本 commit)

- vigil-redaction 内部 5 守门(commit `ccd0e48`):typed/legacy/env 优先级 + non_exhaustive
- vigil-firewall 工厂入口 env miss fail-fast(沿用 ADR 0012)
- vigil-sdk `sdk_ort_ensemble_with_xlmr_mode_factory_visible`:re-export + 工厂签名 + non_exhaustive

### Phase 5.4 — SemVer 影响

- `XlmrProfileMode`:`#[non_exhaustive]` re-export from vigil-redaction;variant 名锁定(MAJOR 改)
- `ort_ensemble_scanner_arc_with_xlmr_mode`:**SDK-owned wrapper**(同 `ort_ensemble_scanner_arc_from_env`,签名 pin SDK 层)
- env 路径(`VIGIL_XLMR_PROFILE`)**保留**作 ops 配置,不 deprecate(向后兼容过渡)

### Phase 5.5 — Sprint 2 typed LanguageHint(2026-05-09 已落地)

**触发**:Decision A-prime(D=C 锁定下的"未来 Firewall 接 lang 时的 typed wrapper"
设计) + Codex `019dfdab` 推荐序第 2 项。

**新公共 items**:

```rust
// vigil-redaction::lang_hint
#[non_exhaustive]
pub enum LangHintSource {
    CallerProvided,        // 高信任(用户 locale / 业务上下文)
    FixtureExperimental,   // 中信任(仅非 production)
    Heuristic,             // 低信任(advisory only;is_trusted = false)
}

#[non_exhaustive]
pub struct LanguageHint {
    pub lang: String,
    pub source: LangHintSource,
    pub confidence: f32,  // 0.0-1.0
}

impl LanguageHint {
    pub fn caller_provided(lang) -> Self;     // confidence = 1.0
    pub fn fixture(lang) -> Self;             // confidence = 1.0
    pub fn heuristic(lang, confidence) -> Self;
    pub fn lang_str(&self) -> Option<&str>;   // fail-closed: heuristic 永返 None;low-conf 返 None
}

pub const LANG_HINT_TRUSTED_CONFIDENCE: f32 = 0.5;

pub fn scan_text_with_engine_with_hint(input, engine, hint: Option<&LanguageHint>);
```

**fail-closed 决策**(`lang_str`):
- `Heuristic` source → `None`(无论 confidence;`feedback_lang_review_authoritative` 约束)
- `confidence < 0.5` → `None`(low-conf 退化 baseline)
- 其他 → `Some(&lang)`

**SDK consumer 用法**:
```rust
use vigil_sdk::{LanguageHint, LangHintSource, scan_text_with_engine_with_hint};
let hint = LanguageHint::caller_provided("de");
let result = scan_text_with_engine_with_hint(text, &engine, Some(&hint))?;
```

### Phase 5.6 — Sprint 3 infer_with_attribution_with_lang(2026-05-09 已落地)

**触发**:v0.9 P1.3 R1 NICE 兑付(Codex `019e03b7`)— BENCH_OUT JSON 在
lang_aware 模式下 attribution 与主路径数据不一致(主 EU FP 37 / attribution
路径仍 baseline EU FP 59)。

**新方法**:
```rust
impl EnsembleEngine {
    pub fn infer_with_attribution_with_lang(
        &self,
        text: &str,
        lang: Option<&str>,
    ) -> Result<(Vec<Finding>, Vec<EngineAttribution>), EngineError>;
}
```

`infer_with_attribution(text)` 委托 `infer_with_attribution_with_lang(text, None)`(legacy
兼容)。`r1_ensemble_e2e` 在 `--lang-aware` 模式下用新方法 — BENCH_OUT JSON
attribution 与主路径口径一致;diagnose_per_label.py 消费 lang_aware bench JSON
得到真 lang-conditional per-engine 矩阵。

### Phase 5.7 — Sprint 6 advisory lang detect(2026-05-09 已落地)

**新公共 items**:

```rust
// vigil-redaction::lang_hint
pub fn detect_lang_heuristic(text: &str) -> LanguageHint;

impl LanguageHint {
    pub fn detect(text: &str) -> Self;  // 等价独立函数
}
```

**算法**(与 `scripts/spike-p3/analyze_fixture_distribution.py::detect_lang` 同口径):

| Tier | 特征 | confidence | 决策 |
|------|------|-----------|------|
| 1 | unicode CJK / Hiragana / Katakana / Hangul 字符集 ≥ 2 字符 | 0.85-0.9 | 高 |
| 2 | 拉丁语系关键词命中(de/fr/it/es) | 0.7 | 中 |
| 3 | 重音字符 fallback(ä/ö/ü/ß / 西欧重音) | 0.4-0.45 | 低(< TRUSTED) |
| 4 | 无特征 → en | 0.3 | 低(< TRUSTED) |

**关键不变量**:**返 `Heuristic` source**,`lang_str()` **永返 None**(无论
confidence 多高)— D=C 锁定 + `feedback_lang_review_authoritative` SDK 边界硬化。

**适用场景**:
- fixture lang 字段标注辅助(P1.0 启发式 Rust 端版本,与 Python 工具同口径)
- SDK consumer 诊断 UI / 建议性显示(显示 detected lang + confidence)
- **永不**作 production 决策权威

**v0.10 SDK pub re-export**:`vigil_sdk::detect_lang_heuristic`。

### Phase 5.8 — 后续 Sprint 状态

- **Sprint 4 设计冻结(2026-05-10 完成)**:Cache hit 路径公共 schema 冻结(无代码),
  详见 ADR 0016 Revised § v0.10 Sprint 4 段。三层接口冻结:
  - `vigil_redaction::ScanCacheMetadata`(non_exhaustive,Option 包装,disabled 时永 None)
  - `vigil_audit::NewRedactionScan` 三 Option 字段(`cache_hit` / `cache_lookup_us` /
    `cached_from_scan_id`)+ schema migration ALTER TABLE 文档
  - `vigil_types::DecisionRecord` 加 `cached_from_scan_id: Option<String>`(已 non_exhaustive)
  - 8 条守门不变量(C1-C8)留 Phase 3 实施;cache hit 不绕 audit/firewall(C1/C2),
    decision_id 永新生成(C3),disabled 时永 None(C6)
- **Sprint 5 待启**:Phase 4 多语言深度模型(中/日/俄),需独立 brainstorm + 用户许可
  - cache invalidation 与模型 `engine_id` / `descriptor_version` 耦合,Sprint 5 完成
    + 稳定期后再启 Sprint 4 Phase 3 实施(详见 ADR 0016 Revised § F)
- **未拍板**:Firewall::evaluate 接 lang(D=C 锁定;v0.11+ 视用户反馈用 typed
  `LanguageHint` 实施)

---

## 8. 引用

- v0.7 brainstorm:`docs/sessions/2026-05-01-v0.7-brainstorm.md`
- v0.7 roadmap:`docs/roadmap-v0.7.md`
- Codex session:`019ddf19-626a-7411-bb24-76788ec93497`
- Vigil v2 战略:`.workflow/.roadmap/RMAP-vigil-v2-privacy-filter-2026-04-24/roadmap.md`
