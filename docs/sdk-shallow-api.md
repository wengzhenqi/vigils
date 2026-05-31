# Vigil SDK Shallow API — v0.8 Consumer Guide

**Version**: v0.8(2026-05-03)  
**Crate**: `vigil-sdk`  
**ADR**: [0015 SDK Boundary § Revised v0.8](./adr/0015-sdk-boundary.md#revised--v08-sprint-4-p31-浅级-ensemble-暴露2026-05-03)

---

## 1. SDK 浅级 API 设计原则

Vigil SDK 提供**最小核心** + **配置级 API**,SDK consumer 走 default-safe path 自动
受 invariants 守护(fail-closed / no-plaintext / DecisionRecord 强制)。

**v0.8 浅级暴露**(roadmap §2.4 ACCEPT):
- 配置级 API(`model_id` 常量 + ensemble 工厂入口)— 暴露
- trait / algorithm 内部(`ModelDescriptor` / `EnsembleEngine` / `EngineAttribution`)— **不**暴露

理由:trait 暴露会让模型变更频率高的内部细节冻结成 SemVer 承诺;真用户反馈出现
后再决定扩展(prevent over-design)。

---

## 2. v0.8 新 SDK Pub Items

### 2.1 三 model_id 字符串常量

```rust
use vigil_sdk::{
    SDK_MODEL_ID_OPENAI_PRIVACY_FILTER_V1,  // = "openai-privacy-filter-v1"
    SDK_MODEL_ID_XLMR_PII_V1,               // = "xlmr-pii-v1"
    SDK_MODEL_ID_YONIGO_PII_V1,             // = "yonigo-pii-v1"
};
```

**用途**:
- **配置 / 部署**:写 `EnsembleConfig { models: [SDK_MODEL_ID_*, ...] }` 类配置时,
  避免硬编码 magic string
- **Audit ledger 跨表 join**:`engine.degraded` 事件 payload 含 `engine_id`,SDK
  consumer 写查询时用常量 join,SDK 升级模型不破查询
- **stable contract**:任一字符串改 = MAJOR(vigil-redaction descriptor 同源守门)

### 2.2 Ensemble 工厂入口(opt-in `ort` feature)

```toml
# Cargo.toml
[dependencies]
vigil-sdk = { version = "*", features = ["ort"] }
```

```rust
use vigil_sdk::{ort_ensemble_scanner_arc_from_env, EngineFactoryError};

// 启动期 fail-fast,SDK 自有错误类型(SemVer-pinned;non_exhaustive)
let scanner = match ort_ensemble_scanner_arc_from_env() {
    Ok(s) => s,
    Err(EngineFactoryError::ModelNotFound { context }) => {
        // env 未设 / 路径错 / 文件未下载完整
        eprintln!("Vigil ensemble: model not found ({context})");
        return Err(...);
    }
    Err(EngineFactoryError::SessionInit { reason }) => {
        // ORT init / tokenizer 加载失败(模型损坏 / ORT 版本不兼容)
        eprintln!("Vigil ensemble: session init failed ({reason})");
        return Err(...);
    }
    // **必须** _ 通配(`EngineFactoryError` 是 non_exhaustive,SemVer 缓冲)
    Err(e) => return Err(e.into()),
};

// 注入 Firewall(走 ensemble 多模型 union + Hard rules 决策路径)
let firewall = vigil_sdk::Firewall::with_scanner(ledger, policy, config, scanner);
```

**SDK-owned error**(R1 ADR 0015 §7.1 锁定 SemVer):
`EngineFactoryError` 是 SDK 自有 enum,内部 wrap 底层 `vigil_redaction::engine::EngineError`。
底层签名变化不级联破 SDK SemVer;variant 名锁定(MAJOR 改),Display 字符串可演进(MINOR)。

**前置 env**:
- `VIGIL_ENSEMBLE_OPENAI_DIR` — OpenAI Privacy Filter v1
- `VIGIL_ENSEMBLE_XLMR_DIR` — xlmr-pii-v1
- `VIGIL_ENSEMBLE_YONIGO_DIR` — yonigo-pii-v1

**适用场景 / 不适用场景**:

| 场景 | 推荐路径 | RAM | EU recall |
|------|---------|-----|-----------|
| 企业 release runner / 自有部署 | `ort_ensemble_scanner_arc_from_env`(本) | 1.4-2.2GB | **0.904** |
| Default GUI / hub-cli(单用户) | `ort_scanner_arc_from_env` 单 OpenAI | 838MB | ~0.886 |
| 测试 / CI(无 ORT) | `scan_text` default-safe path(NoopEngine + Hard) | 0 | secret 类完整 |

---

## 3. 不暴露的内部细节(v0.8)

| 内部 | 不暴露理由 | v0.9+ 候选? |
|------|-----------|-------------|
| `EnsembleEngine::new` 直接构造 | caller 自组易配置错;工厂封装最佳实践 | 可能 |
| `EngineAttribution` struct | Sprint 3 P2.1 决议:不引入 `per_label_min_engines` API;P2.0 内部诊断,SDK consumer 不需要 | 视用户反馈 |
| `ModelDescriptor` trait | 模型变更频率高,trait 暴露 = 每次模型升级 SemVer event | 触发 ADR |
| `with_dual_confirm` / `with_model_ids` | 内部配置;dual_confirm 当前不启用 | 视 Phase 4 多语言深度模型 |

详见 [ADR 0015 § Revised v0.8 §7.5](./adr/0015-sdk-boundary.md#75-v09-候选留观察期)。

---

## 4. 完整 SDK Pub Items 索引(v0.8)

### 4.1 v0.7-α Phase 1 既有(稳定)

```rust
// vigil-types
ApprovalRequest / ApprovalResolution / ApprovalScope / ApprovalStatus
AuditEvent / DecisionKind / DecisionRecord
EffectKind / EffectVector / ToolInvocation

// vigil-firewall
Firewall / FirewallConfig / FirewallError / FirewallOutcome
OAuthScopeContext / PiiScanner

// vigil-redaction
scan_text / scan_text_with_engine / scan_text_with_engine_budgeted
BudgetedScanOutcome / EngineStatus
Finding / FindingSource / PrivacyLabel / RedactionEngine
RedactionResult / RiskSignals / ScanError

// vigil-mcp
descriptor_hash
```

### 4.2 v0.8 Sprint 1 新增(A2 firewall ↔ ledger,Sprint 4 R1 补 re-export)

```rust
// vigil-firewall via vigil-sdk(P3.1 R1 commit Sprint 4 final)
EngineStatusReport  // Ok / DegradedTimeout / DegradedError / Unsupported (non_exhaustive)
```

### 4.3 v0.8 Sprint 4 新增(本 P3.1 + R1)

```rust
// vigil-sdk 自有 const(SemVer-locked)
SDK_MODEL_ID_OPENAI_PRIVACY_FILTER_V1  // = "openai-privacy-filter-v1"
SDK_MODEL_ID_XLMR_PII_V1               // = "xlmr-pii-v1"
SDK_MODEL_ID_YONIGO_PII_V1             // = "yonigo-pii-v1"

// vigil-sdk 自有 wrapper + 错误类型(R1:SDK-owned,不 re-export 底层签名)
EngineFactoryError                      // ModelNotFound / SessionInit / Other (non_exhaustive)
ort_ensemble_scanner_arc_from_env       // pub fn (feature = "ort"),
                                        // -> Result<Arc<dyn PiiScanner>, EngineFactoryError>
```

---

## 5. SemVer 政策(0.0.x → 1.0)

- **当前 0.0.x**:SDK pub items 仍允许小改进;**移除**视为 breaking change,需 ADR
- **v1.0 freeze 之后**:严格 SemVer
  - PATCH:bug fix / 行为修正
  - MINOR:**新增** pub item
  - MAJOR:**移除/重命名/改签名** SDK pub item

详见 [ADR 0015 § 2.4](./adr/0015-sdk-boundary.md#24-semver-政策)。

---

## 6. Invariants(SDK consumer 必须遵守)

1. **Fail-closed**:任何 SDK 函数返 Err → consumer **不可**降级为放行
2. **绝不存原文**:SDK 接收 input 文本不会被 SDK 持久化;consumer 也不应把原文写入
   audit / log / 网络
3. **DecisionRecord 强制**:任何 effect 触发(tool invocation / approval / etc)
   必须 first 产出 DecisionRecord
4. **接口稳定**:SDK pub items 在 0.x 阶段允许小改进,但**移除**视为 breaking change

详见 [vigil-sdk 顶层 doc](../crates/vigil-sdk/src/lib.rs)。

---

## 7. 引用

- [ADR 0015 SDK Boundary](./adr/0015-sdk-boundary.md)
- [v0.8 Roadmap](./roadmap-v0.8.md)
- v0.8 Sprint 4 commit `f2ec7f0`(本 P3.1 SDK 浅级暴露)
- v0.8 Sprint 3 P2.0/P2.1(commits `2f0cc0a` / `2898aad` / `7c4c78d`)
