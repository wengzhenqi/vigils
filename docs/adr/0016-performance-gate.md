# ADR 0016 — Performance Gate(Path-Sliced SLO + Fail-Closed)

- 状态:**Accepted**(v0.7-α Phase 2 Sprint Start,2026-05-01)
- 日期:2026-05-01
- 依赖:ADR 0013(Hard × Model merge)/ ADR 0015(SDK Boundary)
- 驱动决策:Codex 战略协商(session `019de294-01b1-7483-a6c2-4bb49b90bfba`)
- 修订:**取代** v0.7 brainstorm § 6 拟定的 invariant #13 单值阈值(sub-10ms warm
  inference)— 该值与 CPU q4f16 真实推理 ~462-490ms warm 相差 45×,不可达成

## 0. 摘要

Vigil v0.7 invariant #13 从 **单一阈值** 重定义为 **分路径 SLO + fail-closed 兜底**:
默认关键路径(Hard-only `scan_text`)锁 sub-10ms warm,模型增强路径(`scan_text_with_engine`
+ OrtEngine)走更宽预算 sub-1s warm,并加 cache hit / fail-closed 两条护栏。

bench gate 走 **分层落地**:Hard-only 进 CI(workspace cargo bench);ORT 进 release
nightly(独立 ORT runner / VIGIL_RUN_ORT_BENCH=1)。

## 1. 上下文

### 1.1 v0.6.1 真 ORT bench 数据(`docs/operations/bench/v0.6.1-multilang.json`)

机器:linux vigils.ai / CPU q4f16 / ORT 1.24.4 / 32-sample fixture

| 路径 | 总耗时 | 单样本均 |
|---|---|---|
| `hard_only`(NoopEngine,Hard 规则纯 regex)| 2.78ms | **~87μs** |
| `model_only`(OrtEngine.infer 直拿)| 14.8s | **~462ms** |
| `merge`(Hard + Model + ADR 0013)| 15.7s | **~490ms** |

### 1.2 v0.7 brainstorm 草案与现实差距

brainstorm § 6 拟 invariant #13 'sub-100ms cold + sub-10ms warm inference' — 不区分
路径,默认即模型路径。实测模型路径 warm ~462ms 远高于 10ms;要达成需 45× 加速,
当前 ORT/CPU/q4f16 组合不可达(蒸馏 / GPU EP 是 v0.8+ 议题)。

### 1.3 关键洞察

**默认关键路径就是 Hard-only**:
- `scan_text` default 路径走 NoopEngine(`engine.rs:101`),返空 model findings
- `scan_text_with_engine` + OrtEngine 是 **opt-in 激活**(feature `ort` + 模型分发)
- v0.6.1 firewall 默认 deny 路径 + Hard 规则即可拦 secret 类(github_token / slack_webhook
  / stripe_key / google_api / gitlab_pat / database_url)— Hard-only 已是产品安全核心

故 sub-10ms warm 阈值天然适配 Hard-only;模型路径是 'enhanced privacy' 增量,应有
独立预算。

## 2. 决策

### 2.1 invariant #13 重定义:Path-Sliced SLO

| 路径 | Cold p95 | Warm p95 | 实测 | 状态 |
|---|---|---|---|---|
| **Default critical path**(`scan_text` Hard-only)| < 100ms | **< 10ms** | warm ~87μs | 达成 |
| **Enhanced path**(`scan_text_with_engine` + OrtEngine)| < 10s | **< 1s** | warm ~462-490ms / cold ~7s | 达成 |
| **Ensemble path**(`EnsembleEngine` + 多 OrtEngine,P3 E6a S3 实施)| < 30s | **< 1.5s** | warm ~121ms(spike-3 Python POC,3 engines)| Phase 3 |
| **Cache hit path**(input hash → finding cache,Phase 2 stretch)| n/a | **< 10ms** | 未实现 | Phase 2 |

**Ensemble path RAM 预算**:
- 单引擎 RAM ~ 700-840MB(q4f16 模型 + 推理 buffer)
- 双引擎 ensemble RAM ≤ **1500MB**(spike-3 实测 1449MB)
- 三引擎 ensemble RAM ≤ **2200MB**(三模型并存,需 lazy-load 控制)
- ensemble path **opt-in**(显式 config 启用,不在 default critical path 上)

### 2.2 Fail-Closed 兜底(模型路径)

模型路径若超 budget(timeout / OOM / engine error)→ 退化到 Hard-only:
- `scan_text_with_engine` 内部 wrap timeout(默认 2s,上界保护;通过 ENV 可调)
- 退化路径产 `decision_id` 标 `model_path_degraded` + `reason` 字段(timeout / engine_error
  / oom)
- ledger append 'engine.degraded' 事件,审计可追溯
- 不破坏 fail-closed 不变量:Hard 规则继续守 secret 类,只是 enhanced PII 类(person /
  address / date)可能漏

### 2.3 bench gate 分层

| 层 | bench | 触发 | gate 阈值 | CI 策略 |
|---|---|---|---|---|
| **CI bench**(workspace,0 ORT)| `scrub` + `scan_hardonly`(本 ADR 新加)| 每 PR | warm regression < 20% | github actions cargo bench --bench scrub --bench scan_hardonly |
| **Release bench**(ORT 独立 runner)| `precision_recall` --features ort | tag/release | model warm < 1s p95 / cold < 10s p95 | 远程 vigils.ai / VIGIL_RUN_ORT_BENCH=1 |
| **Tag 守门** | 1 + 2 全过 | release tag | 任一不过 → block release | 手工 + scripted check |

### 2.4 Warmup API(Phase 2 实施项)

`OrtEngine::warmup(&self) -> Result<(), EngineError>` public API:
- 用预设短文本(空 prompt 或 1-token)跑 1 次 `infer`,把 cold 7s 摊到 app 启动
- apps/desktop GUI build 启动时调一次(异步 spawn,不阻塞 splash)
- bootstrap 完成后(模型已下载)立即 warmup,首次真请求即 warm
- 守门:`tests/engine_ort_smoke.rs` 加 warmup → infer 双段 latency 断言(warmup + 真请求)

### 2.5 Cache hit 路径(Phase 2 stretch / Phase 3)

input hash → finding cache(LRU,默认 1024 entries):
- 命中 → 直接 return cached findings,p95 < 10ms
- 不命中 → 走原路径,缓存结果(LRU eviction)
- **不变量保留**:cache key 含 `text_sha256` + `engine_id`(模型版本变即 invalidate);
  cache TTL 24h(防 model 配置漂);cache disabled by default,显式 opt-in(避免审计
  路径上 silent 读缓存)

stretch:Phase 2 设计 + 接口冻结;实现可推 Phase 3。

## 3. 理由

### 为什么不简单调高 brainstorm § 6 的阈值?

- 单值阈值无法表达"默认安全 + 增强语义"双层结构;升到 1s 即放弃 Hard-only 的 sub-ms
  优势宣传
- 分路径 SLO 让产品文档可清晰说明:'默认即时 + opt-in 增强 + 兜底安全'

### 为什么 fail-closed 兜底而不是 fail-open?

- ADR 0001 / 0011 沿用 fail-closed 不变量;模型 timeout 不应该让 prompt **更宽松**
- 退化到 Hard-only 仍守 secret 类(产品核心安全承诺),enhanced PII 漏检是 graceful
  degradation 而非 invariant 违反

### 为什么 cache hit 路径设为 stretch?

- 主路径 + warmup + 分层 gate 已是 Phase 2 完整 sprint
- cache 涉及 audit trail 设计(cache hit 是否计入 ledger?);需独立讨论
- 性能上 Hard-only 已 sub-ms,cache 增量收益有限;模型路径才急需,但模型路径独立预算
  已宽到 1s

## 4. 后果

### 正面

- invariant #13 实测可达,不破承诺
- Hard-only sub-10ms 是真护栏,产品文档可宣传
- 模型路径有 fail-closed 兜底,故障不破坏 control plane
- bench gate 分层让 workspace CI 不依赖 ORT,保持 0-ORT-默认编译 SLA

### 负面 / 风险

- 路径切片让 invariant 文档稍复杂(3 path × 2 metric)
- fail-closed 退化路径需要审计能识别(`decision_id = model_path_degraded`)
- cache 推迟到 Phase 3,模型路径常见 prompt 重复扫描时性能仍 ~500ms

### 缓解

- ADR 文档清晰列分路径表,SDK README 给一行总结
- `decision_id` 已有结构化 schema,加新值即可
- Phase 3 多模型 sprint 会自然驱动 cache 设计(因模型多了,缓存效益放大)

## 5. 实施 — Phase 2 sprint 工作清单

### 5.1 Sub-Phase 2A:Performance Baseline(workspace,0 ORT)

- [ ] `crates/vigil-redaction/benches/scan_hardonly.rs` 新加:scan_text(NoopEngine 路径)
      criterion bench,1KB / 10KB / 100KB,cold/warm 双段
- [ ] 在现有 `scrub.rs` bench 上加 cold-iter 测算(criterion `bench_function` first iter)
- [ ] CI 集成:github actions(若已有)加 cargo bench --bench scan_hardonly --bench scrub
      + criterion baseline diff 阈值

### 5.2 Sub-Phase 2B:OrtEngine.warmup() API

- [ ] `crates/vigil-redaction/src/engine.rs::OrtEngine::warmup(&self)` public API
- [ ] doc-test:warmup → infer 链式调用(短 prompt,验证不 panic)
- [ ] `apps/desktop/src/embed.rs`(gui feature):启动后异步 spawn warmup task
- [ ] `tests/engine_ort_smoke.rs` 扩展:warmup 后 infer 测 warm latency

### 5.3 Sub-Phase 2C:Invariant #13 文档落地

- [x] 本 ADR 0016 创建
- [ ] `docs/roadmap-v0.7.md` § 3 #13 改写(已部分完成)
- [ ] `crates/vigil-sdk/README.md` 加 'performance contract' 段
- [ ] `CHANGELOG.md` v0.7-α2 段记录

### 5.4 Sub-Phase 2D:Fail-Closed 兜底(已落地)

- [x] `scan_text_with_engine_budgeted(input, Arc<dyn RedactionEngine>, Duration)`
      新 API(`crates/vigil-redaction/src/scan.rs`):std::sync::mpsc::recv_timeout
      + thread::spawn,0 新依赖
- [x] `EngineStatus` enum:`Ok` / `DegradedTimeout` / `DegradedError`
- [x] `BudgetedScanOutcome { result, status }` 返回类型(不破现有 RedactionResult)
- [x] 4 守门测试(within budget / timeout degrade / engine error degrade / empty input
      fail-closed):**fail-closed 不变量**(Hard secret 路径在退化场景仍命中)
- [x] SDK 暴露 `scan_text_with_engine_budgeted` + `BudgetedScanOutcome` + `EngineStatus`
      + doc-test 类型可见性守门
- [x] **firewall 集成**(Phase 2D-fw,A-lite 路径,Codex session `019de294` ACCEPT):
      新 `ort_scanner_arc_from_env_with_budget(budget)` 工厂返 `Arc<dyn PiiScanner>`,
      内部 `BudgetedOrtPiiScanner` 走 `scan_text_with_engine_budgeted` —
      0 改 `PiiScanner` trait / 0 改 `Firewall` API / 0 改 `PreflightSummary`(SemVer 安全),
      模型 timeout 自动退化 Hard-only;生产推荐 budget = `Duration::from_secs(2)`
- [ ] `decision_id = model_path_degraded` 落地(caller 责任,推 v0.7-α3 firewall
      decision_reasons 改造)
- [ ] ledger 'engine.degraded' 事件 schema(推 v0.7-α3 audit 扩展;Codex 建议先用
      reasons/FTS 字符串稳定行为,事件 schema 早冻结风险大)

## 6. 与既有 ADR 关系

- **ADR 0001**(Action Control Plane):fail-closed 兜底沿用此不变量
- **ADR 0013**(Hard × Model merge):本 ADR 是性能侧补充;merge 决策表 D1-D6 不变,只
  是 D6 fail-closed 加 'budget exceeded' 子条款
- **ADR 0015**(SDK Boundary):SDK README 加 'performance contract' 引用本 ADR

## 7. 引用

- v0.7 brainstorm:`docs/sessions/2026-05-01-v0.7-brainstorm.md`
- v0.7 roadmap:`docs/roadmap-v0.7.md`(§ 3 #13 已修订)
- v0.6.1 multilang bench:`docs/operations/bench/v0.6.1-multilang.json`
- Codex 协商 session:`019de294-01b1-7483-a6c2-4bb49b90bfba`(本 ADR 决策来源)

---

## Revised — v0.10 Sprint 4 Cache Hit 路径接口冻结(2026-05-10)

**驱动**:ADR 0015 Phase 5.8 § Sprint 4 — 在不引入 cache 实施代码的前提下冻结
公共 schema,让 Phase 3 真实施时不必再走 SemVer break。原则与 § 2.5 一致:
**stretch:Phase 2 设计 + 接口冻结;实现推 Phase 3**。

### A. 设计目标(冻结)

1. **cache hit 不绕过 audit**:每次 scan(无论 hit/miss)仍走 `insert_redaction_scan`
   全路径,**不变量"绝不存原文" + audit 完整性**优先于性能
2. **cache hit 不绕过 firewall.evaluate**:cache 只缓存 redaction `Vec<Finding>`
   层(语义裁定)— firewall 决策(Allow/Deny/Approve)始终走 PolicyEngine,
   Hard rules / scope allowlist / risk_score 全部重计算
3. **decision_id 永远新生成**:每次调用产新 `DecisionRecord.decision_id`,即便
   findings 全 cached。新增 `cached_from_scan_id: Option<String>` 字段做溯源,
   fresh compute 时 None
4. **cache disabled by default**:符合 § 2.5 "避免审计路径上 silent 读缓存"
5. **SemVer 抗未来**:所有新增字段挂在 `#[non_exhaustive]` 之内

### B. 公共类型 schema(冻结,实施推 Phase 3)

#### B.1 vigil-redaction:`ScanCacheMetadata`(新)

```rust
/// v0.10 Sprint 4 接口冻结,Phase 3 实施(实施前永远 None)。
///
/// 标注本次 scan 的 cache 路径状态,Phase 3 OrtEngine::with_cache(LruCache::new(1024))
/// 显式 opt-in 后由 engine 写入。
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct ScanCacheMetadata {
    /// true = cached return(LRU 命中);false = fresh compute + 写入 cache
    pub hit: bool,
    /// cache key:sha256(text + engine_id + descriptor_version)[..16] hex-lower
    /// 与 ledger `redaction_scans.fingerprint` 同口径,可跨表 join
    pub key_fingerprint: String,
    /// hit 时剩余 TTL(秒);miss 时 None
    pub ttl_remaining_s: Option<u32>,
    /// cache 查询耗时(微秒,含 LRU lookup + key 计算);fresh compute 仍记录
    /// 用于 § 2.5 "p95 < 10ms" 验证
    pub lookup_us: u32,
}
```

**未实施时的承诺**:Phase 3 之前所有 scan API 返 `cache: Option<ScanCacheMetadata>`
**永远 None**(不需 caller 处理)。Phase 3 opt-in 后才出现 Some。

#### B.2 vigil-audit:`NewRedactionScan` 扩展(冻结,实施推 Phase 3)

```rust
pub struct NewRedactionScan<'a> {
    pub session_id: &'a str,
    pub source: &'a str,
    pub text_length: usize,
    pub fingerprint: &'a str,
    // v0.10 Sprint 4 冻结字段(Phase 3 实施前不持久化):
    pub cache_hit: Option<bool>,                       // None = cache 未启 / Phase 3 前
    pub cache_lookup_us: Option<u32>,
    pub cached_from_scan_id: Option<&'a str>,          // hit 时的源 scan_id
}
```

**Schema migration**(Phase 3):`redaction_scans` 表 `ALTER TABLE` 加三列,默认
NULL(向后兼容现有 ledger 数据库;无迁移脚本即可读旧记录)。

```sql
-- Phase 3 migration,v0.10 不应用
ALTER TABLE redaction_scans ADD COLUMN cache_hit INTEGER;       -- 0/1, NULL=未启
ALTER TABLE redaction_scans ADD COLUMN cache_lookup_us INTEGER;
ALTER TABLE redaction_scans ADD COLUMN cached_from_scan_id TEXT;
```

#### B.3 vigil-types:`DecisionRecord` 扩展(冻结)

```rust
#[non_exhaustive]
pub struct DecisionRecord {
    pub decision_id: String,
    pub invocation_id: String,
    pub decision: DecisionKind,
    pub risk_score: u8,
    pub reasons: Vec<String>,
    pub policy_ids: Vec<String>,
    pub created_at: i64,
    // v0.10 Sprint 4 冻结字段:
    pub cached_from_scan_id: Option<String>,           // 溯源同上,Phase 3 才填
}
```

**注**:`DecisionRecord` 已是 `#[non_exhaustive]`(line 26 of decision.rs),加字段
不破 SemVer。

### C. 不变量(必须 Phase 3 实施时守门)

| # | 不变量 | 守门测试(Phase 3 落) |
|---|--------|---------------------|
| C1 | cache hit 必触发 `insert_redaction_scan`(audit 不可绕) | `cache_hit_still_writes_audit_row` |
| C2 | cache hit 必触发 `firewall.evaluate`(决策不可缓存) | `cache_hit_still_runs_policy_engine` |
| C3 | `decision_id` 每次新生成(UUIDv4 唯一性) | `cache_hit_decision_id_is_fresh` |
| C4 | `cached_from_scan_id` Some 当且仅当 cache_hit==true | `cached_from_only_set_on_hit` |
| C5 | `key_fingerprint` 含 `engine_id` + `descriptor_version`,模型升级即 invalidate | `model_upgrade_invalidates_cache` |
| C6 | cache disabled 时 `cache: Option<_>` **永 None** | `cache_disabled_returns_none` |
| C7 | LRU eviction:capacity 1024 时 1025 项写入,oldest 被驱逐 | `lru_eviction_at_capacity` |
| C8 | TTL 24h:`ttl_remaining_s` ≤ 24*3600;过期不返(必 fresh compute) | `ttl_expiry_triggers_fresh_compute` |

### D. SDK boundary(v0.10 Sprint 4 不暴露)

ScanCacheMetadata / DecisionRecord 扩展字段 **不**经 vigil-sdk 暴露(Phase 3
opt-in 时再走 SDK-owned wrapper,沿用 Sprint 1 XlmrProfileMode 模式)。

### E. SemVer 抗

- 所有新增公共字段挂 `#[non_exhaustive]`(已是)
- 所有新增 `Option<_>` 字段默认 None,旧 caller 无视即可编译通过
- ledger schema migration 走 `ALTER TABLE ADD COLUMN`(NULLABLE),旧 reader 不破

### F. 与 v0.10 其他 Sprint 的互斥

- **不与 Sprint 5(Phase 4 多语言深度模型)同 sprint 实施** — 模型变更可能改
  `engine_id` / `descriptor_version`,cache invalidation 边界与模型 sprint 耦合;
  推荐 Phase 3 = Sprint 5 完成 + 1 个稳定期后再启 cache 实施
- **与 Sprint 1-3(SDK trait 暴露)正交** — cache 不依赖 typed LanguageHint /
  XlmrProfileMode

---

## Revised — v0.10 Sprint 4 收尾状态(2026-05-10)

- [x] 设计冻结:本 § Revised 段(B 公共类型 / C 不变量 / E SemVer)
- [x] ADR 0015 Phase 5.8 状态同步
- [ ] **Phase 3 实施**(待 Sprint 5 + 稳定期后再启):
      - vigil-redaction `ScanCacheMetadata` 落代码 + LRU + 8 守门测试
      - vigil-audit `NewRedactionScan` 三新字段 + schema migration
      - DecisionRecord `cached_from_scan_id` 落字段 + firewall 透传
      - SDK opt-in wrapper(沿 Sprint 1 模式)
