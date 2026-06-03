# ADR 0002 — 审计账本 (vigil-audit) 的脱敏职责、事件时序、Hash Chain 规范

- 状态:Accepted
- 日期:2026-04-20
- 适用迭代:I01 及以后
- 相关:ADR 0001 / AGENTS.md §1 §4

## 背景

I01 实装 SQLite Ledger,是"可证明的控制平面"的黑匣子。在开工前需要把三个跨
迭代的接口语义钉死,避免 I02+ 返工。

## 决策

### D1:脱敏职责线 —— caller 先脱敏,ledger 入口做 fail-closed 自检

```text
caller ──▶ vigil-redaction::redact(value)
             │
             ├─▶ redacted_payload: serde_json::Value
             └─▶ fts_summary: Option<String>
             │
             ▼
        vigil-audit::Ledger::append_event(
            session_id, event_type,
            payload: redacted_payload,   // 信任已脱敏
            redacted_text: fts_summary,  // FTS 专用
        )
```

- **`vigil-redaction`**:纯函数,无 IO。I01 实装最小规则集(AWS / GitHub / OpenAI /
  Anthropic / JWT / PEM / `.env` / email / 内部 IP)。后续 I02 / I09 扩展。
- **`vigil-audit`**:不做二次脱敏,假设 caller 已脱敏。但在 `append_event` 入口做
  **fail-closed 自检**:扫描 `payload` 序列化文本,命中强指纹(如 `ghp_[A-Za-z0-9]{36}` /
  `-----BEGIN .* PRIVATE KEY-----` / `sk-ant-[A-Za-z0-9]+` /
  `AKIA[0-9A-Z]{16}`)则**拒绝写入并返回错**,强迫 caller 先走 redaction。
- 字段数测试(I00 已落)保证本类型不会被无声新增字段。

**理由**:单一职责(redaction 不碰存储,audit 不懂规则),同时在存储入口立一道
"防越权门",让 caller 忘记调用 redaction 时失败响亮而非静默。

### D2:事件时序由类型状态机强制,不靠运行时断言

AGENTS.md §1 要求 "Every tool call must create a DecisionRecord before execution"。
即使 I01 还没有 firewall / executor,也把这条时序写进 API 形状:

```rust
// 由 Ledger 签发,携带 invocation_id
let span: ToolCallSpan<Opened> = ledger.tool_call_span(invocation_id, session_id)?;

// Step 1 必做:decision 事件写入
let span: ToolCallSpan<Decided> = span.decision_recorded(decision_record, ..)?;

// Step 2 可选:执行后写入 Done / Failed
span.executed(result)?;            // or
span.execute_failed(err)?;

// Drop 时若停留在 Opened 或 Decided,Ledger 自动追加
// "tool_call.abandoned" 事件,让审计链不断裂。
```

类型状态(`Opened` → `Decided` → `Done|Failed`)由 `PhantomData<S>` 承载,
错误顺序在**编译期**被拒绝。并发安全:每个 span 持有 Ledger 级 mutex 引用,
保证 hash chain 单写者。

**理由**:时序错误在运行时被 panic/Err 还是晚;钉死在类型系统让 firewall / executor
的后续迭代没有绕过可能。

### D3:Hash Chain 规范(带 domain tag + 长度前缀 + JCS)

```text
domain_tag       = b"vigil.ledger.event.v1"          (21 bytes 常量)
prev_hash_bytes  = sha256 的 32 字节;genesis 时为 32 个 0x00
payload_bytes    = serde_jcs::to_vec(payload)        (RFC 8785 JCS)
created_at_bytes = i64 big-endian                    (8 bytes)

input = domain_tag
      ‖ u32_be(32) ‖ prev_hash_bytes
      ‖ u64_be(payload_bytes.len()) ‖ payload_bytes
      ‖ u32_be(8) ‖ created_at_bytes

event_hash_hex = hex_lower(sha256(input))
```

- **domain tag** 防跨用途哈希碰撞(未来 decision_hash / approval_hash 用不同 tag)。
- **长度前缀** 防串接歧义(避免 `"ab" + "c"` vs `"a" + "bc"` 撞车)。
- **Big-endian** 固定跨平台语义。
- **JCS(RFC 8785)** 确保 key 顺序 / 数字格式 / 字符串 escape 统一。

**测试向量**(`crates/vigil-audit/tests/hash_chain_vectors.rs`):
- TV1 Genesis: `payload = {}`, `created_at = 1700000000`, `prev_hash = genesis(全 0)`
- TV2 After TV1: `payload = {"a":1,"b":"测试"}`, `created_at = 1700000001`
- TV3 JCS 稳定: key 乱序的 `{"b":"测试","a":1}` 必须产出与 TV2 相同的 hash

TV 一旦锁定,日后重构必须通过 TV 或发 ADR 明示向后兼容策略。

## 影响

- `crates/vigil-audit` 依赖:`rusqlite { features = ["bundled"] }` + `serde_jcs` + 已有的
  `sha2` / `hex`;新增 `uuid` 与 `chrono` 用于 id / 时间戳。
- `crates/vigil-redaction` 不再是空骨架,承担纯函数脱敏职责。
- SQLite PRAGMA:`journal_mode=WAL`、`foreign_keys=ON`、`busy_timeout=5000`、`synchronous=NORMAL`;
  后台 checkpoint 策略在 Ledger 内部管理。

## 取舍

| 放弃 | 理由 |
| ---- | ---- |
| 让 `append_event` 自己做 redaction | 违反单一职责;redaction 规则迭代快,audit 稳定 |
| 运行时 `assert!` 强制时序 | 编译期类型状态更强,且零运行时开销 |
| 不加 domain tag / 长度前缀 | 省 21 + 12 字节开销,但引入跨用途碰撞和串接歧义风险 |
| 用 `serde_json::to_vec`(非 JCS)| 不同平台 / 版本 / 字段顺序可能产生不同 hash,replay 无法复现 |

## Revised 2026-06-03 — Hash chain v2(security audit VIGIL-SEC-001)

**触发**:首次结构化安全审计(OWASP + STRIDE + 供应链 + Vigil 不变量逐条核验,报告
`.workflow/.security/audit-report-2026-06-03.json`,9.9/10,0 Critical/High)。唯一触及核心
保证的发现 = **VIGIL-SEC-001(Medium / A08 完整性)**:hash chain 摘要(v1)只覆盖
`prev_hash` / `payload_jcs` / `created_at`,而 `session_id` / `event_type` / `redacted_text`
是 events 表独立列且(对 `tool_call.*` 事件)不在 payload_json 内 —— 本地具 DB 写权限者可改写
这三列(把事件移出某 session 回放、改写 FTS/UI 显示的 redacted_text、翻转 event_type)而
`verify_chain` **检测不到**,部分削弱方案 §threat #7「审计篡改」缓解。

**决策**:引入 **per-event `chain_version`** + **v2 摘要**(domain tag `vigil.ledger.event.v2`):
- v2 = v1 字段 + length-prefixed `session_id` + `event_type` + `redacted_text`(Option 用 1 字节
  presence tag 区分 None / Some("") / Some(content)),使这三列的**部分篡改**可被检测。
- 版本化保证**历史不破**:`compute_event_hash`(v1)+ DOMAIN_TAG v1 + 已 pin 的 TV1-TV3 测试向量
  **完全不动**;`chain_version` 列 legacy 行 DEFAULT 1 → 按 v1 验证,新事件写 2 → v2;
  `verify_chain` 按存储版本分派,未知版本 fail-closed(`ChainBroken`)。
- 守门测试:`tamper_v2_bound_fields_detected`(篡改三列 → ChainBroken)+
  `legacy_v1_event_and_mixed_chain_verify`(v1 genesis + v2 混合链验证)。

**固有限制(非本修复范围,记录待后续)**:具完整 DB 写权限者仍可一致重写整条链(任意版本/
内容);hash chain 在无**外部 anchor**(定期把最新 hash 发布到不可变位置)时只能检测部分篡改、
抬高门槛。外部 checkpoint 锚定是后续增强方向(threat #7 完全闭合)。

**Codex**:security-invariant 改动按纪律走 Codex review(见 commit message / STATUS.md)。
