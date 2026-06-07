# ADR 0020 — Audit Checkpoint Anchor(external append-only anchoring against full-chain rewrite)

**Status**: Accepted-design(2026-06-07,Codex 设计审查 ACCEPT-with-changes → 全部 MUST-FIX 已并入下文;§7 列审查解决)
**Context**: 安全审计 SECURITY-AUDIT-2026-06-03 把 threat #7 列为防篡改审计的**固有局限 + tracked follow-up**:
> *"a hash chain without an external anchor cannot stop a full-chain rewrite by an actor with complete DB write access; it raises the bar and makes partial tampering evident. Periodic external checkpointing is the follow-up to fully close threat #7."*

本 ADR 设计该 checkpoint anchor。它是产品**头牌卖点(tamper-evident audit)唯一公认空白**的闭合,也是 launch 时 r/netsec 必然质疑点的防御。属安全核心改动,**纯增量**(不触已 Codex 祝福的 v2 digest / `verify_chain`)。

## 1. Problem(精确威胁模型)

当前 `vigil-audit`(ledger.rs):
- 每事件存 `event_hash`(v2 摘要,绑 prev_hash/payload/created_at/session_id/event_type/redacted_text),链头 = 末事件 `event_hash`。
- `verify_chain()` 复算整链查**内部**一致性 + chain_version 单调非降(防 v2→v1 降级)。

**威胁 #7(full-chain rewrite)**:攻击者持**完整 `events` 表写权限** → 可删改任意历史事件并**一致重算其后所有 hash**。结果:`verify_chain()` 仍通过(内部自洽),但历史已被伪造。哈希链对**部分**篡改可见(改一行不重算后续 → prev_hash 断裂),对**整链重写**无外部参照即不可检。

**关键观察**:要检测整链重写,需要一份攻击者**事后无法追溯篡改**的、对某个历史链头的独立记录。

## 2. Decision

新增**纯增量** checkpoint anchor 层:周期性把链头快照 `(event_id, event_hash)` 写入一个**与 `events` 表分离的 append-only sidecar**;校验时比对"当前 `events[event_id].event_hash` 是否仍等于锚定值"。整链重写会改变历史 event_hash → 与 checkpoint 不符 → 检出。

### 2.1 Checkpoint 记录(Codex MF#3:多绑 row 字段防 rowid 替换)

```
Checkpoint {
    event_id:    i64,      // 锚定的事件序号(链头位置;SQLite rowid)
    event_hash:  String,   // 该事件在锚定时刻的 64-hex event_hash(= 当时链头)
    prev_hash:   String,   // 该事件 prev_hash(锚定链"位置",非仅末值)
    session_id:  String,   // 身份绑定:该 event_id 当时所属 session
    event_type:  String,   // 身份绑定:该 event_id 当时的事件类型
    created_at:  i64,      // 该事件 created_at(身份绑定 + 锚定时序)
    anchored_at: i64,      // emit 的 wall-clock(仅审计/展示,不参与判定)
}
```

**为何不止 `(event_id, event_hash)`**(Codex MF#3):event_id = SQLite rowid,**未**被纳入
`event_hash` v2 摘要。仅 keying `(rowid, hash)` 时,攻击者可 renumber rowid 让 event_id=N
指向另一条其能控制 hash 的伪造事件。多绑 `prev_hash/session_id/event_type/created_at`:
校验时这些字段必须**逐一**等于当前 `events[event_id]` 行 → rowid 替换会使绑定字段不符而
**可见损坏**,而非依赖链校验兜底。校验判定依赖这组绑定字段的不可变性 —— 即"历史上
seq=event_id 处曾存在一条 (prev_hash, session_id, event_type, created_at) 且链头为
event_hash 的事件"。

### 2.2 存储:append-only sidecar(非 DB 内表)—— 设计核心抉择

checkpoint **不**进 `events` 所在的同一 SQLite 库,而是独立 sidecar 文件(JSON-Lines,每行一条 checkpoint),默认路径 = `<ledger_db_path>.checkpoints`。理由(纵深防御 + 诚实威胁框定):

- **分离 blast radius**:威胁 #7 假设攻击者有 `events` 表写权限。若 checkpoint 在**同一库的另一张表**,同一攻击者顺手改之 → 零额外门槛(被否决方案,见 §4)。独立文件迫使攻击者**在两处一致地伪造**。
- **可外部化(这才是"fully close"的路径)**:sidecar 小且 append-only,可被廉价地:(a) OS 层 append-only(`chattr +a` / 只追加权限);(b) 异地同步/备份;(c) 后续签名(ADR 后续 slice)。**真正闭合威胁 #7 的是 checkpoint 存储的外部性**,本层提供该外部性所附着的机制。

### 2.3 API 表面(blast radius 最小化)

独立 `CheckpointLog` 结构,**不改 `Ledger::open` 签名**(避免触全部 Ledger 调用点):

```rust
pub struct CheckpointLog { path: PathBuf }           // 绑定 sidecar 文件
impl CheckpointLog {
    pub fn at(path: impl AsRef<Path>) -> Self;
    pub fn sidecar_for(ledger_db_path: &Path) -> Self;  // <db>.checkpoints 约定
    pub fn emit(&self, ledger: &Ledger) -> Result<Option<Checkpoint>>;  // 读当前链头→原子 append;空链→None
    pub fn load(&self) -> Result<Vec<Checkpoint>>;       // 解析全部;任一坏行/非单调→CheckpointStoreCorrupt
    // ★ Codex MF#1:对外只暴露 verify_anchored —— 内部先 verify_chain 再比对 checkpoint。
    //   不单独对外暴露 verify_against(避免调用方漏掉前置链校验造成 fail-open)。
    pub fn verify_anchored(&self, ledger: &Ledger) -> Result<Anchored>;
}

pub enum Anchored {           // ★ Codex MF#2:区分"已锚定通过" vs "未锚定"(后者绝不冒充 verified)
    Verified { checkpoints: usize, through_event_id: i64 },
    Unanchored,               // 链内自洽但无 checkpoint / sidecar 不存在 → 调用方须如实显示
}
```

- `emit`:在 **ledger 锁的单一临界区内**读 `latest_event_id()` + 该行全部绑定字段(复用 `get_event_detail`),组成 Checkpoint;以**原子 append**(写整行 + `flush`+`sync_data`,避免崩溃/磁盘满留撕裂行)落 sidecar。**只追加,从不改写既有行**。空链 → `Ok(None)`。
- `verify_anchored`(Codex MF#1):**先** `ledger.verify_chain()`(链内自洽 + 版本单调,失败即返回其错误)——这保证 `events[event_id]` 行已是链一致的;**再** `load()` 全部 checkpoint,对每条查当前 `events[event_id]` 并比对**全部绑定字段**(event_hash/prev_hash/session_id/event_type/created_at);任一不符或行缺失(删/截断)→ `CheckpointMismatch { event_id }`。无 checkpoint / sidecar 不存在 → `Anchored::Unanchored`(**非** Verified,**非**静默 Ok)。
- `load` fail-closed(Codex MF#4):坏行/非法 hash(非 64-hex)/ 非正 event_id / 重复 id / **非严格递增**(append 应单调)/ event_id 超出当前链 max → `CheckpointStoreCorrupt { reason }`。**绝不**静默跳过坏行。

### 2.4 Error / 状态分类(fail-closed)

`AuditError` 加两个变体(已确认 `AuditError` 是 `#[non_exhaustive]`,加变体 **semver 安全**):
- `CheckpointMismatch { event_id }` —— 当前行绑定字段与锚定不符(**整链重写检出信号**,区别于 `ChainBroken` 的链内断裂)。
- `CheckpointStoreCorrupt { reason }` —— sidecar 自身损坏/非单调/重复/越界/非法行 → 拒绝(不静默跳过)。

"无 checkpoint / sidecar 不存在"**不是** error 而是 `Anchored::Unanchored` 状态(Codex MF#2):它表示"链内自洽但未锚定",CLI 必须**如实**显示而非冒充 verified。

### 2.5 CLI 表面(Codex MF#5:CLI 行为"扩展",非全局零变化)

- `vigil-hub checkpoint`(新子命令):对默认共享账本 emit 一条 checkpoint;打印 `(event_id, head_hash 前缀)`。供用户/cron 周期锚定。
- `verify-chain` 现有路径改调 `CheckpointLog::sidecar_for(db).verify_anchored(ledger)`(内部先链内、再锚点)。三态如实输出:
  - `Verified{checkpoints,through_event_id}` → "chain internally valid **and** anchored through event N (M checkpoints)"。
  - `Unanchored` → "chain internally valid; **no checkpoints found — run `vigil-hub checkpoint` to anchor**"(**不**报 tamper-proof)。
  - `CheckpointMismatch`/`CheckpointStoreCorrupt` → 失败 + 明确原因。
  - **诚实**:这是 `verify-chain` CLI 的**行为扩展**(以前仅链内过即 pass;现额外跑锚点)——加密核心(digest/verify_chain)未变,但 CLI 判定面扩大,须在 changelog/输出说明。
- `demo --tamper` 可扩展演示"整链重写 → 链内 PASS 但 `verify_anchored` 报 CheckpointMismatch"(把锚点价值做成可证伪 aha)。

## 3. 诚实威胁框定(非可选 —— 安全产品最忌过度宣称)

**本层(本地 sidecar)检出范围**(Codex 确认此框定准确,但措辞须精确到攻击者权限范围):仅当攻击者**作用域限于 `events`/DB 写权限**(SQL 注入类、DB-文件级访问)**且 checkpoint 文件完好未被触及**时,整链重写被检出。
**本层不单独闭合**:持**完整本地 FS 写权限**者可同时一致地重写 sidecar。对此,**fully close 依赖 checkpoint 存储的外部性**:OS append-only(`chattr +a`)+ 异地同步,或签名(密钥不与 DB 同处)。本 ADR 交付**机制**;外部化/签名是其上明确的后续 slice。
**仅锚定前缀**:checkpoint 只保护到"最新锚定 event_id"为止的前缀;其后的改动要到下一次 emit 才被覆盖(须在文档/输出显式声明)。

→ 文档/CLI 措辞守则:称 **"detects a DB-only full-chain rewrite when the checkpoint file is intact, and enables external anchoring that closes it fully"**,**绝不**称 "tamper-proof"。与 demo/README/FAQ 既有诚实口径一致。

## 4. Alternatives considered

| 方案 | 否决理由 |
|---|---|
| checkpoint 进同库新表 | 与威胁 #7 同 blast radius(攻击者顺手改),零额外门槛 |
| 立即签名 checkpoint | 引入密钥管理/分发 → YAGNI;先交付机制 + 可外部化,签名作后续 slice |
| 远程/TSA 锚定 | 破"本地零外传"楔子 + 重依赖;留作可选企业层 |
| 改 v2 digest 纳入全局计数 | 触 crown-jewel digest(已 Codex 祝福)+ 不解决整链重写(攻击者同样重算) |

## 5. Consequences

- **加密核心纯增量,CLI 行为扩展**(Codex MF#5 校正):`append_event` / `compute_event_hash_v2` / `verify_chain` **零改动** → 不回归已验证的 crown jewel;新逻辑独立可测。但 `verify-chain` **CLI 判定面扩大**(现额外跑锚点,以前仅链内过的账本现可能因 mismatch/corrupt 失败)——这是有意的行为扩展,非"全局零变化",须 changelog 说明。
- **SemVer**:新公开 API(CheckpointLog / Anchored)+ 新 error 变体。已确认 `AuditError` 是 `#[non_exhaustive]` → 加变体 **semver 安全**(minor)。
- **并发/TOCTOU**(Codex MF#6):`emit` 在 ledger 锁单一临界区内读链头快照;`verify_anchored` 的 verify_chain + checkpoint 比对是两次读,假设 Vigil 本地**单写者**(账本由单 Hub 进程串行 append)——此假设须显式记录;并发外部篡改下的 TOCTOU 非本层目标(那已是 full-FS-write 威胁,靠外部化闭合)。
- **测试关键不变量(实现期必含)**:见 §6;核心 killer 对照测试 = 整链重写后 `verify_chain()` PASS 但 `verify_anchored()` 返回 CheckpointMismatch。
- **前向路径**:sidecar 签名 / OS append-only(`chattr +a`)部署文档 / cron 锚定 timer = 后续 slice,把"raises the bar"升级为"fully closes"。

## 6. 实施切片(下一增量)

1. `checkpoint.rs`:Checkpoint(7 字段)+ CheckpointLog(at/sidecar_for/emit/**verify_anchored**)+ Anchored 状态。emit 原子 append(flush+sync_data)。
2. error.rs:CheckpointMismatch / CheckpointStoreCorrupt(non_exhaustive 已确认)。
3. 测试(Codex MF#7,fail-closed 全覆盖):
   - **killer 对照**:整链重写 → `verify_chain()` PASS 但 `verify_anchored()` = CheckpointMismatch。
   - 仅改 `events[N].event_hash`=锚定值但留行内不自洽 → verify_chain 先失败(证 MF#1 的前置链校验闭合"checkpoint-only 绕过")。
   - rowid 替换(让 N 指向另一 session/type 的伪造事件)→ 绑定字段不符 = CheckpointMismatch(证 MF#3)。
   - checkpoint 行被删 / DB 截断到锚点前 → 行缺失 = CheckpointMismatch。
   - sidecar 空 / 文件不存在 → `Anchored::Unanchored`(非 Verified、非 error)。
   - sidecar 坏行 / 非 64-hex / 非正 id / 重复 id / 非严格递增 / 越界 max → CheckpointStoreCorrupt。
   - 空链 emit → `Ok(None)`。
4. CLI:`vigil-hub checkpoint` + `verify-chain` 改 `verify_anchored` 三态如实输出(§2.5)。
5. Codex 代码审查(安全核心)→ ACCEPT。
6. 文档诚实口径(§3)落地到 verify-chain 输出 + 后续 mdBook audit-ledger 页(双语)。

## 7. Codex 设计审查解决(2026-06-07,ACCEPT-with-changes → resolved)

| MF | Codex 关切 | 本 ADR 解决 |
|---|---|---|
| #1 | verify_against 不前置 verify_chain → 只改 event_hash=锚定值的 checkpoint-only 绕过(fail-open)| 只暴露 `verify_anchored`(内部先 verify_chain 再比对);不单独暴露 verify_against(§2.3)|
| #2 | 零/缺失 checkpoint 报 verified = fail-open | `Anchored::Unanchored` 独立状态,CLI 如实显示(§2.4/2.5)|
| #3 | 仅 keying (rowid,hash);rowid 未入 digest → 替换攻击 | Checkpoint 多绑 prev_hash/session_id/event_type/created_at,逐字段比对(§2.1)|
| #4 | JSONL append 撕裂行 / 坏行静默跳过 | 原子 append(flush+sync_data)+ load 坏行/非单调/重复/越界 fail-closed(§2.3)|
| #5 | "零行为变化"过度声称 | 校正为"加密核心增量 + CLI 行为扩展"(§2.5/5)|
| #6 | emit/verify 并发 TOCTOU、仅锚定前缀未声明 | emit 单临界区 + 单写者假设显式 + "仅保护到最新锚定前缀"声明(§3/5)|
| #7 | killer test 不足 | 测试矩阵补 6 类 fail-closed + 身份替换 + checkpoint-only 绕过(§6.3)|
| ✓ | AuditError 是否 non_exhaustive | Codex 确认**是** → 加变体 semver 安全 |
