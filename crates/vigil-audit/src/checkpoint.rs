//! Audit checkpoint anchor —— 对抗**整链重写**(security audit threat #7)的外部 append-only 锚定。
//!
//! 详见 ADR 0020。哈希链(`Ledger::verify_chain`)只能检测**部分**篡改:持完整 `events` 表写
//! 权限者可一致重写整链 → 链内自洽、verify_chain 仍过、但历史被伪造。本模块提供一份**与 SQLite
//! 库分离**的 append-only sidecar,周期性锚定链头快照;校验时比对当前链头是否仍与锚点一致,从而
//! 检出整链重写。
//!
//! **诚实威胁框定**(非可选):本地 sidecar 仅在攻击者作用域**限于 DB 写权限且 checkpoint 文件
//! 完好**时检出整链重写;持完整本地 FS 写权限者可一致重写 sidecar。**fully close** 依赖 checkpoint
//! 存储的外部性(OS append-only `chattr +a` / 异地同步 / 签名)—— 本模块交付**机制**,外部化是其上
//! 的部署层。绝不称 "tamper-proof"。锚点只保护到"最新锚定 event_id"为止的前缀。

use std::ffi::OsString;
use std::fs::OpenOptions;
use std::io::Write;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::error::{AuditError, Result};
use crate::ledger::{now_secs, Ledger};

/// 一条链头快照锚点。
///
/// 校验依赖这组**绑定字段**的不可变性 —— 即"历史上 seq=event_id 处曾存在一条
/// (prev_hash, session_id, event_type, created_at) 且链头为 event_hash 的事件"。多绑字段(非仅
/// `(event_id, event_hash)`)是为防 rowid 替换:event_id = SQLite rowid,**未**纳入 event_hash 摘要,
/// 仅锚 (rowid, hash) 时攻击者可 renumber rowid 让 event_id 指向另一条其能控制 hash 的伪造事件。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Checkpoint {
    /// 锚定的事件序号(SQLite rowid)。
    pub event_id: i64,
    /// 锚定时刻该事件的 64-hex event_hash(= 当时链头)。
    pub event_hash: String,
    /// 该事件 prev_hash(空串=genesis;否则 64-hex)。绑定链"位置"。
    pub prev_hash: String,
    /// 身份绑定:该 event_id 当时所属 session。
    pub session_id: String,
    /// 身份绑定:该 event_id 当时的事件类型。
    pub event_type: String,
    /// 身份绑定:该事件 created_at。
    pub created_at: i64,
    /// emit 的 wall-clock(仅审计/展示,**不**参与校验判定)。
    pub anchored_at: i64,
}

/// `verify_anchored` 的结果。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Anchored {
    /// 链内自洽**且**所有锚点匹配,锚定覆盖到 `through_event_id` 前缀。
    Verified {
        /// 校验通过的 checkpoint 条数。
        checkpoints: usize,
        /// 最高锚定 event_id(锚定覆盖的前缀终点)。
        through_event_id: i64,
    },
    /// 链内自洽但**无 checkpoint / sidecar 不存在** —— 调用方须如实显示"未锚定",
    /// **绝不**等同于 verified(否则空 sidecar = fail-open)。
    Unanchored,
}

/// 绑定到一个 append-only sidecar 文件的 checkpoint 日志。
#[derive(Debug, Clone)]
pub struct CheckpointLog {
    path: PathBuf,
}

impl CheckpointLog {
    /// 绑定到指定 sidecar 路径。
    pub fn at(path: impl AsRef<Path>) -> Self {
        Self {
            path: path.as_ref().to_path_buf(),
        }
    }

    /// 按约定 `<ledger_db_path>.checkpoints` 绑定 sidecar(与账本同目录,便于一起异地同步/锁权限)。
    pub fn sidecar_for(ledger_db_path: &Path) -> Self {
        // 追加后缀(非替换扩展名):ledger.sqlite3 → ledger.sqlite3.checkpoints
        let mut os: OsString = ledger_db_path.as_os_str().to_os_string();
        os.push(".checkpoints");
        Self {
            path: PathBuf::from(os),
        }
    }

    /// sidecar 文件路径。
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// 读当前链头(单临界区,ADR MF#6)→ 组成 Checkpoint → **原子 append** 到 sidecar。
    ///
    /// - 空账本 → `Ok(None)`。
    /// - 链头未前进(`head.event_id <= 最新锚点 event_id`)→ `Ok(None)`(无新前缀可锚,且避免破坏
    ///   sidecar 严格递增不变量)。**不**在此判断篡改 —— 那是 `verify_anchored` 的职责;已存在的
    ///   锚点仍会在校验时比对被重写的行。
    /// - sidecar 已损坏 → 传播 `CheckpointStoreCorrupt`(不向损坏日志追加)。
    ///
    /// **不**在 emit 内调 verify_chain:emit 锚定"当前可信状态",调用方应在信任链状态时锚定。
    pub fn emit(&self, ledger: &Ledger) -> Result<Option<Checkpoint>> {
        let Some(head) = ledger.head_detail()? else {
            return Ok(None); // 空账本
        };

        // 先 load(顺带校验 sidecar 完整性 + 取最新锚点 id);损坏即 fail-closed,不追加。
        let existing = self.load()?;
        if let Some(last) = existing.last() {
            if head.event_id <= last.event_id {
                return Ok(None); // 无更新前缀可锚
            }
        }

        let cp = Checkpoint {
            event_id: head.event_id,
            event_hash: head.event_hash,
            prev_hash: head.prev_hash,
            session_id: head.session_id,
            event_type: head.event_type,
            created_at: head.created_at,
            anchored_at: now_secs(),
        };

        // 原子 append:整行(JSON + '\n')一次 write_all + flush + sync_data,尽量避免崩溃/磁盘满
        // 留撕裂行(若仍发生,load 端 fail-closed)。
        let mut line = serde_json::to_string(&cp)?;
        line.push('\n');
        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)?;
        file.write_all(line.as_bytes())?;
        file.flush()?;
        file.sync_data()?;

        Ok(Some(cp))
    }

    /// 解析全部 checkpoint,fail-closed:任一坏行/非法 hash/非正 id/重复/**非严格递增** →
    /// `CheckpointStoreCorrupt`(绝不静默跳过坏行)。sidecar 不存在或空 → `Ok(Vec::new())`。
    pub fn load(&self) -> Result<Vec<Checkpoint>> {
        let content = match std::fs::read_to_string(&self.path) {
            Ok(s) => s,
            // 不存在 = 未锚定(非错误);verify 据此返回 Unanchored。
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
            // 非法 UTF-8(撕裂在多字节中)等 → fail-closed(Io)。
            Err(e) => return Err(AuditError::Io(e)),
        };
        if content.is_empty() {
            return Ok(Vec::new()); // 0 字节 sidecar = 未锚定
        }
        // 撕裂行守门(Codex BLOCKER / MF#4):每条 emit 以 '\n' 收尾;非空文件末字节非 '\n'
        // = 最后一条记录未结束(崩溃/部分写)。`BufRead::lines()` 不区分"有无尾换行",会把
        // "完整 JSON 但缺尾换行"的撕裂写误纳 → 必须显式查末字节,fail-closed。
        if !content.ends_with('\n') {
            return Err(corrupt(
                "unterminated final line (partial write?)".to_string(),
            ));
        }
        let mut out: Vec<Checkpoint> = Vec::new();
        let mut last_id: Option<i64> = None;
        for (idx, line) in content.lines().enumerate() {
            let lineno = idx + 1;
            // 空行(中间空行 / 截断后空尾行)= 非预期 → fail-closed。
            if line.is_empty() {
                return Err(corrupt(format!("empty line {lineno}")));
            }
            let cp: Checkpoint = serde_json::from_str(line)
                .map_err(|_| corrupt(format!("malformed checkpoint at line {lineno}")))?;
            // 字段 fail-closed 校验(不回显不可信原文,只报结构性原因 + 行号)。
            if !is_valid_event_hash(&cp.event_hash) {
                return Err(corrupt(format!("invalid event_hash at line {lineno}")));
            }
            if !cp.prev_hash.is_empty() && !is_valid_event_hash(&cp.prev_hash) {
                return Err(corrupt(format!("invalid prev_hash at line {lineno}")));
            }
            if cp.event_id <= 0 {
                return Err(corrupt(format!("non-positive event_id at line {lineno}")));
            }
            // 严格递增:emit 只追加更高 id;非严格递增 = sidecar 被改/重排。
            if let Some(prev) = last_id {
                if cp.event_id <= prev {
                    return Err(corrupt(format!(
                        "non-monotonic event_id at line {lineno} (<= previous)"
                    )));
                }
            }
            last_id = Some(cp.event_id);
            out.push(cp);
        }
        Ok(out)
    }

    /// 锚定校验。**先**链内 `verify_chain`(ADR MF#1:保证 events[event_id] 行已链一致,堵住
    /// "只把 event_hash 改回锚定值却留行内不自洽"的 checkpoint-only 绕过),**再**逐锚点比对**全部
    /// 绑定字段**。
    ///
    /// - verify_chain 失败 → 传播其 `ChainBroken`。
    /// - 无锚点 → `Anchored::Unanchored`(非 Verified、非静默 Ok)。
    /// - 某锚点对应行缺失(删/截断/越过当前 max)→ `CheckpointMismatch`(锚定事件已不在链上)。
    /// - 绑定字段任一不符 → `CheckpointMismatch`(前缀被重写)。
    pub fn verify_anchored(&self, ledger: &Ledger) -> Result<Anchored> {
        ledger.verify_chain()?; // MF#1:必须先链内校验
        let checkpoints = self.load()?;
        if checkpoints.is_empty() {
            return Ok(Anchored::Unanchored); // MF#2:未锚定绝不冒充 verified
        }
        let mut through: i64 = 0;
        for cp in &checkpoints {
            let Some(row) = ledger.get_event_detail(cp.event_id)? else {
                // 行缺失:被删 / DB 截断到锚点前 / event_id 越过当前 max → 锚定事件已消失。
                return Err(AuditError::CheckpointMismatch {
                    event_id: cp.event_id,
                });
            };
            // MF#3:比对全部绑定字段(非仅 event_hash),令 rowid 替换可见损坏。
            // 注:对 v2 行(CURRENT_CHAIN_VERSION,即所有新事件),`redacted_text` 已被 event_hash
            // 摘要覆盖(verify_chain 先行复算 v2 hash),故此处比对 event_hash 即间接绑定它;锚点设计
            // 面向 v2 链头。极老纯 v1 链头的 redacted_text 不被 v1 摘要绑定(legacy 边角,非本层目标)。
            if row.event_hash != cp.event_hash
                || row.prev_hash != cp.prev_hash
                || row.session_id != cp.session_id
                || row.event_type != cp.event_type
                || row.created_at != cp.created_at
            {
                return Err(AuditError::CheckpointMismatch {
                    event_id: cp.event_id,
                });
            }
            through = through.max(cp.event_id);
        }
        Ok(Anchored::Verified {
            checkpoints: checkpoints.len(),
            through_event_id: through,
        })
    }
}

/// 64-char lower-hex 校验(sha256 hex 形式)。
fn is_valid_event_hash(s: &str) -> bool {
    s.len() == 64
        && s.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

fn corrupt(reason: String) -> AuditError {
    AuditError::CheckpointStoreCorrupt { reason }
}
