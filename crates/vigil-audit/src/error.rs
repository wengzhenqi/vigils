//! `vigil-audit` 的错误类型。

use thiserror::Error;

/// 审计账本错误。
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum AuditError {
    /// SQLite 底层错误(连接 / 执行 / schema 迁移等)。
    #[error("sqlite: {0}")]
    Sqlite(#[from] rusqlite::Error),

    /// 文件系统 IO 错误(如开库前 `create_dir_all` 建账本父目录失败)。
    #[error("io: {0}")]
    Io(#[from] std::io::Error),

    /// JSON 规范化或反序列化错误(影响 hash 计算)。
    #[error("json canonicalization: {0}")]
    Json(#[from] serde_json::Error),

    /// `append_event` 入口 fail-closed 自检命中强指纹 —— 拒绝写入。
    /// Caller 必须先走 `vigil-redaction::redact`。
    #[error("hard-secret detected in payload (rule={rule}); refusing to persist")]
    HardSecretDetected {
        /// 命中的规则名(如 `github_token` / `pem_private_key`)。
        rule: &'static str,
    },

    /// hash chain 在给定 `event_id` 处断裂(可能是存储被篡改或代码 bug)。
    #[error("hash chain broken at event_id={event_id}")]
    ChainBroken {
        /// 首个校验失败的事件 id。
        event_id: i64,
    },

    /// 输入参数无效(非法 hex 长度、空 session_id 等)。
    #[error("invalid input: {reason}")]
    InvalidInput {
        /// 人类可读的失败原因。
        reason: &'static str,
    },

    /// 被内部锁污染(另一个线程在持有 mutex 时 panic)。
    #[error("internal lock poisoned")]
    LockPoisoned,

    /// Server registry 冲突:同 id 但 identity hash 不一致(I05 drift 处理)。
    #[error("server `{server_id}` already registered with different identity hash")]
    RegistryConflict {
        /// 冲突的 server id
        server_id: String,
    },

    /// ADR 0020:checkpoint 锚点与当前链头不符 —— **整链重写检出信号**。
    /// 区别于 `ChainBroken`(链内 prev_hash/摘要断裂):这里链内自洽(verify_chain 已过)但
    /// 某个被外部锚定的历史链头的绑定字段已变,说明该前缀被一致重写过。
    #[error(
        "checkpoint anchor mismatch at event_id={event_id} (chain prefix may have been rewritten)"
    )]
    CheckpointMismatch {
        /// 与锚点不符的事件 id。
        event_id: i64,
    },

    /// ADR 0020:checkpoint sidecar 自身损坏 / 非单调 / 非法行 —— fail-closed 拒绝
    /// (绝不静默跳过坏行,否则攻击者可用坏行掩盖删除的锚点)。
    #[error("checkpoint store corrupt: {reason}")]
    CheckpointStoreCorrupt {
        /// 人类可读的损坏原因(不含不可信原文)。
        reason: String,
    },
}

/// 本 crate 专用 Result。
pub type Result<T> = std::result::Result<T, AuditError>;
