//! Runner 审计事件契约(ADR 0007 §D9 / §I-7.6)。
//!
//! Codex R1 MUST-FIX 3:原 ADR 把 5 条 `runner.*` 事件列为 I07 范围,但最初实现让
//! caller 负责写入,与 §I-7.6 "所有 RunnerError 路径必须产审计事件" 冲突。
//! R2 修复:runner 内部通过可选 `RunnerAuditSink` trait 写事件;
//! `sink = None` 时静默(测试 / 非审计场景)。

use crate::error::RejectField;

/// runner 向 caller 回报的 5 类事件(ADR 0007 §D9)。
#[derive(Debug, Clone)]
#[non_exhaustive]
pub enum RunnerEvent<'a> {
    /// spawn / Wasm instantiate 成功,即将进入主循环。
    Started {
        /// `Native` / `Wasm`
        runner_kind: &'static str,
        /// caller 贴上的 server id(可选)
        server_id: Option<&'a str>,
        /// 配置的 wall timeout
        wall_ms: u64,
        /// env key 清单(**不含**真实值)
        env_keys: &'a [String],
        /// 子进程 / wasm instance 的 cwd
        cwd: &'a str,
    },
    /// 正常退出。
    Completed {
        /// 退出码
        exit_code: Option<i32>,
        /// 实际墙钟耗时
        wall_elapsed_ms: u64,
        /// 脱敏后 stdout 字节数
        stdout_bytes: usize,
        /// 脱敏后 stderr 字节数
        stderr_bytes: usize,
    },
    /// wall_ms 耗尽,子进程被 kill / guest epoch 中断。
    KilledByTimeout {
        /// 配置的 wall_ms
        wall_ms: u64,
    },
    /// stdin/stdout/stderr/wait pipe 出错。
    IoError {
        /// spawn / wait / read_line 等
        phase: &'static str,
        /// 稳定 reason code(不含 OS 原文)
        reason_code: &'static str,
    },
    /// 预检失败(path 越界 / profile deny / unsupported runner kind)。
    Rejected {
        /// 字段定位
        field: RejectField,
        /// reason code
        reason_code: &'static str,
    },
    /// **ISS-020**:post-exec leak detection —— stdout/stderr 已 line-by-line
    /// `scrub_text` 脱敏后,二次防御扫描 `vigil_redaction::scan_hard_findings`
    /// 命中(scrub 偶发漏掉跨行 secret / lookalike placeholder 攻击等)。
    ///
    /// caller 应据此把对应 `ExecutionResult` 视作 quarantined,**禁止后续工具
    /// 读取该 artifact**(本 ISS 不实装 artifact registry,留给 ISS-019 Tauri
    /// embed Hub 配套;runner 层只负责标位 + 审计)。
    ///
    /// 与 ISS-016(Hub upstream response 扫描)同形态对称:**out-of-band**,
    /// 不修改 stdout/stderr 字节(MCP 协议透明性原则)。stdout / stderr 各自
    /// 命中各发一条事件,便于审计端按 `source` 聚合。
    LeakDetected {
        /// 命中位置:`"stdout"` / `"stderr"`
        source: &'static str,
        /// 命中的全部 hard rule names(可多条;保 `scan_hard_findings` 声明顺序)
        rules: &'a [&'static str],
        /// 该 ExecutionResult 已被标 quarantined(目前恒为 true,字段保留为
        /// 未来"软告警 / 阈值"语义留口)
        quarantined: bool,
    },
}

/// 审计事件回调 trait。caller(例如 Hub)可实现本 trait 把事件写入 Ledger。
///
/// 实现**必须非阻塞 + 不 panic**:runner 在 hot path 同步调用,任何失败都被吞掉
/// (审计失败不得影响主流程)。典型实现:`let _ = ledger.append_event(...)`。
pub trait RunnerAuditSink: Send + Sync + std::fmt::Debug {
    /// 处理一条 runner 事件。实现应立即返回,不应阻塞 runner hot path。
    fn emit(&self, event: RunnerEvent<'_>);
}

/// No-op sink:开发 / 单元测试默认。
#[derive(Debug, Default, Clone, Copy)]
pub struct NullAuditSink;

impl RunnerAuditSink for NullAuditSink {
    fn emit(&self, _event: RunnerEvent<'_>) {}
}
